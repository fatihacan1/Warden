#!/bin/sh
# Initializes a single-node Garage for local development. Safe to re-run.
set -eu

: "${S3_BUCKET:?}" "${S3_ACCESS_KEY_ID:?}" "${S3_SECRET_ACCESS_KEY:?}"

# The CLI talks to the node over RPC: it needs the node id (read from the
# shared metadata volume) and the node's address on the compose network.
NODE_ID=""
for i in $(seq 1 60); do
  NODE_ID=$(garage -c /etc/garage.toml node id -q 2>/dev/null | cut -d@ -f1 || true)
  [ -n "$NODE_ID" ] && break
  sleep 1
done
[ -n "$NODE_ID" ] || { echo "garage-init: node id not available"; exit 1; }

ADDR=$(getent hosts garage | awk '{print $1}' | head -n1)
G="garage -c /etc/garage.toml -h ${NODE_ID}@${ADDR}:3901"

for i in $(seq 1 60); do
  $G status >/dev/null 2>&1 && break
  sleep 1
done

if $G status 2>/dev/null | grep -q "NO ROLE ASSIGNED"; then
  echo "garage-init: assigning layout"
  $G layout assign -z dc1 -c 1G "$NODE_ID"
  $G layout apply --version 1
fi

if ! $G key info "$S3_ACCESS_KEY_ID" >/dev/null 2>&1; then
  echo "garage-init: importing access key"
  $G key import --yes -n warden "$S3_ACCESS_KEY_ID" "$S3_SECRET_ACCESS_KEY"
fi

if ! $G bucket info "$S3_BUCKET" >/dev/null 2>&1; then
  echo "garage-init: creating bucket $S3_BUCKET"
  $G bucket create "$S3_BUCKET"
fi
$G bucket allow --read --write --owner "$S3_BUCKET" --key "$S3_ACCESS_KEY_ID"

echo "garage-init: ready (bucket=$S3_BUCKET)"
