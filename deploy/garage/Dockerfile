# One-shot initializer for the local Garage node: assigns the cluster layout,
# imports the development access key and creates the bucket. Idempotent.
FROM dxflrs/garage:v2.1.0 AS garage

FROM alpine:3.22
COPY --from=garage /garage /usr/local/bin/garage
COPY init.sh /init.sh
# Runs as root on purpose: it must read the node key Garage writes as root
# into the shared metadata volume. Local development only, never deployed.
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/bin/sh", "/init.sh"]
