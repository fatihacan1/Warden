// k6 overload test: sign-ins arrive far faster than Argon2 can serve them.
// Expect 200s for what fits, 503 + Retry-After for the rest, and a flat
// process memory line. Compare warden_password_hash_wait_seconds and
// warden_password_hash_rejected_total on :9090/metrics afterwards.
//
//   docker run --rm -i -e BASE=http://host.docker.internal:8080 -e RATE=600 grafana/k6 run - < loadtest/overload.js
import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const BASE = __ENV.BASE || "http://localhost:8080";
const PASSWORD = "load test passphrase 2026";
const json = { headers: { "Content-Type": "application/json" } };
const shed = new Counter("shed_503");
const shedWithRetryAfter = new Counter("shed_503_with_retry_after");

export const options = {
  scenarios: {
    flood: {
      executor: "constant-arrival-rate",
      rate: parseInt(__ENV.RATE || "600"),
      timeUnit: "1s",
      duration: __ENV.DURATION || "40s",
      preAllocatedVUs: 200,
      maxVUs: 3000,
    },
  },
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max"],
};

export function setup() {
  const users = [];
  for (let i = 0; i < 100; i++) {
    const email = `flood-${Date.now()}-${i}@example.com`;
    const r = http.post(`${BASE}/v1/auth/signup`, JSON.stringify({ email, password: PASSWORD }), json);
    if (r.status === 201) users.push(email);
  }
  if (users.length === 0) throw new Error("setup failed");
  return { users };
}

export default function (d) {
  const email = d.users[Math.floor(Math.random() * d.users.length)];
  const r = http.post(`${BASE}/v1/auth/signin`, JSON.stringify({ email, password: PASSWORD }), json);
  if (r.status === 503) {
    shed.add(1);
    if (r.headers["Retry-After"]) shedWithRetryAfter.add(1);
  }
  if (r.status !== 200 && r.status !== 503 && Math.random() < 0.02) {
    console.log(`unexpected status=${r.status} body=${String(r.body).slice(0, 100)} err=${r.error}`);
  }
  check(r, { "200 or graceful 503": (x) => x.status === 200 || x.status === 503 });
}
