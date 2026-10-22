// k6 load test: realistic mix of sign-ins, token refreshes and /v1/me calls.
//
//   docker run --rm -i --network host -e BASE=http://localhost:8080 grafana/k6 run - < loadtest/auth.js
//
// Rate limits are per client IP, so run Warden with RATE_LIMIT_ENABLED=false
// (or a high RATE_LIMIT_AUTH_PER_MINUTE) when load testing from one machine.
import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const BASE = __ENV.BASE || "http://localhost:8080";
const PASSWORD = "load test passphrase 2026";
const shed = new Counter("shed_503");

export const options = {
  scenarios: {
    // Password sign-in is deliberately expensive (Argon2id). This scenario
    // pushes past capacity to show the service sheds load instead of falling over.
    signin: {
      executor: "ramping-arrival-rate",
      exec: "signin",
      startRate: 10,
      timeUnit: "1s",
      preAllocatedVUs: 50,
      maxVUs: 400,
      stages: [
        { target: 50, duration: "20s" },
        { target: 150, duration: "20s" },
        { target: 0, duration: "5s" },
      ],
    },
    // Token validation and refresh are the hot path for every app request.
    api: {
      executor: "constant-arrival-rate",
      exec: "api",
      rate: 400,
      timeUnit: "1s",
      duration: "45s",
      preAllocatedVUs: 100,
      maxVUs: 400,
    },
  },
  thresholds: {
    "http_req_duration{scenario:api}": ["p(95)<200"],
    "checks{scenario:api}": ["rate>0.99"],
  },
};

const json = { headers: { "Content-Type": "application/json" } };

export function setup() {
  const users = [];
  for (let i = 0; i < 20; i++) {
    const email = `load-${Date.now()}-${i}@example.com`;
    const r = http.post(`${BASE}/v1/auth/signup`, JSON.stringify({ email, password: PASSWORD }), json);
    if (r.status === 201) users.push({ email, access: r.json("tokens.access_token"), refresh: r.json("tokens.refresh_token") });
  }
  if (users.length === 0) throw new Error("setup failed: could not create users (rate limited?)");
  return { users };
}

export function signin(data) {
  const u = data.users[Math.floor(Math.random() * data.users.length)];
  const r = http.post(`${BASE}/v1/auth/signin`, JSON.stringify({ email: u.email, password: PASSWORD }), json);
  if (r.status === 503) shed.add(1);
  // 200 = served, 503 = shed with Retry-After (graceful). Anything else is a failure.
  check(r, { "signin served or shed": (x) => x.status === 200 || x.status === 503 });
}

export function api(data) {
  const u = data.users[Math.floor(Math.random() * data.users.length)];
  const r = http.get(`${BASE}/v1/me`, { headers: { Authorization: `Bearer ${u.access}` } });
  check(r, { "me 200": (x) => x.status === 200 });
  if (Math.random() < 0.02) {
    http.get(`${BASE}/.well-known/jwks.json`);
  }
}
