// k6 per-endpoint baseline: one scenario per run, closed-loop VUs ramping 10 -> 100.
//
//   docker run --rm -i -e BASE=http://host.docker.internal:8080 -e SCEN=me \
//     -e CID=svc_... -e CSEC=wcs_... -e SK=sk_... grafana/k6 run - < loadtest/scenarios.js
//
// SCEN: signup | signin | refresh | me | cc | verify | verify_session | jwks | graphql
// Run Warden with RATE_LIMIT_ENABLED=false (limits are per client IP). `cc` needs
// a service client (CID/CSEC) and `verify*` a secret key (SK), both from the admin UI.
import http from "k6/http";
import { check } from "k6";
import encoding from "k6/encoding";

const BASE = __ENV.BASE || "http://localhost:8080";
const SCEN = __ENV.SCEN || "me";
const PEAK = parseInt(__ENV.PEAK || "100");
const PASSWORD = "load test passphrase 2026";
const json = { headers: { "Content-Type": "application/json" } };

export const options = {
  scenarios: {
    [SCEN]: {
      executor: "ramping-vus",
      exec: SCEN,
      startVUs: 10,
      stages: [
        { target: PEAK, duration: __ENV.RAMP || "45s" },
        { target: PEAK, duration: __ENV.HOLD || "15s" },
      ],
      gracefulRampDown: "5s",
    },
  },
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max"],
};

export function setup() {
  const users = [];
  const n = SCEN === "signup" ? 0 : parseInt(__ENV.USERS || "20");
  for (let i = 0; i < n; i++) {
    const email = `perf-${Date.now()}-${i}@example.com`;
    const r = http.post(`${BASE}/v1/auth/signup`, JSON.stringify({ email, password: PASSWORD }), json);
    if (r.status === 201) users.push({ email, access: r.json("tokens.access_token") });
  }
  if (n > 0 && users.length === 0) throw new Error("setup failed: could not create users");
  return { users };
}

const pick = (d) => d.users[Math.floor(Math.random() * d.users.length)];
const bearer = (t) => ({ headers: { Authorization: `Bearer ${t}` } });

export function signup() {
  const email = `perf-${__VU}-${__ITER}-${Date.now()}@example.com`;
  const r = http.post(`${BASE}/v1/auth/signup`, JSON.stringify({ email, password: PASSWORD }), json);
  check(r, { "signup 201": (x) => x.status === 201 });
}

export function signin(d) {
  const r = http.post(`${BASE}/v1/auth/signin`, JSON.stringify({ email: pick(d).email, password: PASSWORD }), json);
  check(r, { "signin 200": (x) => x.status === 200, "not shed": (x) => x.status !== 503 });
}

// Refresh tokens rotate, so each VU keeps its own session.
let mine = null;
export function refresh(d) {
  if (!mine) {
    const r = http.post(`${BASE}/v1/auth/signin`, JSON.stringify({ email: pick(d).email, password: PASSWORD }), json);
    if (r.status !== 200) return;
    mine = r.json("tokens.refresh_token");
  }
  const r = http.post(`${BASE}/v1/auth/refresh`, JSON.stringify({ refresh_token: mine }), json);
  check(r, { "refresh 200": (x) => x.status === 200 });
  if (r.status === 200) mine = r.json("tokens.refresh_token");
}

export function me(d) {
  check(http.get(`${BASE}/v1/me`, bearer(pick(d).access)), { "me 200": (x) => x.status === 200 });
}

export function cc() {
  const auth = `Basic ${encoding.b64encode(`${__ENV.CID}:${__ENV.CSEC}`)}`;
  const r = http.post(`${BASE}/v1/oauth/token`, "grant_type=client_credentials", {
    headers: { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" },
  });
  check(r, { "cc 200": (x) => x.status === 200 });
}

function verifyBody(d, checkSession) {
  return http.post(`${BASE}/v1/server/tokens/verify`, JSON.stringify({ token: pick(d).access, check_session: checkSession }),
    { headers: { "Content-Type": "application/json", Authorization: `Bearer ${__ENV.SK}` } });
}
export function verify(d) {
  check(verifyBody(d, false), { "verify 200": (x) => x.status === 200 && x.json("active") === true });
}
export function verify_session(d) {
  check(verifyBody(d, true), { "verify+session 200": (x) => x.status === 200 && x.json("active") === true });
}

export function jwks() {
  check(http.get(`${BASE}/.well-known/jwks.json`), { "jwks 200": (x) => x.status === 200 });
}

export function graphql(d) {
  const r = http.post(`${BASE}/graphql`, JSON.stringify({ query: "{ me { id } }" }),
    { headers: { "Content-Type": "application/json", Authorization: `Bearer ${pick(d).access}` } });
  check(r, { "graphql ok": (x) => x.status === 200 && !x.json("errors") });
}
