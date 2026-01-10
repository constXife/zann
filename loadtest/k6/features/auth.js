import http from "k6/http";
import { check } from "k6";

import { withName } from "../lib/metrics.js";
import { randomEmail, randomId } from "../lib/random.js";

export function registerUser(baseUrl, params, opts = {}) {
  const domain = opts.emailDomain || "loadtest.local";
  const password = opts.password || `k6-${randomId("pw")}`;
  const payload = {
    email: randomEmail(domain),
    password,
    full_name: "K6 Loadtest",
    device_name: "k6",
    device_platform: "loadtest",
  };
  const res = http.post(
    `${baseUrl}/v1/auth/register`,
    JSON.stringify(payload),
    withName(params, "auth.register"),
  );
  check(res, {
    "auth register ok": (r) => r.status === 201,
  });
  if (!res || res.status !== 201) {
    return { res, body: null };
  }
  const body = res.json();
  return { res, body };
}
