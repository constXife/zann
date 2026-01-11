import { sleep } from "k6";

import { setupAuth } from "../lib/auth.js";
import { ACCESS_TOKEN_ENV, BASE_URL, SERVICE_ACCOUNT_TOKEN } from "../lib/env.js";
import { runBaseline } from "./baseline_normal.js";

const LEAK_VUS = Number(__ENV.K6_LEAK_VUS || "20");
const LEAK_DURATION = __ENV.K6_LEAK_DURATION || "2h";

export const options = {
  scenarios: {
    leak: {
      executor: "constant-vus",
      vus: LEAK_VUS,
      duration: LEAK_DURATION,
      exec: "leak",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500", "p(99)<1200"],
  },
};

const jsonHeaders = { "Content-Type": "application/json" };

export function setup() {
  return setupAuth({
    baseUrl: BASE_URL,
    accessTokenEnv: ACCESS_TOKEN_ENV,
    serviceAccountToken: SERVICE_ACCOUNT_TOKEN,
    jsonHeaders,
  });
}

export function leak(data) {
  runBaseline(data);
  sleep(Math.random() * 0.5);
}

export default leak;
