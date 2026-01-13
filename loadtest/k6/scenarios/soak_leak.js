import { sleep } from "k6";
import { Gauge } from "k6/metrics";

import { setupAuth } from "../lib/auth.js";
import { ACCESS_TOKEN_ENV, BASE_URL, SERVICE_ACCOUNT_TOKEN } from "../lib/env.js";
import { monitorLoop, parseIntervalSeconds } from "../lib/monitor.js";
import { runBaseline } from "./baseline_normal.js";

const LEAK_VUS = Number(__ENV.K6_LEAK_VUS || "20");
const LEAK_DURATION = __ENV.K6_LEAK_DURATION || "2h";
const VM_URL = __ENV.VM_URL || "";
const CPU_QUERY =
  __ENV.CPU_QUERY ||
  'avg(rate(process_cpu_seconds_total{env="loadtest"}[1m]))';
const MEM_QUERY =
  __ENV.MEM_QUERY ||
  'max(process_resident_memory_bytes{env="loadtest"})';
const MONITOR_INTERVAL = __ENV.ZANN_MONITOR_INTERVAL || "5s";
const MEM_LIMIT_BYTES = Number(__ENV.ZANN_MEM_LIMIT_BYTES || "1000000000");
const CPU_LIMIT = Number(__ENV.ZANN_CPU_LIMIT || "0.85");
const monitorEnabled = VM_URL.length > 0;
const monitorDuration = __ENV.ZANN_MONITOR_DURATION || LEAK_DURATION;

export const options = {
  scenarios: {
    leak: {
      executor: "constant-vus",
      vus: LEAK_VUS,
      duration: LEAK_DURATION,
      exec: "leak",
    },
    ...(monitorEnabled
      ? {
          monitor: {
            executor: "constant-vus",
            vus: 1,
            duration: monitorDuration,
            exec: "monitor",
          },
        }
      : {}),
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500", "p(99)<1200"],
    ...(monitorEnabled
      ? {
          sut_cpu: [
            {
              threshold: `value<${CPU_LIMIT}`,
              delayAbortEval: "30s",
            },
          ],
          sut_mem: [
            {
              threshold: `value<${MEM_LIMIT_BYTES}`,
              abortOnFail: true,
              delayAbortEval: "30s",
            },
          ],
        }
      : {}),
  },
};

const jsonHeaders = { "Content-Type": "application/json" };
const sutCpu = new Gauge("sut_cpu");
const sutMem = new Gauge("sut_mem");

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

export function monitor() {
  const intervalSeconds = parseIntervalSeconds(MONITOR_INTERVAL);
  monitorLoop({
    enabled: monitorEnabled,
    intervalSeconds,
    vmUrl: VM_URL,
    cpuQuery: CPU_QUERY,
    memQuery: MEM_QUERY,
    cpuGauge: sutCpu,
    memGauge: sutMem,
  });
}

export default leak;
