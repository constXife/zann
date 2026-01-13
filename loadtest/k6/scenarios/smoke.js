import { sleep } from "k6";
import { Gauge } from "k6/metrics";

import { setupAuth } from "../lib/auth.js";
import { authHeaders } from "../lib/headers.js";
import { ACCESS_TOKEN_ENV, BASE_URL, SERVICE_ACCOUNT_TOKEN } from "../lib/env.js";
import {
  calcStagesDurationSeconds,
  monitorLoop,
  parseDurationSeconds,
  parseIntervalSeconds,
} from "../lib/monitor.js";
import { resolveStages } from "../lib/profile.js";
import { systemBatch } from "../features/system.js";
import { listVaults, pickVaultId } from "../features/vaults.js";
import { listItems } from "../features/items.js";

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

const loadStages = resolveStages([
  { duration: "1m", target: 10 },
  { duration: "3m", target: 30 },
  { duration: "1m", target: 0 },
]);
const monitorDurationSeconds =
  calcStagesDurationSeconds(loadStages) ||
  parseDurationSeconds(__ENV.ZANN_MONITOR_DURATION || "10m");
const monitorDuration = `${Math.ceil(monitorDurationSeconds)}s`;
const thresholds = {
  http_req_failed: ["rate<0.02"],
  http_req_duration: ["p(95)<1500"],
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
};

export const options = {
  scenarios: {
    default: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: loadStages,
      exec: "default",
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
  thresholds,
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

export default function (data) {
  systemBatch(BASE_URL);

  if (data.token) {
    const { vaults } = listVaults(BASE_URL, authHeaders(data.token));
    const vaultId = pickVaultId(vaults);
    if (vaultId) {
      listItems(BASE_URL, vaultId, authHeaders(data.token));
    }
  }

  sleep(Math.random() * 0.5);
}
