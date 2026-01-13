import { sleep } from "k6";
import exec from "k6/execution";
import { Gauge } from "k6/metrics";

import { setupAuth } from "../lib/auth.js";
import { buildHeaders } from "../lib/headers.js";
import { ACCESS_TOKEN_ENV, BASE_URL, SERVICE_ACCOUNT_TOKEN } from "../lib/env.js";
import {
  calcStagesDurationSeconds,
  monitorLoop,
  parseDurationSeconds,
  parseIntervalSeconds,
} from "../lib/monitor.js";
import { resolveStages } from "../lib/profile.js";
import { makeRequestId } from "../lib/trace.js";
import { systemBatch } from "../features/system.js";
import { listVaults, pickVaultId } from "../features/vaults.js";
import { listItems } from "../features/items.js";

const PEAK_VUS = Number(__ENV.ZANN_PEAK_VUS || "500");
const HOLD_DURATION = __ENV.ZANN_HOLD_DURATION || "5m";
const VM_URL = __ENV.VM_URL || "";
const CPU_QUERY =
  __ENV.CPU_QUERY ||
  'avg(rate(process_cpu_seconds_total{env="loadtest"}[1m]))';
const MEM_QUERY =
  __ENV.MEM_QUERY ||
  'max(process_resident_memory_bytes{env="loadtest"})';
const MONITOR_INTERVAL = __ENV.ZANN_MONITOR_INTERVAL || "5s";
const MEM_LIMIT_BYTES = Number(__ENV.ZANN_MEM_LIMIT_BYTES || "1000000000");
const monitorEnabled = VM_URL.length > 0;
const TEST_RUN_ID =
  __ENV.ZANN_TEST_RUN_ID ||
  `k6-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;

const jsonHeaders = { "Content-Type": "application/json" };
const sutCpu = new Gauge("sut_cpu");
const sutMem = new Gauge("sut_mem");

const loadStages = resolveStages([
  { duration: "2m", target: PEAK_VUS },
  { duration: HOLD_DURATION, target: PEAK_VUS },
  { duration: "1m", target: 0 },
]);
const monitorDurationSeconds =
  calcStagesDurationSeconds(loadStages) ||
  parseDurationSeconds(__ENV.ZANN_MONITOR_DURATION || "10m");
const monitorDuration = `${Math.ceil(monitorDurationSeconds)}s`;
const thresholds = {
  http_req_failed: ["rate<0.005"],
  http_req_duration: ["p(95)<200", "p(99)<400"],
};

if (monitorEnabled) {
  thresholds.sut_mem = [
    {
      threshold: `value<${MEM_LIMIT_BYTES}`,
      abortOnFail: true,
      delayAbortEval: "30s",
    },
  ];
}

export const options = {
  scenarios: {
    load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: loadStages,
      exec: "load",
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

export function setup() {
  return setupAuth({
    baseUrl: BASE_URL,
    accessTokenEnv: ACCESS_TOKEN_ENV,
    serviceAccountToken: SERVICE_ACCOUNT_TOKEN,
    loginParams: (headers) =>
      buildHeaders({
        requestId: makeRequestId(),
        testRunId: TEST_RUN_ID,
        extraHeaders: headers,
      }),
    jsonHeaders,
  });
}

function runLoad(data) {
  const baseParams = () =>
    buildHeaders({ requestId: makeRequestId(), testRunId: TEST_RUN_ID });
  systemBatch(BASE_URL, baseParams);

  if (data.token) {
    const { vaults } = listVaults(
      BASE_URL,
      buildHeaders({
        token: data.token,
        requestId: makeRequestId(),
        testRunId: TEST_RUN_ID,
      }),
    );
    const vaultId = pickVaultId(vaults);
    if (vaultId) {
      listItems(
        BASE_URL,
        vaultId,
        buildHeaders({
          token: data.token,
          requestId: makeRequestId(),
          testRunId: TEST_RUN_ID,
        }),
      );
    }
  }

  sleep(Math.random() * 0.5);
}

export default runLoad;

export function monitor() {
  const intervalSeconds = parseIntervalSeconds(MONITOR_INTERVAL);
  monitorLoop({
    intervalSeconds,
    enabled: monitorEnabled,
    vmUrl: VM_URL,
    cpuQuery: CPU_QUERY,
    memQuery: MEM_QUERY,
    cpuGauge: sutCpu,
    memGauge: sutMem,
    memLimitBytes: MEM_LIMIT_BYTES,
    onMemLimit: (memVal) => {
      exec.test.abort(`Memory limit exceeded: ${memVal}`);
    },
  });
}

export function load(data) {
  return runLoad(data);
}
