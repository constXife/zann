import http from "k6/http";
import { sleep } from "k6";

export function vmInstantQuery(vmUrl, query) {
  if (!vmUrl) {
    return null;
  }
  const url = `${vmUrl}/api/v1/query?query=${encodeURIComponent(query)}`;
  const res = http.get(url, { timeout: "5s" });
  if (res.status !== 200) {
    return null;
  }
  const body = res.json();
  const value = body?.data?.result?.[0]?.value?.[1];
  if (value === undefined || value === null) {
    return null;
  }
  const parsed = Number(value);
  if (Number.isNaN(parsed)) {
    return null;
  }
  return parsed;
}

export function parseIntervalSeconds(interval) {
  const match = interval.match(/^(\d+)(ms|s|m)$/);
  if (!match) {
    return 5;
  }
  const value = Number(match[1]);
  const unit = match[2];
  if (unit === "ms") {
    return Math.max(1, Math.round(value / 1000));
  }
  if (unit === "m") {
    return value * 60;
  }
  return value;
}

export function parseDurationSeconds(duration) {
  const match = duration.match(/^(\d+(?:\.\d+)?)(ms|s|m|h)$/);
  if (!match) {
    return 0;
  }
  const value = Number(match[1]);
  const unit = match[2];
  if (Number.isNaN(value)) {
    return 0;
  }
  if (unit === "ms") {
    return value / 1000;
  }
  if (unit === "m") {
    return value * 60;
  }
  if (unit === "h") {
    return value * 60 * 60;
  }
  return value;
}

export function calcStagesDurationSeconds(stages) {
  if (!Array.isArray(stages)) {
    return 0;
  }
  return stages.reduce((total, stage) => {
    if (!stage?.duration) {
      return total;
    }
    return total + parseDurationSeconds(stage.duration);
  }, 0);
}

export function monitorOnce({
  enabled,
  vmUrl,
  cpuQuery,
  memQuery,
  cpuGauge,
  memGauge,
  memLimitBytes,
  onMemLimit,
}) {
  if (!enabled) {
    return;
  }
  const cpuVal = vmInstantQuery(vmUrl, cpuQuery);
  const memVal = vmInstantQuery(vmUrl, memQuery);

  if (cpuVal != null && cpuGauge) {
    cpuGauge.add(cpuVal);
  }
  if (memVal != null && memGauge) {
    memGauge.add(memVal);
    if (memLimitBytes && memVal > memLimitBytes && typeof onMemLimit === "function") {
      onMemLimit(memVal);
    }
  }
}

export function monitorLoop({ intervalSeconds, ...opts }) {
  while (true) {
    monitorOnce(opts);
    sleep(intervalSeconds);
  }
}
