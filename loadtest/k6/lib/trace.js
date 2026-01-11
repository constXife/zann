import exec from "k6/execution";

export function makeRequestId() {
  const random = Math.random().toString(16).slice(2);
  return `k6-${exec.vu.idInTest}-${exec.vu.iterationInScenario}-${Date.now()}-${random}`;
}
