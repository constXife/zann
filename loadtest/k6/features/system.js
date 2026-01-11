import http from "k6/http";
import { withName } from "../lib/metrics.js";

export function systemBatch(baseUrl, requestParams) {
  const params = typeof requestParams === "function" ? requestParams : () => ({});
  return http.batch([
    ["GET", `${baseUrl}/health`, null, withName(params(), "system.health")],
    ["GET", `${baseUrl}/v1/system/info`, null, withName(params(), "system.info")],
    [
      "GET",
      `${baseUrl}/v1/system/security-profiles`,
      null,
      withName(params(), "system.security_profiles"),
    ],
  ]);
}
