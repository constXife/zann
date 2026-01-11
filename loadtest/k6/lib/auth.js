import http from "k6/http";
import { check } from "k6";

const defaultJsonHeaders = { "Content-Type": "application/json" };

export function setupAuth({
  baseUrl,
  accessTokenEnv,
  serviceAccountToken,
  jsonHeaders = defaultJsonHeaders,
  loginParams,
}) {
  if (accessTokenEnv) {
    return { token: accessTokenEnv };
  }
  if (!serviceAccountToken) {
    console.warn("No access token provided; only public endpoints will be tested.");
    return { token: "" };
  }
  const params =
    typeof loginParams === "function" ? loginParams(jsonHeaders) : { headers: jsonHeaders };
  const res = http.post(
    `${baseUrl}/v1/auth/service-account`,
    JSON.stringify({ token: serviceAccountToken }),
    params,
  );
  const ok = check(res, {
    "service-account login ok": (r) => r.status === 200,
  });
  if (!ok) {
    console.warn(`Service-account login failed: ${res.status} ${res.body}`);
    return { token: "" };
  }
  const body = res.json();
  return { token: body?.access_token || "" };
}
