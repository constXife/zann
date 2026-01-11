import http from "k6/http";
import { check } from "k6";

import { logFailure } from "../lib/logging.js";
import { withName } from "../lib/metrics.js";
import { randomAscii, randomId } from "../lib/random.js";

export function ensureSecret(baseUrl, vaultId, params) {
  const path = `k6/${randomAscii(6)}/${randomId("secret")}`;
  const payload = {
    path,
    meta: {
      source: "k6",
    },
  };
  const res = http.post(
    `${baseUrl}/v1/vaults/${vaultId}/secrets/ensure`,
    JSON.stringify(payload),
    withName(params, "secrets.ensure"),
  );
  if (res.status !== 200) {
    logFailure(res, "secrets.ensure");
  }
  check(res, {
    "secret ensure ok": (r) => r.status === 200,
  });
  const ok = res.status === 200;
  return { res, path: ok ? path : "", ok };
}

export function rotateSecret(baseUrl, vaultId, path, params) {
  const payload = {
    path,
    meta: {
      source: "k6",
    },
  };
  const res = http.post(
    `${baseUrl}/v1/vaults/${vaultId}/secrets/rotate`,
    JSON.stringify(payload),
    withName(params, "secrets.rotate"),
  );
  if (res.status !== 200) {
    logFailure(res, "secrets.rotate");
  }
  check(res, {
    "secret rotate ok": (r) => r.status === 200,
  });
  return res;
}
