import { sleep } from "k6";

import { setupAuth } from "../lib/auth.js";
import { authHeaders } from "../lib/headers.js";
import { ACCESS_TOKEN_ENV, BASE_URL, SERVICE_ACCOUNT_TOKEN } from "../lib/env.js";
import { resolveStages } from "../lib/profile.js";
import { systemBatch } from "../features/system.js";
import { listVaults, pickVaultId } from "../features/vaults.js";
import { listItems } from "../features/items.js";

export const options = {
  stages: resolveStages([
    { duration: "1m", target: 10 },
    { duration: "3m", target: 30 },
    { duration: "1m", target: 0 },
  ]),
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<1500"],
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
