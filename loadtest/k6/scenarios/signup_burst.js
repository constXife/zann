import { sleep } from "k6";

import { buildHeaders } from "../lib/headers.js";
import { ACCESS_TOKEN_ENV, BASE_URL } from "../lib/env.js";
import { resolveStages } from "../lib/profile.js";
import { makeRequestId } from "../lib/trace.js";
import { registerUser } from "../features/auth.js";
import { listVaults, pickVaultId } from "../features/vaults.js";
import { listItems } from "../features/items.js";

const TEST_RUN_ID =
  __ENV.ZANN_TEST_RUN_ID ||
  `k6-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
const EMAIL_DOMAIN = __ENV.K6_EMAIL_DOMAIN || "loadtest.local";
const FOLLOWUP_ENABLED = __ENV.K6_SIGNUP_FOLLOWUP !== "0";

const jsonHeaders = { "Content-Type": "application/json" };

export const options = {
  stages: resolveStages([
    { duration: "1m", target: 20 },
    { duration: "5m", target: 50 },
    { duration: "1m", target: 0 },
  ]),
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<600", "p(99)<1200"],
  },
};

function headersFor(token) {
  return buildHeaders({
    token,
    requestId: makeRequestId(),
    testRunId: TEST_RUN_ID,
    extraHeaders: jsonHeaders,
  });
}

export default function () {
  const { body } = registerUser(BASE_URL, headersFor(""), { emailDomain: EMAIL_DOMAIN });
  const accessToken = body?.access_token || "";
  if (!FOLLOWUP_ENABLED || !accessToken) {
    sleep(Math.random() * 0.3);
    return;
  }
  const { vaults } = listVaults(BASE_URL, headersFor(accessToken));
  const vaultId = pickVaultId(vaults);
  if (vaultId) {
    listItems(BASE_URL, vaultId, headersFor(accessToken));
  }
  sleep(Math.random() * 0.3);
}
