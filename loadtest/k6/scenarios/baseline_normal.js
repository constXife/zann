import { sleep } from "k6";
import exec from "k6/execution";

import { setupAuth } from "../lib/auth.js";
import { buildHeaders } from "../lib/headers.js";
import { ACCESS_TOKEN_ENV, BASE_URL, SERVICE_ACCOUNT_TOKEN } from "../lib/env.js";
import { resolveStages } from "../lib/profile.js";
import { makeRequestId } from "../lib/trace.js";
import { pickWeighted } from "../lib/random.js";
import { systemBatch } from "../features/system.js";
import { registerUser } from "../features/auth.js";
import {
  createPersonalItem,
  createSharedItem,
  deleteItem,
  getItem,
  listItemVersions,
  listItems,
  updatePersonalItem,
  updateSharedItem,
} from "../features/items.js";
import { ensureSecret, rotateSecret } from "../features/secrets.js";
import {
  createFileId,
  createSharedFileItem,
  downloadFile,
  uploadFile,
} from "../features/files.js";
import {
  listVaults,
  pickPersonalVaultId,
  pickSharedVaultId,
  pickVaultId,
} from "../features/vaults.js";

const TEST_RUN_ID =
  __ENV.ZANN_TEST_RUN_ID ||
  `k6-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
const FILE_SIZE_BYTES = Number(__ENV.K6_FILE_SIZE_BYTES || "2048");
const EMAIL_DOMAIN = __ENV.K6_EMAIL_DOMAIN || "loadtest.local";
const SHARED_VAULT_SLUG =
  __ENV.K6_SHARED_VAULT_SLUG || __ENV.ZANN_LOADTEST_VAULT_SLUG || "loadtest";
const registerEnabled = __ENV.K6_REGISTER_ENABLED === "1";
const writeEnabled = ACCESS_TOKEN_ENV.length > 0 || __ENV.K6_WRITES_ENABLED === "1";
const personalRatioRaw = Number(__ENV.K6_PERSONAL_RATIO || "0.3");
const sharedRatioRaw = Number(__ENV.K6_SHARED_RATIO || "0.7");
const ratioSum = Math.max(0, personalRatioRaw) + Math.max(0, sharedRatioRaw);
const personalRatio = ratioSum > 0 ? Math.max(0, personalRatioRaw) / ratioSum : 0.3;

const jsonHeaders = { "Content-Type": "application/json" };
const binaryHeaders = { "Content-Type": "application/octet-stream" };

const localState = {
  vaultId: "",
  sharedVaultId: "",
  personalVaultId: "",
  itemIds: [],
  sharedItemIds: [],
  personalItemIds: [],
};

export const options = {
  stages: resolveStages([
    { duration: "2m", target: 30 },
    { duration: "10m", target: 60 },
    { duration: "2m", target: 0 },
  ]),
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<400", "p(99)<800"],
  },
};

function headersFor(token, extraHeaders) {
  return buildHeaders({
    token,
    requestId: makeRequestId(),
    testRunId: TEST_RUN_ID,
    extraHeaders,
  });
}

function refreshVaults(token) {
  const { vaults } = listVaults(BASE_URL, headersFor(token));
  localState.vaultId = pickVaultId(vaults);
  localState.sharedVaultId = pickSharedVaultId(vaults, SHARED_VAULT_SLUG);
  localState.personalVaultId = pickPersonalVaultId(vaults);
}

function refreshItemsForVault(token, vaultId, targetKey) {
  if (!vaultId) {
    localState[targetKey] = [];
    return;
  }
  const { items } = listItems(BASE_URL, vaultId, headersFor(token));
  localState[targetKey] = items.map((item) => item.id).filter(Boolean);
}

function pickItemId(list) {
  if (!list || list.length === 0) {
    return "";
  }
  const idx = Math.floor(Math.random() * list.length);
  return list[idx];
}

function ensureItemId(token) {
  if (!localState.vaultId) {
    refreshVaults(token);
  }
  if (!localState.vaultId) {
    return "";
  }
  let itemId = pickItemId(localState.itemIds);
  if (itemId) {
    return itemId;
  }
  refreshItemsForVault(token, localState.vaultId, "itemIds");
  itemId = pickItemId(localState.itemIds);
  if (itemId) {
    return itemId;
  }
  if (!writeEnabled) {
    return "";
  }
  const res = createSharedItem(
    BASE_URL,
    localState.vaultId,
    headersFor(token, jsonHeaders),
  );
  const created = res.json();
  itemId = created?.id || "";
  if (itemId) {
    localState.itemIds.push(itemId);
  }
  return itemId;
}

function ensureSharedItemId(token) {
  if (!localState.sharedVaultId) {
    refreshVaults(token);
  }
  if (!localState.sharedVaultId) {
    return "";
  }
  let itemId = pickItemId(localState.sharedItemIds);
  if (itemId) {
    return itemId;
  }
  refreshItemsForVault(token, localState.sharedVaultId, "sharedItemIds");
  itemId = pickItemId(localState.sharedItemIds);
  if (itemId) {
    return itemId;
  }
  if (!writeEnabled) {
    return "";
  }
  const res = createSharedItem(
    BASE_URL,
    localState.sharedVaultId,
    headersFor(token, jsonHeaders),
  );
  const created = res.json();
  itemId = created?.id || "";
  if (itemId) {
    localState.sharedItemIds.push(itemId);
  }
  return itemId;
}

function ensurePersonalItemId(token) {
  if (!localState.personalVaultId) {
    refreshVaults(token);
  }
  if (!localState.personalVaultId) {
    return "";
  }
  let itemId = pickItemId(localState.personalItemIds);
  if (itemId) {
    return itemId;
  }
  refreshItemsForVault(token, localState.personalVaultId, "personalItemIds");
  itemId = pickItemId(localState.personalItemIds);
  if (itemId) {
    return itemId;
  }
  if (!writeEnabled) {
    return "";
  }
  const res = createPersonalItem(
    BASE_URL,
    localState.personalVaultId,
    headersFor(token, jsonHeaders),
  );
  const created = res.json();
  itemId = created?.id || "";
  if (itemId) {
    localState.personalItemIds.push(itemId);
  }
  return itemId;
}

function pickVaultKind() {
  if (!localState.personalVaultId) {
    return "shared";
  }
  return Math.random() < personalRatio ? "personal" : "shared";
}

function vaultIdForKind(kind) {
  return kind === "personal" ? localState.personalVaultId : localState.sharedVaultId;
}

function actionReadList(token) {
  systemBatch(BASE_URL);
  refreshVaults(token);
  if (localState.vaultId) {
    refreshItemsForVault(token, localState.vaultId, "itemIds");
  }
}

function actionReadGet(token) {
  const kind = pickVaultKind();
  const itemId = kind === "personal" ? ensurePersonalItemId(token) : ensureSharedItemId(token);
  if (!itemId) {
    return;
  }
  const vaultId = vaultIdForKind(kind);
  if (!vaultId) {
    return;
  }
  getItem(BASE_URL, vaultId, itemId, headersFor(token));
}

function actionReadVersions(token) {
  const kind = pickVaultKind();
  const itemId = kind === "personal" ? ensurePersonalItemId(token) : ensureSharedItemId(token);
  if (!itemId) {
    return;
  }
  const vaultId = vaultIdForKind(kind);
  if (!vaultId) {
    return;
  }
  listItemVersions(BASE_URL, vaultId, itemId, headersFor(token));
}

function actionWriteCreate(token) {
  const kind = pickVaultKind();
  if (kind === "personal") {
    if (!localState.personalVaultId) {
      refreshVaults(token);
    }
    if (!localState.personalVaultId) {
      return;
    }
    const res = createPersonalItem(
      BASE_URL,
      localState.personalVaultId,
      headersFor(token, jsonHeaders),
    );
    const created = res.json();
    const itemId = created?.id || "";
    if (itemId) {
      localState.personalItemIds.push(itemId);
    }
    return;
  }
  if (!localState.sharedVaultId) {
    refreshVaults(token);
  }
  if (!localState.sharedVaultId) {
    return;
  }
  const res = createSharedItem(
    BASE_URL,
    localState.sharedVaultId,
    headersFor(token, jsonHeaders),
  );
  const created = res.json();
  const itemId = created?.id || "";
  if (itemId) {
    localState.sharedItemIds.push(itemId);
  }
}

function actionWriteUpdate(token) {
  const kind = pickVaultKind();
  const itemId = kind === "personal" ? ensurePersonalItemId(token) : ensureSharedItemId(token);
  if (!itemId) {
    return;
  }
  if (kind === "personal") {
    updatePersonalItem(
      BASE_URL,
      localState.personalVaultId,
      itemId,
      headersFor(token, jsonHeaders),
    );
  } else {
    updateSharedItem(
      BASE_URL,
      localState.sharedVaultId,
      itemId,
      headersFor(token, jsonHeaders),
    );
  }
}

function actionWriteDelete(token) {
  const kind = pickVaultKind();
  const itemId = kind === "personal" ? ensurePersonalItemId(token) : ensureSharedItemId(token);
  if (!itemId) {
    return;
  }
  if (kind === "personal") {
    deleteItem(BASE_URL, localState.personalVaultId, itemId, headersFor(token));
    localState.personalItemIds = localState.personalItemIds.filter((id) => id !== itemId);
  } else {
    deleteItem(BASE_URL, localState.sharedVaultId, itemId, headersFor(token));
    localState.sharedItemIds = localState.sharedItemIds.filter((id) => id !== itemId);
  }
}

function actionHeavySecrets(token) {
  if (!localState.sharedVaultId) {
    refreshVaults(token);
  }
  if (!localState.sharedVaultId) {
    return;
  }
  const ensured = ensureSecret(
    BASE_URL,
    localState.sharedVaultId,
    headersFor(token, jsonHeaders),
  );
  if (!ensured?.path) {
    return;
  }
  rotateSecret(
    BASE_URL,
    localState.sharedVaultId,
    ensured.path,
    headersFor(token, jsonHeaders),
  );
}

function actionHeavyFiles(token) {
  if (!localState.sharedVaultId) {
    refreshVaults(token);
  }
  if (!localState.sharedVaultId) {
    return;
  }
  const fileId = createFileId();
  const res = createSharedFileItem(
    BASE_URL,
    localState.sharedVaultId,
    fileId,
    headersFor(token, jsonHeaders),
  );
  const created = res.json();
  const itemId = created?.id || "";
  if (!itemId) {
    return;
  }
  const bytes = new Uint8Array(FILE_SIZE_BYTES);
  uploadFile(
    BASE_URL,
    localState.sharedVaultId,
    itemId,
    fileId,
    bytes,
    headersFor(token, binaryHeaders),
  );
  downloadFile(
    BASE_URL,
    localState.sharedVaultId,
    itemId,
    headersFor(token, binaryHeaders),
  );
}

function actionRegister() {
  registerUser(BASE_URL, headersFor("", jsonHeaders), { emailDomain: EMAIL_DOMAIN });
}

const actions = (() => {
  if (writeEnabled) {
    if (registerEnabled) {
      return [
        { name: "read_list", weight: 0.33, run: actionReadList },
        { name: "read_get", weight: 0.2, run: actionReadGet },
        { name: "read_versions", weight: 0.15, run: actionReadVersions },
        { name: "write_create", weight: 0.08, run: actionWriteCreate },
        { name: "write_update", weight: 0.08, run: actionWriteUpdate },
        { name: "write_delete", weight: 0.04, run: actionWriteDelete },
        { name: "heavy_secrets", weight: 0.06, run: actionHeavySecrets },
        { name: "heavy_files", weight: 0.04, run: actionHeavyFiles },
        { name: "auth_register", weight: 0.02, run: actionRegister },
      ];
    }
    return [
      { name: "read_list", weight: 0.35, run: actionReadList },
      { name: "read_get", weight: 0.2, run: actionReadGet },
      { name: "read_versions", weight: 0.15, run: actionReadVersions },
      { name: "write_create", weight: 0.08, run: actionWriteCreate },
      { name: "write_update", weight: 0.08, run: actionWriteUpdate },
      { name: "write_delete", weight: 0.04, run: actionWriteDelete },
      { name: "heavy_secrets", weight: 0.06, run: actionHeavySecrets },
      { name: "heavy_files", weight: 0.04, run: actionHeavyFiles },
    ];
  }
  if (registerEnabled) {
    return [
      { name: "read_list", weight: 0.48, run: actionReadList },
      { name: "read_get", weight: 0.3, run: actionReadGet },
      { name: "read_versions", weight: 0.2, run: actionReadVersions },
      { name: "auth_register", weight: 0.02, run: actionRegister },
    ];
  }
  return [
    { name: "read_list", weight: 0.5, run: actionReadList },
    { name: "read_get", weight: 0.3, run: actionReadGet },
    { name: "read_versions", weight: 0.2, run: actionReadVersions },
  ];
})();

export function setup() {
  return setupAuth({
    baseUrl: BASE_URL,
    accessTokenEnv: ACCESS_TOKEN_ENV,
    serviceAccountToken: SERVICE_ACCOUNT_TOKEN,
    jsonHeaders,
    loginParams: (headers) =>
      buildHeaders({
        requestId: makeRequestId(),
        testRunId: TEST_RUN_ID,
        extraHeaders: headers,
      }),
  });
}

export function runBaseline(data) {
  if (!data.token) {
    systemBatch(BASE_URL);
    sleep(Math.random() * 0.5);
    return;
  }

  if (
    (!localState.vaultId || !localState.sharedVaultId) &&
    exec.vu.iterationInScenario % 5 === 0
  ) {
    refreshVaults(data.token);
  }

  const action = pickWeighted(Math.random, actions);
  action.run(data.token);

  sleep(Math.random() * 0.6);
}

export default function (data) {
  return runBaseline(data);
}
