import http from "k6/http";
import { check } from "k6";
import { sha256 } from "k6/crypto";

import { logFailure } from "../lib/logging.js";
import { withName } from "../lib/metrics.js";
import { randomAscii, randomId } from "../lib/random.js";

export function listItems(baseUrl, vaultId, params) {
  const res = http.get(
    `${baseUrl}/v1/vaults/${vaultId}/items`,
    withName(params, "items.list"),
  );
  check(res, {
    "items list ok": (r) => r.status === 200,
  });
  const items = res.json("items") || [];
  return { res, items };
}

export function getItem(baseUrl, vaultId, itemId, params) {
  const res = http.get(
    `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}`,
    withName(params, "items.get"),
  );
  check(res, {
    "item get ok": (r) => r.status === 200,
  });
  return res;
}

export function listItemVersions(baseUrl, vaultId, itemId, params) {
  const res = http.get(
    `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}/versions?limit=5`,
    withName(params, "items.versions.list"),
  );
  check(res, {
    "item versions list ok": (r) => r.status === 200,
  });
  return res;
}

export function createSharedItem(baseUrl, vaultId, params) {
  const path = `k6/${randomAscii(6)}/${randomId("item")}`;
  const payload = {
    path,
    name: path,
    type_id: "login",
    payload: {
      v: 1,
      typeId: "login",
      fields: {
        username: { kind: "text", value: "k6-user" },
        password: { kind: "password", value: randomAscii(12) },
      },
    },
  };
  const res = http.post(
    `${baseUrl}/v1/vaults/${vaultId}/items`,
    JSON.stringify(payload),
    withName(params, "items.create"),
  );
  check(res, {
    "item create ok": (r) => r.status === 201,
  });
  return res;
}

export function createPersonalItem(baseUrl, vaultId, params) {
  const path = `k6/${randomAscii(6)}/${randomId("personal")}`;
  const payloadBytes = new Uint8Array(32);
  for (let i = 0; i < payloadBytes.length; i += 1) {
    payloadBytes[i] = Math.floor(Math.random() * 256);
  }
  const payloadEnc = Array.from(payloadBytes);
  const checksum = sha256(payloadBytes, "hex");
  const payload = {
    path,
    name: path,
    type_id: "login",
    payload_enc: payloadEnc,
    checksum,
  };
  const res = http.post(
    `${baseUrl}/v1/vaults/${vaultId}/items`,
    JSON.stringify(payload),
    withName(params, "items.create.personal"),
  );
  check(res, {
    "item create ok": (r) => r.status === 201,
  });
  return res;
}

export function updateSharedItem(baseUrl, vaultId, itemId, params) {
  const payload = {
    path: `k6/${randomAscii(6)}/${randomId("item-upd")}`,
    name: `k6-${randomId("upd")}`,
    type_id: "login",
    payload: {
      v: 1,
      typeId: "login",
      fields: {
        password: { kind: "password", value: randomAscii(14) },
      },
    },
  };
  const res = http.put(
    `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}`,
    JSON.stringify(payload),
    withName(params, "items.update"),
  );
  if (res.status !== 200 && res.status !== 409) {
    logFailure(res, "items.update");
  }
  check(res, {
    "item update ok": (r) => r.status === 200 || r.status === 409,
  });
  return res;
}

export function updatePersonalItem(baseUrl, vaultId, itemId, params) {
  const payload = {
    path: `k6/${randomAscii(6)}/${randomId("personal-upd")}`,
    name: `k6-${randomId("p-upd")}`,
  };
  const res = http.put(
    `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}`,
    JSON.stringify(payload),
    withName(params, "items.update.personal"),
  );
  if (res.status !== 200 && res.status !== 409) {
    logFailure(res, "items.update.personal");
  }
  check(res, {
    "item update ok": (r) => r.status === 200 || r.status === 409,
  });
  return res;
}

export function deleteItem(baseUrl, vaultId, itemId, params) {
  const res = http.del(
    `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}`,
    null,
    withName(params, "items.delete"),
  );
  if (res.status !== 204 && res.status !== 404 && res.status !== 409) {
    logFailure(res, "items.delete");
  }
  check(res, {
    "item delete ok": (r) => r.status === 204 || r.status === 404 || r.status === 409,
  });
  return res;
}
