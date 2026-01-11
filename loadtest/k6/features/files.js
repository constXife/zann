import http from "k6/http";
import { check } from "k6";

import { logFailure } from "../lib/logging.js";
import { withName } from "../lib/metrics.js";
import { randomId, randomUuidV4 } from "../lib/random.js";

function makeFilePayload(fileId) {
  return {
    v: 1,
    typeId: "file_secret",
    fields: {},
    extra: {
      file_id: fileId,
      upload_state: "pending",
      filename: "secret.bin",
      mime: "application/octet-stream",
    },
  };
}

export function createSharedFileItem(baseUrl, vaultId, fileId, params) {
  const payload = {
    path: `k6/files/${randomId("file")}`,
    name: "File Secret",
    type_id: "file_secret",
    payload: makeFilePayload(fileId),
  };
  const res = http.post(
    `${baseUrl}/v1/vaults/${vaultId}/items`,
    JSON.stringify(payload),
    withName(params, "files.item.create"),
  );
  check(res, {
    "file item create ok": (r) => r.status === 201,
  });
  return res;
}

export function createFileId() {
  return randomUuidV4();
}

export function uploadFile(
  baseUrl,
  vaultId,
  itemId,
  fileId,
  bytes,
  params,
) {
  const url = `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}/file` +
    `?representation=plain&file_id=${fileId}`;
  const res = http.post(url, bytes, withName(params, "files.upload"));
  if (res.status !== 200) {
    logFailure(res, "files.upload");
  }
  check(res, {
    "file upload ok": (r) => r.status === 200,
  });
  return res;
}

export function downloadFile(baseUrl, vaultId, itemId, params) {
  const url = `${baseUrl}/v1/vaults/${vaultId}/items/${itemId}/file?representation=plain`;
  const res = http.get(url, withName(params, "files.download"));
  if (res.status !== 200) {
    logFailure(res, "files.download");
  }
  check(res, {
    "file download ok": (r) => r.status === 200,
  });
  return res;
}
