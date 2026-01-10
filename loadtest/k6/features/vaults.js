import http from "k6/http";
import { check } from "k6";
import { withName } from "../lib/metrics.js";

export function listVaults(baseUrl, params) {
  const res = http.get(`${baseUrl}/v1/vaults`, withName(params, "vaults.list"));
  check(res, {
    "vaults list ok": (r) => r.status === 200,
  });
  const vaults = res.json("vaults") || [];
  return { res, vaults };
}

export function pickVaultId(vaults) {
  if (!vaults || vaults.length === 0) {
    return "";
  }
  const vault = vaults[0];
  return vault?.id || vault?.vault_id || "";
}

export function pickSharedVaultId(vaults, slug) {
  if (!vaults || vaults.length === 0) {
    return "";
  }
  if (slug) {
    const bySlug = vaults.find((vault) => vault.slug === slug);
    if (bySlug) {
      return bySlug?.id || bySlug?.vault_id || "";
    }
  }
  const shared = vaults.find((vault) => vault.kind === "shared");
  if (shared) {
    return shared?.id || shared?.vault_id || "";
  }
  return "";
}

export function pickPersonalVaultId(vaults) {
  if (!vaults || vaults.length === 0) {
    return "";
  }
  const personal = vaults.find((vault) => vault.kind === "personal");
  if (personal) {
    return personal?.id || personal?.vault_id || "";
  }
  return "";
}
