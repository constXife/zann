import { computed } from "vue";
import type { ComputedRef, Ref } from "vue";
import type { StorageSummary, VaultSummary } from "../../../types";
import { StorageKind } from "../../../constants/enums";

type AppVaultContextOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  storages: Ref<StorageSummary[]>;
  vaults: Ref<VaultSummary[]>;
  sharedVaults: Ref<VaultSummary[]>;
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
};

export function useAppVaultContext({
  t,
  storages,
  vaults,
  sharedVaults,
  selectedStorageId,
  selectedVaultId,
}: AppVaultContextOptions) {
  const currentStorage = computed(() =>
    storages.value.find((storage) => storage.id === selectedStorageId.value),
  );
  const selectedVault = computed(
    () => vaults.value.find((vault) => vault.id === selectedVaultId.value) ?? null,
  );
  const selectedVaultName = computed(
    () => selectedVault.value?.name ?? t("nav.vaults"),
  );
  const isSharedVault = computed(
    () =>
      !!selectedVaultId.value &&
      sharedVaults.value.some((vault) => vault.id === selectedVaultId.value),
  );
  const vaultContextLabel = computed(() => {
    const storage = currentStorage.value;
    const parts: string[] = [];
    if (storage?.kind === StorageKind.Remote) {
      parts.push(storage.server_name ?? storage.name ?? storage.server_url ?? t("nav.vaults"));
      parts.push(isSharedVault.value ? t("nav.shared") : t("nav.personal"));
    } else if (storage) {
      parts.push(t("storage.localVault"));
    }
    if (selectedVaultName.value) {
      parts.push(selectedVaultName.value);
    }
    return parts.filter(Boolean).join(" • ");
  });

  return {
    currentStorage,
    selectedVaultName,
    isSharedVault,
    vaultContextLabel,
  };
}
