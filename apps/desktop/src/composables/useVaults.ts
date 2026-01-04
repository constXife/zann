import { computed, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, VaultSummary } from "../types";

type Translator = (key: string) => string;

type UseVaultsOptions = {
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
  listLoading: Ref<boolean>;
  onFatalError: (message: string) => void;
  t: Translator;
};

export const useVaults = (options: UseVaultsOptions) => {
  const vaults = ref<VaultSummary[]>([]);

  const personalVaults = computed(() =>
    vaults.value.filter((v) => v.kind === "personal"),
  );
  const sharedVaults = computed(() =>
    vaults.value.filter((v) => v.kind === "shared"),
  );

  const loadVaults = async () => {
    if (!options.initialized.value || !options.unlocked.value) {
      return;
    }
    options.listLoading.value = true;
    try {
      const response = await invoke<ApiResponse<VaultSummary[]>>("vault_list", {
        req: { storage_id: options.selectedStorageId.value },
      });
      if (!response.ok || !response.data) {
        const message = response.error?.message;
        const key = response.error?.kind ?? "generic";
        throw new Error(message ?? options.t(`errors.${key}`));
      }
      vaults.value = response.data;
      if (!options.selectedVaultId.value && response.data.length > 0) {
        options.selectedVaultId.value = response.data[0].id;
      }
    } catch (err) {
      options.onFatalError(String(err));
    } finally {
      options.listLoading.value = false;
    }
  };

  return {
    vaults,
    personalVaults,
    sharedVaults,
    loadVaults,
  };
};
