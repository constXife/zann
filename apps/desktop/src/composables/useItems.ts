import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, ItemSummary } from "../types";

type Translator = (key: string) => string;

type UseItemsOptions = {
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
  listLoading: Ref<boolean>;
  onFatalError: (message: string) => void;
  t: Translator;
};

export const useItems = (options: UseItemsOptions) => {
  const items = ref<ItemSummary[]>([]);

  const loadItems = async () => {
    if (!options.selectedVaultId.value || !options.initialized.value || !options.unlocked.value) {
      items.value = [];
      return;
    }
    options.listLoading.value = true;
    try {
      const response = await invoke<ApiResponse<ItemSummary[]>>("items_list", {
        req: {
          storage_id: options.selectedStorageId.value,
          vault_id: options.selectedVaultId.value,
          include_deleted: true,
        },
      });
      if (!response.ok || !response.data) {
        const key = response.error?.kind ?? "generic";
        throw new Error(options.t(`errors.${key}`));
      }
      items.value = response.data;
    } catch (err) {
      options.onFatalError(String(err));
    } finally {
      options.listLoading.value = false;
    }
  };

  return {
    items,
    loadItems,
  };
};
