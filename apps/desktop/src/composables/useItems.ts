import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, ItemSummary } from "../types";
import { createErrorWithCause } from "./errors";

type Translator = (key: string) => string;

type UseItemsOptions = {
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
  listLoading: Ref<boolean>;
  listError: Ref<string>;
  t: Translator;
  onAfterLoad?: () => void;
};

export const useItems = (options: UseItemsOptions) => {
  const items = ref<ItemSummary[]>([]);

  const loadItems = async (loadOptions?: { silent?: boolean }) => {
    const shouldToggleLoading = !loadOptions?.silent;
    if (!options.selectedVaultId.value || !options.initialized.value || !options.unlocked.value) {
      items.value = [];
      options.listError.value = "";
      if (shouldToggleLoading) {
        options.listLoading.value = false;
      }
      return;
    }
    if (shouldToggleLoading) {
      options.listLoading.value = true;
    }
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
        throw createErrorWithCause(options.t(`errors.${key}`), response.error);
      }
      items.value = response.data;
      options.listError.value = "";
      options.onAfterLoad?.();
    } catch (err) {
      options.listError.value = String(err);
    } finally {
      if (shouldToggleLoading) {
        options.listLoading.value = false;
      }
    }
  };

  return {
    items,
    loadItems,
  };
};
