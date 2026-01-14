import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, ItemDetail } from "../types";
import { createErrorWithCause } from "./errors";

type Translator = (key: string) => string;

type UseConflictActionsOptions = {
  selectedItem: Ref<ItemDetail | null>;
  selectedStorageId: Ref<string>;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  loadItems: () => Promise<void>;
  t: Translator;
  showToast: (message: string, options?: { duration?: number }) => void;
  formatError: (error: unknown) => string;
};

export const useConflictActions = (options: UseConflictActionsOptions) => {
  const resolveConflict = async () => {
    if (!options.selectedItem.value) {
      return;
    }
    try {
      const response = await invoke<ApiResponse<null>>("items_resolve_conflict", {
        req: {
          storage_id: options.selectedStorageId.value,
          item_id: options.selectedItem.value.id,
        },
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        const message = response.error?.message ?? options.t(`errors.${key}`);
        throw createErrorWithCause(message, response.error);
      }
      await options.runRemoteSync(options.selectedStorageId.value);
      await options.loadItems();
      options.showToast(options.t("items.resolveConflictDone"));
    } catch (err) {
      options.showToast(options.formatError(err), { duration: 1800 });
    }
  };

  return { resolveConflict };
};
