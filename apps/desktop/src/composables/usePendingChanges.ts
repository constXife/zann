import { ref, computed, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse } from "../types";

type UsePendingChangesOptions = {
  selectedStorageId: Ref<string>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
};

export const usePendingChanges = (options: UsePendingChangesOptions) => {
  const pendingChangesByStorage = ref<Map<string, number>>(new Map());

  const pendingChangesCount = computed(
    () => pendingChangesByStorage.value.get(options.selectedStorageId.value) ?? 0,
  );

  const refreshPendingChanges = async (storageId = options.selectedStorageId.value) => {
    if (!options.initialized.value || !options.unlocked.value || !storageId) {
      return;
    }
    try {
      const response = await invoke<ApiResponse<number>>("pending_changes_count", {
        req: { storage_id: storageId },
      });
      if (response.ok && typeof response.data === "number") {
        pendingChangesByStorage.value.set(storageId, response.data);
      }
    } catch {
      // Ignore count refresh failures, offline state handles visibility.
    }
  };

  watch(
    () => [options.selectedStorageId.value, options.initialized.value, options.unlocked.value],
    () => {
      void refreshPendingChanges();
    },
    { immediate: true },
  );

  return {
    pendingChangesByStorage,
    pendingChangesCount,
    refreshPendingChanges,
  };
};
