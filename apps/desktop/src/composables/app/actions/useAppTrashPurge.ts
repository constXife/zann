import { ref } from "vue";
import type { ComputedRef, Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { ApiResponse, Settings } from "../../../types";

type AppTrashPurgeOptions = {
  settings: Ref<Settings | null>;
  unlocked: ComputedRef<boolean>;
  initialized: ComputedRef<boolean>;
  storages: Ref<{ id: string }[]>;
  loadItems: () => Promise<void>;
};

export function useAppTrashPurge({
  settings,
  unlocked,
  initialized,
  storages,
  loadItems,
}: AppTrashPurgeOptions) {
  const trashPurgeTimer = ref<number | null>(null);

  const runTrashPurge = async () => {
    if (!settings.value || !unlocked.value || !initialized.value) {
      return;
    }
    const days = settings.value.trash_auto_purge_days ?? 0;
    if (days <= 0) {
      return;
    }
    for (const storage of storages.value) {
      try {
        const response = await invoke<ApiResponse<number>>("items_purge_trash", {
          req: {
            storage_id: storage.id,
            older_than_days: days,
          },
        });
        if (!response.ok) {
          continue;
        }
      } catch {
        // Silent best-effort cleanup.
      }
    }
    await loadItems();
  };

  const scheduleTrashPurge = () => {
    if (trashPurgeTimer.value) {
      window.clearTimeout(trashPurgeTimer.value);
    }
    trashPurgeTimer.value = window.setTimeout(() => {
      trashPurgeTimer.value = null;
      void runTrashPurge();
    }, 1000);
  };

  const clearTrashPurgeTimer = () => {
    if (!trashPurgeTimer.value) {
      return;
    }
    window.clearTimeout(trashPurgeTimer.value);
    trashPurgeTimer.value = null;
  };

  return {
    scheduleTrashPurge,
    clearTrashPurgeTimer,
  };
}
