import { watch } from "vue";
import type { ComputedRef, Ref } from "vue";
import type { ItemDetail, ItemSummary, Settings, VaultSummary } from "../../../types";
import type { UiSettings } from "../../useUiSettings";

type AppWatchersOptions = {
  initialized: ComputedRef<boolean>;
  unlocked: ComputedRef<boolean>;
  startAutoSync: () => void;
  stopAutoSync: () => void;
  loadStorages: () => Promise<void>;
  loadVaults: () => Promise<void>;
  loadItems: () => Promise<void>;
  vaults: Ref<VaultSummary[]>;
  items: Ref<ItemSummary[]>;
  filteredItems: ComputedRef<ItemSummary[]>;
  selectedItem: Ref<ItemDetail | null>;
  selectedVaultId: Ref<string | null>;
  selectedStorageId: Ref<string>;
  selectedItemId: Ref<string | null>;
  uiSettings: Ref<UiSettings>;
  loadItemDetail: (itemId: string) => Promise<void>;
  revealedFields: Ref<Set<string>>;
  itemDetailError: Ref<string>;
  error: Ref<string>;
  clearToast: () => void;
  fatalError: Ref<string>;
  settings: Ref<Settings | null>;
  idleTimer: Ref<number | null>;
  lastActivityAt: Ref<number>;
  clearRevealTimer: () => void;
  lockSession: () => Promise<void> | void;
  storages: Ref<{ id: string }[]>;
  scheduleTrashPurge: () => void;
};

export function useAppWatchers({
  initialized,
  unlocked,
  startAutoSync,
  stopAutoSync,
  loadStorages,
  loadVaults,
  loadItems,
  vaults,
  items,
  filteredItems,
  selectedItem,
  selectedVaultId,
  selectedStorageId,
  selectedItemId,
  uiSettings,
  loadItemDetail,
  revealedFields,
  itemDetailError,
  error,
  clearToast,
  fatalError,
  settings,
  idleTimer,
  lastActivityAt,
  clearRevealTimer,
  lockSession,
  storages,
  scheduleTrashPurge,
}: AppWatchersOptions) {
  watch(
    () => [initialized.value, unlocked.value],
    async ([isInitialized, isUnlocked]) => {
      if (isInitialized && isUnlocked) {
        startAutoSync();
        lastActivityAt.value = Date.now();
        await loadStorages();
        await loadVaults();
        await loadItems();
      } else {
        stopAutoSync();
        vaults.value = [];
        items.value = [];
        selectedItem.value = null;
        clearToast();
        fatalError.value = "";
      }
    },
  );

  watch(selectedVaultId, async () => {
    if (initialized.value && unlocked.value) {
      await loadItems();
    }
    if (selectedVaultId.value) {
      uiSettings.value.lastSelectedVaultByStorage[selectedStorageId.value] =
        selectedVaultId.value;
    }
  });

  watch(selectedStorageId, async () => {
    uiSettings.value.lastSelectedStorageId = selectedStorageId.value;
    selectedVaultId.value =
      uiSettings.value.lastSelectedVaultByStorage[selectedStorageId.value] ?? null;
    selectedItemId.value = null;
    if (initialized.value && unlocked.value) {
      await loadVaults();
      if (
        selectedVaultId.value &&
        !vaults.value.some((vault) => vault.id === selectedVaultId.value)
      ) {
        selectedVaultId.value = vaults.value[0]?.id ?? null;
      }
      await loadItems();
    }
  });

  watch(selectedItemId, async (value) => {
    console.info("[details] selected_item_id", { itemId: value });
    revealedFields.value = new Set();
    itemDetailError.value = "";
    if (!value) {
      selectedItem.value = null;
      return;
    }
    try {
      await loadItemDetail(value);
      console.info("[details] sidebar_ready", {
        itemId: selectedItem.value?.id ?? null,
        name: selectedItem.value?.name ?? null,
      });
    } catch (err) {
      selectedItem.value = null;
      error.value = String(err);
      itemDetailError.value = error.value;
    }
  });

  watch(items, async () => {
    if (!initialized.value || !unlocked.value) {
      return;
    }
    if (!selectedItemId.value || selectedItem.value?.id !== selectedItemId.value) {
      return;
    }
    await loadItemDetail(selectedItemId.value);
  });

  watch(filteredItems, (value) => {
    if (value.length === 0) {
      selectedItemId.value = null;
      return;
    }
    if (!selectedItemId.value) {
      selectedItemId.value = value[0].id;
    }
  });

  watch(
    () => settings.value,
    (value) => {
      if (idleTimer.value) {
        window.clearInterval(idleTimer.value);
        idleTimer.value = null;
      }
      if (!value) {
        return;
      }
      if (value.auto_hide_reveal_seconds <= 0) {
        clearRevealTimer();
      }
      if (value.auto_lock_minutes > 0) {
        idleTimer.value = window.setInterval(() => {
          if (!unlocked.value) {
            return;
          }
          const elapsed = Date.now() - lastActivityAt.value;
          if (elapsed > value.auto_lock_minutes * 60 * 1000) {
            void lockSession();
          }
        }, 1000);
      }
    },
    { deep: true },
  );

  watch(
    () => ({
      unlocked: unlocked.value,
      days: settings.value?.trash_auto_purge_days ?? 0,
      storageIds: storages.value.map((storage) => storage.id).join(","),
    }),
    (value) => {
      if (!value.unlocked || value.days <= 0) {
        return;
      }
      scheduleTrashPurge();
    },
  );
}
