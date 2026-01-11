import { onBeforeUnmount, onMounted, ref } from "vue";
import type { ComputedRef, Ref } from "vue";
import { listen } from "@tauri-apps/api/event";
import type { Settings } from "../../../types";

type PaletteItem = { action?: () => void; enabled?: boolean };

type AppEventHandlersOptions = {
  settings: Ref<Settings | null>;
  unlocked: ComputedRef<boolean>;
  storageDropdownOpen: Ref<boolean>;
  vaultDropdownOpen: Ref<boolean>;
  paletteOpen: Ref<boolean>;
  paletteIndex: Ref<number>;
  paletteItems: Ref<PaletteItem[]>;
  createModalOpen: Ref<boolean>;
  selectedItem: Ref<{ id: string } | null>;
  copyPrimarySecret: () => Promise<void> | void;
  revealToggle: () => void;
  openCreateModal: (mode: "item" | "vault") => void;
  detailsPanel: Ref<{ focusSearch?: () => void } | null>;
  moveSelection: (delta: number) => void;
  selectedItemId: Ref<string | null>;
  loadItemDetail: (itemId: string) => Promise<void>;
  settingsOpen: Ref<boolean>;
  openSettings: (tab?: "general" | "accounts") => void;
  lockSession: () => Promise<void> | void;
  scheduleRemoteSync: (storageId: string | null) => void;
  selectedStorageId: Ref<string>;
  clearClipboardNow: () => Promise<void> | void;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  timeTravelActive: Ref<boolean>;
  timeTravelIndex: Ref<number>;
  timeTravelMaxIndex: ComputedRef<number>;
  setTimeTravelIndex: (index: number) => Promise<void> | void;
};

export function useAppEventHandlers({
  settings,
  unlocked,
  storageDropdownOpen,
  vaultDropdownOpen,
  paletteOpen,
  paletteIndex,
  paletteItems,
  createModalOpen,
  selectedItem,
  copyPrimarySecret,
  revealToggle,
  openCreateModal,
  detailsPanel,
  moveSelection,
  selectedItemId,
  loadItemDetail,
  settingsOpen,
  openSettings,
  lockSession,
  scheduleRemoteSync,
  selectedStorageId,
  clearClipboardNow,
  runRemoteSync,
  timeTravelActive,
  timeTravelIndex,
  timeTravelMaxIndex,
  setTimeTravelIndex,
}: AppEventHandlersOptions) {
  const lastActivityAt = ref(Date.now());
  const altRevealAll = ref(false);
  let cacheInvalidationUnlisten: null | (() => void) = null;
  let settingsUnlisten: null | (() => void) = null;

  const onActivity = () => {
    lastActivityAt.value = Date.now();
  };

  const onVisibility = () => {
    if (!settings.value || !unlocked.value) {
      return;
    }
    if (document.hidden && settings.value.lock_on_hidden) {
      void lockSession();
      return;
    }
    if (!document.hidden) {
      scheduleRemoteSync(selectedStorageId.value);
    }
  };

  const onBlur = () => {
    if (!settings.value || !unlocked.value) {
      return;
    }
    if (settings.value.lock_on_focus_loss) {
      void lockSession();
    }
  };

  const onBeforeUnload = () => {
    if (settings.value?.clipboard_clear_on_exit) {
      void clearClipboardNow();
    }
  };

  const isTextInputFocused = () => {
    const active = document.activeElement;
    if (!active) {
      return false;
    }
    if ((active as HTMLElement).isContentEditable) {
      return true;
    }
    const tag = active.tagName.toLowerCase();
    if (tag === "input") {
      return (active as HTMLInputElement).type !== "range";
    }
    return tag === "textarea" || tag === "select";
  };

  const onKeydown = (event: KeyboardEvent) => {
    if ((storageDropdownOpen.value || vaultDropdownOpen.value) && event.key === "Escape") {
      event.preventDefault();
      storageDropdownOpen.value = false;
      vaultDropdownOpen.value = false;
      return;
    }

    if (paletteOpen.value) {
      if (event.key >= "1" && event.key <= "8") {
        event.preventDefault();
        const index = Number(event.key) - 1;
        const entry = paletteItems.value[index];
        if (entry?.action && entry.enabled !== false) {
          entry.action();
        }
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        const max = paletteItems.value.length - 1;
        paletteIndex.value = Math.min(max, paletteIndex.value + 1);
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        paletteIndex.value = Math.max(0, paletteIndex.value - 1);
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        const selected = paletteItems.value[paletteIndex.value];
        if (selected?.action && selected.enabled !== false) {
          selected.action();
        }
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        paletteOpen.value = false;
        return;
      }
    }
    if (isTextInputFocused()) {
      return;
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      paletteOpen.value = !paletteOpen.value;
    }
    if ((event.metaKey || event.ctrlKey) && event.key === ",") {
      event.preventDefault();
      openSettings();
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "l") {
      event.preventDefault();
      void lockSession();
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "c") {
      if (createModalOpen.value) {
        return;
      }
      if (selectedItem.value) {
        event.preventDefault();
        void copyPrimarySecret();
      }
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "r") {
      if (selectedItem.value) {
        event.preventDefault();
        revealToggle();
      }
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "n") {
      event.preventDefault();
      openCreateModal("item");
    }
    if (event.key === "/") {
      event.preventDefault();
      detailsPanel.value?.focusSearch?.();
    }
    if (timeTravelActive.value) {
      if (event.key === "ArrowLeft" || event.key.toLowerCase() === "a") {
        event.preventDefault();
        setTimeTravelIndex(timeTravelIndex.value + 1);
        return;
      }
      if (event.key === "ArrowRight" || event.key.toLowerCase() === "d") {
        event.preventDefault();
        setTimeTravelIndex(timeTravelIndex.value - 1);
        return;
      }
      if (event.key === "Home") {
        event.preventDefault();
        setTimeTravelIndex(timeTravelMaxIndex.value);
        return;
      }
      if (event.key === "End") {
        event.preventDefault();
        setTimeTravelIndex(0);
        return;
      }
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveSelection(1);
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      moveSelection(-1);
    }
    if (event.key === "Enter" && selectedItemId.value) {
      event.preventDefault();
      void loadItemDetail(selectedItemId.value);
    }
    if (event.key === "Escape") {
      paletteOpen.value = false;
      settingsOpen.value = false;
      createModalOpen.value = false;
    }
  };

  const handleAltRevealKeydown = (event: KeyboardEvent) => {
    if (event.key === "Alt") {
      altRevealAll.value = true;
    }
  };

  const handleAltRevealKeyup = (event: KeyboardEvent) => {
    if (event.key === "Alt") {
      altRevealAll.value = false;
    }
  };

  const handleAltRevealBlur = () => {
    altRevealAll.value = false;
  };

  const initCacheInvalidationListener = async () => {
    if (cacheInvalidationUnlisten) {
      return;
    }
    cacheInvalidationUnlisten = await listen("shared-cache-invalidated", () => {
      if (!unlocked.value) {
        return;
      }
      void runRemoteSync();
    });
  };

  const initSettingsListener = async () => {
    if (settingsUnlisten) {
      return;
    }
    settingsUnlisten = await listen("zann:open-settings", () => {
      openSettings();
    });
  };

  onMounted(() => {
    window.addEventListener("keydown", onKeydown);
    window.addEventListener("mousemove", onActivity);
    window.addEventListener("keydown", onActivity);
    window.addEventListener("click", onActivity);
    window.addEventListener("scroll", onActivity);
    window.addEventListener("keydown", handleAltRevealKeydown);
    window.addEventListener("keyup", handleAltRevealKeyup);
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("blur", onBlur);
    window.addEventListener("blur", handleAltRevealBlur);
    window.addEventListener("beforeunload", onBeforeUnload);
    void initCacheInvalidationListener();
    void initSettingsListener();
  });

  onBeforeUnmount(() => {
    window.removeEventListener("keydown", onKeydown);
    window.removeEventListener("mousemove", onActivity);
    window.removeEventListener("keydown", onActivity);
    window.removeEventListener("click", onActivity);
    window.removeEventListener("scroll", onActivity);
    window.removeEventListener("keydown", handleAltRevealKeydown);
    window.removeEventListener("keyup", handleAltRevealKeyup);
    document.removeEventListener("visibilitychange", onVisibility);
    window.removeEventListener("blur", onBlur);
    window.removeEventListener("blur", handleAltRevealBlur);
    window.removeEventListener("beforeunload", onBeforeUnload);
    if (cacheInvalidationUnlisten) {
      cacheInvalidationUnlisten();
      cacheInvalidationUnlisten = null;
    }
    if (settingsUnlisten) {
      settingsUnlisten();
      settingsUnlisten = null;
    }
  });

  return {
    lastActivityAt,
    altRevealAll,
  };
}
