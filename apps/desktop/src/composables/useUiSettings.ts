import { ref, watch } from "vue";

export type UiSettings = {
  language: string;
  theme: "system" | "light" | "dark";
  sidebarCollapsed: boolean;
  sidebarWidth: number;
  detailsWidth: number;
  showLocalStorage: boolean;
  listDensity: "comfortable" | "compact";
  defaultVaultId: string | null;
  lastSelectedSection: string;
  lastSelectedStorageId: string | null;
  lastSelectedVaultByStorage: Record<string, string>;
  lastCreateItemType: string;
};

const UI_SETTINGS_KEY = "zann:ui-settings";

const defaults: UiSettings = {
  language: "system",
  theme: "system",
  sidebarCollapsed: false,
  sidebarWidth: 280,
  detailsWidth: 520,
  showLocalStorage: false,
  listDensity: "comfortable",
  defaultVaultId: null,
  lastSelectedSection: "all",
  lastSelectedStorageId: null,
  lastSelectedVaultByStorage: {},
  lastCreateItemType: "login",
};

function load(): UiSettings {
  const stored = localStorage.getItem(UI_SETTINGS_KEY);
  if (!stored) {
    return { ...defaults };
  }
  return { ...defaults, ...JSON.parse(stored) };
}

function save(settings: UiSettings) {
  localStorage.setItem(UI_SETTINGS_KEY, JSON.stringify(settings));
}

const uiSettings = ref<UiSettings>(load());

watch(uiSettings, (value) => save(value), { deep: true });

export function useUiSettings() {
  return {
    settings: uiSettings,
    reset: () => {
      uiSettings.value = { ...defaults };
    },
  };
}
