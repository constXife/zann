import { ref } from "vue";
import type { Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { UiSettings } from "../../useUiSettings";
import type { ApiResponse, StorageSummary } from "../../../types";
import { createErrorWithCause } from "../../errors";

type AppStorageActionsOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  uiSettings: Ref<UiSettings>;
  storages: Ref<StorageSummary[]>;

  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;

  loadStorages: () => Promise<void>;
  loadVaults: () => Promise<void>;
  loadItems: (options?: { silent?: boolean }) => Promise<void>;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  refreshStatus: () => Promise<void>;
  refreshAppStatus: () => Promise<void>;
  disconnectStorage: (storageId: string) => Promise<boolean>;
  revealStorage: (storageId: string) => Promise<void>;
  openCreateModal: (mode: "item" | "vault") => void;
  setupOpen: Ref<boolean>;
  setupStep: Ref<"welcome" | "password" | "connect">;
  settingsOpen: Ref<boolean>;
  settingsInitialTab: Ref<"general" | "accounts">;
  startConnect: () => void;
  showAuthMethodSelection: () => Promise<void>;
  connectServerUrl: Ref<string>;
  setError: (message: string) => void;
  showToast: (message: string, options?: { duration?: number }) => void;
};

export function useAppStorageActions({
  t,
  uiSettings,
  storages,

  selectedStorageId,
  selectedVaultId,

  loadStorages,
  loadVaults,
  loadItems,
  runRemoteSync,
  refreshStatus,
  refreshAppStatus,
  disconnectStorage,
  revealStorage,
  openCreateModal,
  setupOpen,
  setupStep,
  settingsOpen,
  settingsInitialTab,
  startConnect,
  showAuthMethodSelection,
  connectServerUrl,
  setError,
  showToast,
}: AppStorageActionsOptions) {
  const storageDropdownOpen = ref(false);
  const vaultDropdownOpen = ref(false);

  const toggleStorageDropdown = () => {
    storageDropdownOpen.value = !storageDropdownOpen.value;
  };

  const closeStorageDropdown = () => {
    storageDropdownOpen.value = false;
  };

  const switchStorage = (storageId: string) => {
    selectedStorageId.value = storageId;
    storageDropdownOpen.value = false;
  };

  const openAddStorageWizard = () => {
    storageDropdownOpen.value = false;
    startConnect();
    setupOpen.value = true;
  };

  const openStorageSettings = () => {
    storageDropdownOpen.value = false;
    settingsInitialTab.value = "accounts";
    settingsOpen.value = true;
  };

  const handleStorageReveal = async (storageId: string) => {
    await revealStorage(storageId);
  };

  const handleSignOut = async (storageId: string, eraseCache: boolean) => {
    try {
      const response = await invoke<ApiResponse<null>>("storage_sign_out", {
        storageId,
        eraseCache,
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      setError("");
      await loadStorages();
      await loadVaults();
      await loadItems();
      showToast(t("common.saved"));
    } catch (err) {
      setError(String(err));
    }
  };

  const handleRemoveServer = async (storageId: string) => {
    await disconnectStorage(storageId);
    if (uiSettings.value.lastSelectedStorageId === storageId) {
      uiSettings.value.lastSelectedStorageId = "";
    }
    if (selectedStorageId.value === storageId) {
      selectedStorageId.value = "";
    }
    if (uiSettings.value.lastSelectedVaultByStorage[storageId]) {
      delete uiSettings.value.lastSelectedVaultByStorage[storageId];
    }
  };

  const handleSignIn = async (storageId: string) => {
    const storage = storages.value.find((s) => s.id === storageId);
    if (!storage?.server_url) return;

    settingsOpen.value = false;
    connectServerUrl.value = storage.server_url;
    setupStep.value = "connect";
    setupOpen.value = true;
    await showAuthMethodSelection();
  };

  const handleClearData = async (
    alsoClearRemoteCache: boolean,
    alsoRemoveConnections: boolean,
  ) => {
    try {
      const response = await invoke<ApiResponse<null>>("local_clear_data", {
        alsoClearRemoteCache,
        alsoRemoveConnections,
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      await loadStorages();
      await loadVaults();
      await loadItems();
      showToast(t("common.saved"));
    } catch (err) {
      setError(String(err));
    }
  };

  const handleFactoryReset = async () => {
    try {
      const response = await invoke<ApiResponse<null>>("local_factory_reset");
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      await refreshStatus();
      await refreshAppStatus();
    } catch (err) {
      setError(String(err));
    }
  };

  const handleSyncNow = async (storageId: string) => {
    await runRemoteSync(storageId);
  };

  const handleResetSyncCursor = async (storageId: string) => {
    try {
      const response = await invoke<ApiResponse<null>>("sync_reset_cursor", { storageId });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      await runRemoteSync(storageId);
      showToast(t("common.saved"));
    } catch (err) {
      setError(String(err));
    }
  };

  const openCreateVault = () => {
    vaultDropdownOpen.value = false;
    void openCreateModal("vault");
  };

  const toggleVaultDropdown = () => {
    vaultDropdownOpen.value = !vaultDropdownOpen.value;
  };

  const closeVaultDropdown = () => {
    vaultDropdownOpen.value = false;
  };

  const switchVault = (vaultId: string) => {
    selectedVaultId.value = vaultId;
    vaultDropdownOpen.value = false;
  };

  return {
    storageDropdownOpen,
    vaultDropdownOpen,
    toggleStorageDropdown,
    closeStorageDropdown,
    switchStorage,
    openAddStorageWizard,
    openStorageSettings,
    handleStorageReveal,
    handleSignOut,
    handleRemoveServer,
    handleSignIn,
    handleClearData,
    handleFactoryReset,
    handleSyncNow,
    handleResetSyncCursor,
    openCreateVault,

    toggleVaultDropdown,
    closeVaultDropdown,
    switchVault,
  };
}
