import { ref } from "vue";
import type { ComputedRef, Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { UiSettings } from "../../useUiSettings";
import type { ApiResponse, StorageInfo, StorageSummary } from "../../../types";

type AppStorageActionsOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  uiSettings: Ref<UiSettings>;
  storages: Ref<StorageSummary[]>;
  localStorageRef: Ref<StorageSummary | null>;
  hasLocalVaults: ComputedRef<boolean>;
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
  localStorageId: string;
  loadStorages: () => Promise<void>;
  loadVaults: () => Promise<void>;
  loadItems: () => Promise<void>;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  refreshStatus: () => Promise<void>;
  refreshAppStatus: () => Promise<void>;
  getStorageInfo: (storageId: string) => Promise<StorageInfo | null>;
  deleteStorage: (storageId: string, moveToTrash: boolean) => Promise<boolean>;
  disconnectStorage: (storageId: string) => Promise<boolean>;
  revealStorage: (storageId: string) => Promise<void>;
  openCreateModal: (mode: "item" | "vault") => void;
  setupOpen: Ref<boolean>;
  setupStep: Ref<"welcome" | "password" | "connect">;
  settingsOpen: Ref<boolean>;
  settingsInitialTab: Ref<"general" | "accounts">;
  showAuthMethodSelection: () => Promise<void>;
  connectServerUrl: Ref<string>;
  setError: (message: string) => void;
  showToast: (message: string, options?: { duration?: number }) => void;
};

export function useAppStorageActions({
  t,
  uiSettings,
  storages,
  localStorageRef,
  hasLocalVaults,
  selectedStorageId,
  selectedVaultId,
  localStorageId,
  loadStorages,
  loadVaults,
  loadItems,
  runRemoteSync,
  refreshStatus,
  refreshAppStatus,
  getStorageInfo,
  deleteStorage,
  disconnectStorage,
  revealStorage,
  openCreateModal,
  setupOpen,
  setupStep,
  settingsOpen,
  settingsInitialTab,
  showAuthMethodSelection,
  connectServerUrl,
  setError,
  showToast,
}: AppStorageActionsOptions) {
  const storageDropdownOpen = ref(false);
  const vaultDropdownOpen = ref(false);
  const deleteStorageOpen = ref(false);
  const deleteStorageInfo = ref<StorageInfo | null>(null);
  const deleteStorageBusy = ref(false);

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
    setupOpen.value = true;
    setupStep.value = "connect";
  };

  const openStorageSettings = () => {
    storageDropdownOpen.value = false;
    settingsInitialTab.value = "accounts";
    settingsOpen.value = true;
  };

  const handleStorageReveal = async (storageId: string) => {
    await revealStorage(storageId);
  };

  const handleStorageDisconnect = async (storageId: string) => {
    const info = await getStorageInfo(storageId);
    if (info) {
      deleteStorageInfo.value = info;
      deleteStorageOpen.value = true;
      settingsOpen.value = false;
    }
  };

  const handleStorageDelete = async (storageId: string) => {
    const info = await getStorageInfo(storageId);
    if (info) {
      deleteStorageInfo.value = info;
      deleteStorageOpen.value = true;
      settingsOpen.value = false;
    }
  };

  const handleStorageGetInfo = async (
    storageId: string,
    callback: (info: StorageInfo | null) => void,
  ) => {
    const info = await getStorageInfo(storageId);
    callback(info);
  };

  const handleSignOut = async (storageId: string, eraseCache: boolean) => {
    try {
      const response = await invoke<ApiResponse<null>>("storage_sign_out", {
        storageId,
        eraseCache,
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw new Error(t(`errors.${key}`));
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
      uiSettings.value.lastSelectedStorageId = localStorageId;
    }
    if (selectedStorageId.value === storageId) {
      selectedStorageId.value = localStorageId;
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
        throw new Error(t(`errors.${key}`));
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
        throw new Error(t(`errors.${key}`));
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

  const openCreateVault = () => {
    vaultDropdownOpen.value = false;
    void openCreateModal("vault");
  };

  const openCreateLocalVault = () => {
    storageDropdownOpen.value = false;
    uiSettings.value.showLocalStorage = true;
    if (localStorageRef.value) {
      selectedStorageId.value = localStorageRef.value.id;
    }
    if (!hasLocalVaults.value) {
      void openCreateModal("vault");
    }
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

  const confirmDeleteStorage = async (moveToTrash: boolean) => {
    if (!deleteStorageInfo.value) return;
    deleteStorageBusy.value = true;
    const success = await deleteStorage(deleteStorageInfo.value.id, moveToTrash);
    deleteStorageBusy.value = false;
    if (success) {
      deleteStorageOpen.value = false;
      deleteStorageInfo.value = null;
    }
  };

  const confirmDisconnectStorage = async (_eraseCache: boolean) => {
    if (!deleteStorageInfo.value) return;
    deleteStorageBusy.value = true;
    const success = await disconnectStorage(deleteStorageInfo.value.id);
    deleteStorageBusy.value = false;
    if (success) {
      deleteStorageOpen.value = false;
      deleteStorageInfo.value = null;
    }
  };

  return {
    storageDropdownOpen,
    vaultDropdownOpen,
    deleteStorageOpen,
    deleteStorageInfo,
    deleteStorageBusy,
    toggleStorageDropdown,
    closeStorageDropdown,
    switchStorage,
    openAddStorageWizard,
    openStorageSettings,
    handleStorageReveal,
    handleStorageDisconnect,
    handleStorageDelete,
    handleStorageGetInfo,
    handleSignOut,
    handleRemoveServer,
    handleSignIn,
    handleClearData,
    handleFactoryReset,
    handleSyncNow,
    openCreateVault,
    openCreateLocalVault,
    toggleVaultDropdown,
    closeVaultDropdown,
    switchVault,
    confirmDeleteStorage,
    confirmDisconnectStorage,
  };
}
