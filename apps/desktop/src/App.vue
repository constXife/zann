<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";
import { open as openShell } from "@tauri-apps/plugin-shell";
import { useUiSettings } from "./composables/useUiSettings";
import { useAppLayout } from "./composables/app/state/useAppLayout";
import { useAppAuthFlow } from "./composables/app/actions/useAppAuthFlow";
import { useAppItemFilters } from "./composables/app/state/useAppItemFilters";
import { useAppItemActions } from "./composables/app/actions/useAppItemActions";
import { useAppStorageActions } from "./composables/app/actions/useAppStorageActions";
import { useAppSettingsActions } from "./composables/app/actions/useAppSettingsActions";
import { useAppEventHandlers } from "./composables/app/actions/useAppEventHandlers";
import { useAppTrashPurge } from "./composables/app/actions/useAppTrashPurge";
import { useAppWatchers } from "./composables/app/actions/useAppWatchers";
import { useAppPersonalUnlock } from "./composables/app/actions/useAppPersonalUnlock";
import { useAppToast } from "./composables/app/state/useAppToast";
import { useAppConfirm } from "./composables/app/state/useAppConfirm";
import { useAppComputed } from "./composables/app/state/useAppComputed";
import { useAppBindings } from "./composables/app/actions/useAppBindings";
import { useAppStatusBanners } from "./composables/app/state/useAppStatusBanners";
import { useAppVaultContext } from "./composables/app/state/useAppVaultContext";
import { useItemDetails } from "./composables/useItemDetails";
import { useConflictActions } from "./composables/useConflictActions";
import { getSchemaFieldDefs } from "./data/secretSchemas";
import { useItems } from "./composables/useItems";
import { usePendingChanges } from "./composables/usePendingChanges";
import { useStorages } from "./composables/useStorages";
import { useVaults } from "./composables/useVaults";
import { useFolders } from "./composables/useFolders";
import { useCreateModal } from "./composables/useCreateModal";
import { useClipboard } from "./composables/useClipboard";
import { useBootstrap } from "./composables/useBootstrap";
import { usePalette } from "./composables/usePalette";
import { useSession } from "./composables/useSession";
import { StorageKind } from "./constants/enums";
import logoUrl from "./assets/logo.png";
import AppShell from "./components/AppShell.vue";
import AppModals from "./components/AppModals.vue";
import type {
  ApiResponse,
  KeystoreStatus,
} from "./types";

const LOCAL_STORAGE_ID = "00000000-0000-0000-0000-000000000000";

const { t, locale } = useI18n();
const { settings: uiSettings } = useUiSettings();

const password = ref("");
const error = ref("");
const identityAlertOpen = ref(false);
const identityAlertTitle = ref("");
const identityAlertMessage = ref("");
const initialStorageId = uiSettings.value.lastSelectedStorageId ?? LOCAL_STORAGE_ID;
const selectedStorageId = ref(initialStorageId);
const selectedVaultId = ref<string | null>(
  uiSettings.value.lastSelectedVaultByStorage[initialStorageId] ?? null,
);
const selectedItemId = ref<string | null>(null);
const itemDetailError = ref("");
const listLoading = ref(false);
const listLoadingMore = ref(false);
const listError = ref("");
const fatalError = ref("");
const settingsOpen = ref(uiSettings.value.lastSettingsOpen ?? false);
const settingsInitialTab = ref<"general" | "security" | "accounts" | "backups" | "about">(
  (uiSettings.value.lastSettingsTab as "general" | "security" | "accounts" | "backups" | "about")
    ?? "general",
);
const openSettings = (tab: "general" | "accounts" = "general") => {
  settingsInitialTab.value = tab;
  settingsOpen.value = true;
};
const idleTimer = ref<number | null>(null);

const {
  status,
  appStatus,
  settings,
  autoUnlockError,
  keystoreStatus,
  refreshStatus,
  refreshAppStatus,
  bootstrap,
} = useBootstrap({
  t,
  locale,
  onFatalError: (message) => {
    fatalError.value = message;
  },
});

const unlocked = computed(() => status.value?.unlocked ?? false);
const initialized = computed(() => appStatus.value?.initialized ?? false);
const showMain = computed(() => appStatus.value && initialized.value && unlocked.value);

const toastState = useAppToast();
const { toasts, clearToast, showToast, clearToastTimer } = toastState;

const confirmState = useAppConfirm();
const {
  confirmOpen,
  confirmTitle,
  confirmMessage,
  confirmConfirmLabel,
  confirmCancelLabel,
  confirmBusy,
  confirmInputExpected,
  confirmInputLabel,
  confirmInputPlaceholder,
  openConfirm,
  handleConfirm,
} = confirmState;


const { copyToClipboard, clearClipboardNow, clearClipboardTimer } = useClipboard({
  settings,
  t,
  setToast: (message) => {
    showToast(message);
  },
});

const vaultState = useVaults({
  selectedStorageId,
  selectedVaultId,
  initialized,
  unlocked,
  listLoading,
  onFatalError: (message) => {
    fatalError.value = message;
  },
  t,
});
const { vaults, personalVaults, sharedVaults, loadVaults } = vaultState;

const pendingChangesState = usePendingChanges({
  selectedStorageId,
  initialized,
  unlocked,
});

const itemsState = useItems({
  selectedStorageId,
  selectedVaultId,
  initialized,
  unlocked,
  listLoading,
  listLoadingMore,
  listError,
  t,
  onAfterLoad: () => {
    void pendingChangesState.refreshPendingChanges();
  },
});
const { items, loadItems, loadMoreItems, hasMore, totalCount, itemCounts } = itemsState;
const totalItemsCount = computed(() => itemCounts.value?.all ?? totalCount.value);

const storageState = useStorages({
  selectedStorageId,
  initialized,
  unlocked,
  t,
  localStorageId: LOCAL_STORAGE_ID,
  onFatalError: (message) => {
    fatalError.value = message;
  },
  onReloadVaults: loadVaults,
  onReloadItems: loadItems,
  onSessionExpired: (_serverUrl) => {
    // Ничего не делаем - баннер покажется автоматически через storageSyncErrors
  },
  localStorageVisible: computed(() => uiSettings.value.showLocalStorage),
});
const {
  storages, remoteStorages, localStorage: localStorageRef, hasLocalVaults, showLocalSection,
  storageSyncErrors, storagePersonalLocked, isOffline, syncBusy, syncError, loadStorages, checkLocalVaults,
  runRemoteSync: runRemoteSyncRaw, scheduleRemoteSync, startAutoSync, stopAutoSync, clearSyncErrors, getSyncStatus,
  getStorageInfo, deleteStorage, disconnectStorage, revealStorage,
} = storageState;

const lastSyncTime = ref<string | null>(null);
let lastSyncRequestId = 0;
const refreshLastSyncTime = async (storageId: string | null = selectedStorageId.value) => {
  const requestId = ++lastSyncRequestId;
  if (!storageId || storageId === LOCAL_STORAGE_ID) {
    if (requestId === lastSyncRequestId) {
      lastSyncTime.value = null;
    }
    return;
  }
  const info = await getStorageInfo(storageId);
  if (requestId === lastSyncRequestId) {
    lastSyncTime.value = info?.last_synced ?? null;
  }
};
const runRemoteSync = async (storageId?: string | null) => {
  const targetId = storageId ?? selectedStorageId.value;
  const storage = storages.value.find((entry) => entry.id === targetId);
  if (!storage) {
    if (!targetId) {
      return false;
    }
    const result = await runRemoteSyncRaw(targetId);
    await refreshLastSyncTime(targetId);
    return result;
  }
  if (storage.kind === StorageKind.LocalOnly) {
    return false;
  }
  const result = await runRemoteSyncRaw(targetId);
  await refreshLastSyncTime(targetId);
  return result;
};

const runBootstrap = async () => {
  error.value = "";
  fatalError.value = "";
  await bootstrap();
  if (status.value?.unlocked && appStatus.value?.initialized) {
    await loadStorages();
    await refreshLastSyncTime();
    await checkLocalVaults();
    await loadVaults();
    await loadItems();
  }
};

runBootstrap();

const {
  currentStorage,
  selectedVaultName,
  isSharedVault,
  vaultContextLabel,
} = useAppVaultContext({
  t,
  storages,
  vaults,
  sharedVaults,
  selectedStorageId,
  selectedVaultId,
});

const itemDetailsState = useItemDetails({
  selectedStorageId,
  initialized,
  unlocked,
  settings,
  t,
  onError: (message) => {
    error.value = message;
  },
});
const selectedItem = itemDetailsState.selectedItem;
const detailSections = itemDetailsState.detailSections;
const revealedFields = itemDetailsState.revealedFields;

const sessionState = useSession({
  t,
  status,
  settings,
  refreshStatus,
  refreshAppStatus,
  clearClipboardNow,
  clearClipboardTimer,
  clearRevealTimer: itemDetailsState.clearRevealTimer,
  onAfterUnlock: async () => {
    await loadStorages();
    await runRemoteSync();
  },
  onLocked: () => {
    selectedItem.value = null;
    selectedItemId.value = null;
    revealedFields.value = new Set();
    showToast("Locked");
  },
  onError: (message) => {
    error.value = message;
  },
});
const { unlockBusy, unlock, unlockWithBiometrics, lockSession } = sessionState;
const doUnlock = () => void unlock(password);
const refreshKeystoreStatus = async () => {
  const ks = await invoke<ApiResponse<KeystoreStatus>>("keystore_status");
  if (ks.ok && ks.data) {
    keystoreStatus.value = ks.data;
  }
};

const scheduleRemoteSyncAsync = async (storageId: string | null) => {
  scheduleRemoteSync(storageId);
};
const selectedCategory = ref<string | null>(uiSettings.value.lastSelectedSection ?? "all");
const createState = useCreateModal({
  selectedStorageId,
  selectedVaultId,
  selectedItemId,
  vaults,
  items,
  selectedItem,
  selectedCategory,
  loadItems,
  loadVaults,
  runRemoteSync: scheduleRemoteSyncAsync,
  localStorageId: LOCAL_STORAGE_ID,
  lastCreateItemType: computed(() => uiSettings.value.lastCreateItemType),
  t,
  onOptimisticHistory: (payload) => itemDetailsState.addOptimisticHistory(payload),
  onOptimisticHistoryRollback: (version) => itemDetailsState.removeOptimisticHistory(version),
});

const foldersState = useFolders({
  items,
  selectedStorageId,
  createItemFolder: createState.createItemFolder,
  onReloadItems: loadItems,
  t,
});
const selectedFolder = foldersState.selectedFolder;

const {
  query,
  categoryCounts,
  categories,
  selectCategory,
  selectedSubtype,
  selectSubtype,
  filteredItems,
  isDeletedItem,
} = useAppItemFilters({
  t,
  items,
  itemCounts,
  isSharedVault,
  selectedFolder,
  selectedCategory,
});
if (!query.value) {
  query.value = uiSettings.value.lastSearchQuery ?? "";
}
const statusBanners = useAppStatusBanners({
  selectedStorageId,
  storageSyncErrors,
  storagePersonalLocked,
  isOffline,
  pendingChangesByStorage: pendingChangesState.pendingChangesByStorage,
  localStorageId: LOCAL_STORAGE_ID,
});
const {
  showOfflineBanner, showSessionExpiredBanner, showPersonalLockedBanner,
  syncErrorMessage, showSyncErrorBanner, pendingChangesCount,
} = statusBanners;

watch(
  () => [selectedStorageId.value, storages.value],
  () => {
    void refreshLastSyncTime();
  },
  { immediate: true },
);

watch(settingsOpen, (value) => {
  uiSettings.value.lastSettingsOpen = value;
});

watch(settingsInitialTab, (value) => {
  uiSettings.value.lastSettingsTab = value;
});

watch(selectedCategory, (value) => {
  uiSettings.value.lastSelectedSection = value ?? "all";
});

watch(query, (value) => {
  uiSettings.value.lastSearchQuery = value ?? "";
});

watch(selectedFolder, (value) => {
  const vaultId = selectedVaultId.value;
  if (!vaultId) {
    return;
  }
  if (!value) {
    delete uiSettings.value.lastSelectedFolderByVault[vaultId];
  } else {
    uiSettings.value.lastSelectedFolderByVault[vaultId] = value;
  }
});

watch(selectedItemId, (value) => {
  const vaultId = selectedVaultId.value;
  if (!vaultId) {
    return;
  }
  if (!value) {
    delete uiSettings.value.lastSelectedItemByVault[vaultId];
  } else {
    uiSettings.value.lastSelectedItemByVault[vaultId] = value;
  }
});

watch(selectedVaultId, (vaultId) => {
  if (!vaultId) {
    selectedFolder.value = null;
    return;
  }
  const savedFolder = uiSettings.value.lastSelectedFolderByVault[vaultId] ?? null;
  selectedFolder.value = savedFolder;
});

watch(items, () => {
  const vaultId = selectedVaultId.value;
  if (!vaultId || items.value.length === 0) {
    return;
  }
  const savedItem = uiSettings.value.lastSelectedItemByVault[vaultId];
  if (!savedItem) {
    return;
  }
  if (items.value.some((item) => item.id === savedItem)) {
    selectedItemId.value = savedItem;
  } else if (selectedItemId.value && !items.value.some((item) => item.id === selectedItemId.value)) {
    selectedItemId.value = null;
  }
});


const layoutState = useAppLayout({
  uiSettings,
  showMain,
  filteredItems,
  selectedItemId,
});
const {
  listPanel,
  detailsPanel,
  listContainerEl,
  listWidth,
  isResizingDetails,
  startResizeDetails,
  onListScroll,
  visibleItems,
  totalListHeight,
  listOffset,
  moveSelection,
} = layoutState;

const LOAD_MORE_THRESHOLD_PX = 240;
const maybeLoadMore = () => {
  const container = listContainerEl.value;
  if (!container || listLoading.value || listLoadingMore.value || !hasMore.value) {
    return;
  }
  const remaining =
    container.scrollHeight - (container.scrollTop + container.clientHeight);
  if (remaining <= LOAD_MORE_THRESHOLD_PX) {
    void loadMoreItems();
  }
};
const maybeFillList = () => {
  const container = listContainerEl.value;
  if (!container || listLoading.value || listLoadingMore.value || !hasMore.value) {
    return;
  }
  if (container.scrollHeight <= container.clientHeight + LOAD_MORE_THRESHOLD_PX) {
    void loadMoreItems();
  }
};
const handleListScroll = () => {
  onListScroll();
  maybeLoadMore();
};

const hasSelectedItem = computed(() => !!selectedItem.value);

const openExternal = async (url: string) => {
  if (!url) {
    return;
  }
  try {
    await openShell(url);
  } catch {
    globalThis.open?.(url, "_blank");
  }
};

watch([items, hasMore, listContainerEl], async () => {
  await nextTick();
  maybeFillList();
});

const itemActions = useAppItemActions({
  t,
  selectedStorageId,
  selectedVaultName,
  isSharedVault,
  selectedCategory,
  selectedItemId,
  selectedItem,
  items,
  detailSections,
  fetchHistoryPayload: itemDetailsState.fetchHistoryPayload,
  loadItemDetail: itemDetailsState.loadItemDetail,
  loadItems,
  runRemoteSync,
  scheduleRemoteSync,
  copyToClipboard,
  findPrimarySecret: itemDetailsState.findPrimarySecret,
  openConfirm,
  showToast,
  setError: (message) => {
    error.value = message;
  },
  isDeletedItem,
  localStorageId: LOCAL_STORAGE_ID,
});
const {
  copyField, copyEnv, copyJson, copyRaw, copyHistoryPassword, restoreHistoryVersion,
  copyPrimarySecret, openTrash, deleteItem, restoreItem, purgeItem, emptyTrash,
} = itemActions;

const paletteState = usePalette({
  t,
  filteredItems,
  hasSelectedItem,
  onSelectItem: (itemId) => {
    selectedItemId.value = itemId;
  },
  onLock: () => void lockSession(),
  onRevealToggle: itemDetailsState.revealToggle,
  onCopyPrimary: () => void copyPrimarySecret(),
  onOpenSettings: () => {
    openSettings();
  },
});
const { paletteOpen, paletteQuery, paletteIndex, paletteItems } = paletteState;
const openPalette = () => {
  paletteOpen.value = true;
};

const formatError = (err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  const normalized = message.toLowerCase();
  if (normalized.startsWith("server_time_skew:")) {
    const raw = normalized.replace("server_time_skew:", "").trim();
    const seconds = Number.parseInt(raw, 10);
    const minutes = Number.isFinite(seconds) ? Math.max(1, Math.round(seconds / 60)) : 0;
    identityAlertTitle.value = t("errors.time_sync_title");
    identityAlertMessage.value = t("errors.server_time_skew", { minutes });
    identityAlertOpen.value = true;
    return identityAlertMessage.value;
  }
  if (normalized === "server_identity_invalid") {
    identityAlertTitle.value = t("errors.security_title");
    identityAlertMessage.value = t("errors.server_identity_invalid");
    identityAlertOpen.value = true;
    return identityAlertMessage.value;
  }
  if (normalized === "server_identity_missing") {
    identityAlertTitle.value = t("errors.security_title");
    identityAlertMessage.value = t("errors.server_identity_missing");
    identityAlertOpen.value = true;
    return identityAlertMessage.value;
  }
  if (
    normalized.includes("error sending request") ||
    normalized.includes("connection refused") ||
    normalized.includes("dns error") ||
    normalized.includes("failed to lookup address") ||
    normalized.includes("invalid url")
  ) {
    return t("errors.server_unreachable");
  }
  return message;
};

const personalUnlock = useAppPersonalUnlock({
  t,
  selectedStorageId,
  storages,
  storagePersonalLocked,
  clearSyncErrors,
  refreshStatus,
  refreshAppStatus,
  runRemoteSync,
  openConfirm,
  showToast,
});
const {
  personalUnlockOpen,
  personalUnlockPassword,
  personalUnlockError,
  personalUnlockBusy,
  openPersonalUnlock,
  handleResetPersonal,
  unlockPersonalVaults,
  sessionExpiredStorage,
} = personalUnlock;

const authFlow = useAppAuthFlow({
  t,
  uiSettings,
  appStatus,
  unlocked,
  selectedStorageId,
  localStorageId: LOCAL_STORAGE_ID,
  showSessionExpiredBanner,
  sessionExpiredStorage,
  syncError,
  refreshStatus,
  refreshAppStatus,
  loadStorages,
  runRemoteSync,
  runBootstrap,
  clearSyncErrors,
  openConfirm,
  showToast,
  openExternal,
  formatError,
});
const {
  setupStep, setupFlow, setupOpen, setupPassword, setupConfirm, setupError, setupBusy,
  connectServerUrl, connectLoginId, connectVerification, connectStatus, connectError,
  connectOldFp, connectNewFp, connectBusy, authMethodOpen, availableMethods,
  passwordLoginOpen, passwordLoginMode, passwordLoginBusy, passwordLoginError, normalizeServerUrl,
  startLocalSetup, startConnect, backToWelcome, createMasterPassword,
  showAuthMethodSelection, trustFingerprint, handleBannerSignIn,
  handleSelectOidc, handleSelectPassword, handlePasswordAuth,
} = authFlow;

const computedState = useAppComputed({
  settings,
  status,
  appStatus,
  setupOpen,
  items,
  selectedItemId,
  selectedItem,
  detailSections,
  getSchemaFieldDefs,
});
const {
  rememberEnabled, showUnlock, showSetupModal,
  selectedItemDeleted, selectedItemConflict, hasPasswordField,
} = computedState;

watch(
  () => [showUnlock.value, rememberEnabled.value, keystoreStatus.value] as const,
  ([isOpen, remember, statusValue]) => {
    if (isOpen && remember && !statusValue) {
      void refreshKeystoreStatus();
    }
  },
  { immediate: true },
);

const storageActions = useAppStorageActions({
  t,
  uiSettings,
  storages,
  localStorageRef,
  hasLocalVaults,
  selectedStorageId,
  selectedVaultId,
  localStorageId: LOCAL_STORAGE_ID,
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
  openCreateModal: createState.openCreateModal,
  setupOpen,
  setupStep,
  settingsOpen,
  settingsInitialTab,
  startConnect,
  showAuthMethodSelection,
  connectServerUrl,
  setError: (message) => {
    error.value = message;
  },
  showToast,
});
const {
  storageDropdownOpen, vaultDropdownOpen, deleteStorageOpen, deleteStorageInfo, deleteStorageBusy,
  toggleStorageDropdown, closeStorageDropdown, switchStorage, openAddStorageWizard,
  openStorageSettings, handleStorageReveal, handleStorageDisconnect, handleStorageDelete,
  handleStorageGetInfo, handleSignOut, handleRemoveServer, handleSignIn, handleClearData,
  handleFactoryReset, handleSyncNow, openCreateVault, openCreateLocalVault, toggleVaultDropdown,
  closeVaultDropdown, switchVault, confirmDeleteStorage, confirmDisconnectStorage,
} = storageActions;

const { resolveConflict } = useConflictActions({
  selectedItem,
  selectedStorageId,
  runRemoteSync,
  loadItems,
  t,
  showToast,
  formatError,
});

const selectItemById = (itemId: string) => {
  selectedItemId.value = itemId;
};

const settingsActions = useAppSettingsActions({
  t,
  settings,
  keystoreStatus,
  locale,
  showToast,
  runRemoteSync,
  syncError,
  setError: (message) => {
    error.value = message;
  },
});
const { updateSettings, testBiometrics, rebindBiometrics, exportPlainBackup, importPlainBackup } = settingsActions;

const timeTravelMaxIndex = computed(() =>
  Math.max(0, itemDetailsState.historyEntries.value.length - 1),
);


const { lastActivityAt, altRevealAll } = useAppEventHandlers({
  t,
  settings,
  unlocked,
  storageDropdownOpen,
  vaultDropdownOpen,
  paletteOpen,
  paletteIndex,
  paletteItems,
  createModalOpen: createState.createModalOpen,
  selectedItem,
  copyPrimarySecret,
  revealToggle: itemDetailsState.revealToggle,
  openCreateModal: createState.openCreateModal,
  detailsPanel,
  moveSelection,
  selectedItemId,
  loadItemDetail: itemDetailsState.loadItemDetail,
  settingsOpen,
  openSettings,
  lockSession,
  scheduleRemoteSync,
  selectedStorageId,
  clearClipboardNow,
  runRemoteSync,
  timeTravelActive: itemDetailsState.timeTravelActive,
  timeTravelIndex: itemDetailsState.timeTravelIndex,
  timeTravelMaxIndex,
  setTimeTravelIndex: itemDetailsState.setTimeTravelIndex,
  showToast,
});

const { scheduleTrashPurge, clearTrashPurgeTimer } = useAppTrashPurge({
  settings,
  unlocked,
  initialized,
  storages,
  loadItems,
});

useAppWatchers({
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
  loadItemDetail: itemDetailsState.loadItemDetail,
  revealedFields,
  itemDetailError,
  error,
  clearToast,
  fatalError,
  settings,
  idleTimer,
  lastActivityAt,
  clearRevealTimer: itemDetailsState.clearRevealTimer,
  lockSession,
  storages,
  scheduleTrashPurge,
});

const selectionState = {
  selectedStorageId,
  selectedVaultId,
  selectedItemId,
  selectedCategory,
  categoryCounts,
  categories,
  selectCategory,
  filteredItems,
  query,
  selectItemById,
  selectedVaultName,
  isSharedVault,
  currentStorage,
  vaultContextLabel,
};

const layoutBindings = {
  ...layoutState,
  onListScroll: handleListScroll,
};

const { shellBindings, modalBindings } = useAppBindings({
  core: {
    t,
    uiSettings,
    logoUrl,
    appStatus,
    runBootstrap,
    runRemoteSync,
    openExternal,
    lastSyncTime,
    copyToClipboard,
    password,
    error,
    identityAlertOpen,
    identityAlertTitle,
    identityAlertMessage,
    settingsOpen,
    settingsInitialTab,
    openSettings,
    listLoading,
    listError,
    itemDetailError,
    settings,
    keystoreStatus,
    autoUnlockError,
    locale,
    fatalError,
    doUnlock,
    totalItemsCount,
  },
  computedState,
  statusBanners,
  selectionState,
  storageState,
  vaultState,
  foldersState,
  createState,
  detailState: itemDetailsState,
  layoutState: layoutBindings,
  itemActions,
  storageActions,
  settingsActions,
  authFlow,
  personalUnlock,
  paletteState,
  sessionState,
  toastState,
  confirmState,
  misc: {
    resolveConflict,
    altRevealAll,
    openPalette,
    loadItems,
  },
});

onBeforeUnmount(() => {
  if (idleTimer.value) {
    window.clearInterval(idleTimer.value);
  }
  clearTrashPurgeTimer();
  clearToastTimer();
  clearClipboardTimer();
  stopAutoSync();
});
</script>

<template>
  <main class="h-full">
    <div
      v-if="altRevealAll"
      class="fixed bottom-4 right-4 z-50 rounded-full border border-[var(--border-color)] bg-[var(--bg-secondary)]/90 px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] shadow-lg"
    >
      Alt reveal
    </div>
    <KeepAlive>
      <AppShell
        v-if="showMain"
        v-bind="shellBindings"
      />
    </KeepAlive>
    <AppModals v-bind="modalBindings" />
  </main>
</template>
