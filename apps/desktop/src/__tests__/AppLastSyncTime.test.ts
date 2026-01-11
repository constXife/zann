import { render, cleanup } from "@testing-library/vue";
import { afterEach, describe, expect, it, vi } from "vitest";
import { computed, ref } from "vue";

const LOCAL_STORAGE_ID = "00000000-0000-0000-0000-000000000000";
const mockGetStorageInfo = vi.fn();
const mockRunRemoteSyncRaw = vi.fn();
let capturedBindingsOptions: Record<string, unknown> | null = null;

vi.mock("vue-i18n", () => ({
  useI18n: () => ({
    t: (key: string) => key,
    locale: ref("en"),
  }),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockResolvedValue({ ok: true, data: null }),
}));

vi.mock("@tauri-apps/plugin-shell", () => ({
  open: vi.fn(),
}));

vi.mock("../composables/useUiSettings", () => ({
  useUiSettings: () => ({
    settings: ref({
      lastSelectedStorageId: "remote-1",
      lastSelectedVaultByStorage: {},
      showLocalStorage: true,
      lastCreateItemType: "login",
    }),
  }),
}));

vi.mock("../composables/useBootstrap", () => ({
  useBootstrap: () => ({
    status: ref({ unlocked: true }),
    appStatus: ref({ initialized: true }),
    settings: ref({
      remember_unlock: false,
      auto_unlock: false,
      language: "en",
      auto_lock_minutes: 10,
      lock_on_focus_loss: false,
      lock_on_hidden: false,
      clipboard_clear_seconds: 30,
      clipboard_clear_on_lock: false,
      clipboard_clear_on_exit: false,
      clipboard_clear_if_unchanged: false,
      auto_hide_reveal_seconds: 20,
      require_os_auth: true,
      biometry_dwk_backup: null,
      trash_auto_purge_days: 90,
      close_to_tray: true,
      close_to_tray_notice_shown: false,
    }),
    autoUnlockError: ref(""),
    keystoreStatus: ref(null),
    refreshStatus: vi.fn(),
    refreshAppStatus: vi.fn(),
    bootstrap: vi.fn().mockResolvedValue(undefined),
  }),
}));

vi.mock("../composables/app/state/useAppToast", () => ({
  useAppToast: () => ({
    toast: ref(""),
    toastActionLabel: ref(""),
    toastAction: ref(null),
    clearToast: vi.fn(),
    showToast: vi.fn(),
    clearToastTimer: vi.fn(),
  }),
}));

vi.mock("../composables/app/state/useAppConfirm", () => ({
  useAppConfirm: () => ({
    confirmOpen: ref(false),
    confirmTitle: ref(""),
    confirmMessage: ref(""),
    confirmConfirmLabel: ref(""),
    confirmCancelLabel: ref(""),
    confirmBusy: ref(false),
    confirmInputExpected: ref(""),
    confirmInputLabel: ref(""),
    confirmInputPlaceholder: ref(""),
    openConfirm: vi.fn(),
    handleConfirm: vi.fn(),
  }),
}));

vi.mock("../composables/useClipboard", () => ({
  useClipboard: () => ({
    copyToClipboard: vi.fn(),
    clearClipboardNow: vi.fn(),
    clearClipboardTimer: vi.fn(),
  }),
}));

vi.mock("../composables/useVaults", () => ({
  useVaults: () => ({
    vaults: ref([]),
    personalVaults: ref([]),
    sharedVaults: ref([]),
    loadVaults: vi.fn(),
  }),
}));

vi.mock("../composables/useItems", () => ({
  useItems: () => ({
    items: ref([]),
    loadItems: vi.fn(),
  }),
}));

vi.mock("../composables/useStorages", () => ({
  useStorages: () => ({
    storages: ref([
      {
        id: "remote-1",
        name: "Remote",
        kind: "remote",
        personal_vaults_enabled: true,
      },
    ]),
    remoteStorages: ref([
      {
        id: "remote-1",
        name: "Remote",
        kind: "remote",
        personal_vaults_enabled: true,
      },
    ]),
    localStorage: ref(null),
    hasLocalVaults: ref(false),
    showLocalSection: ref(false),
    storageSyncErrors: ref(new Map()),
    storagePersonalLocked: ref(new Map()),
    syncBusy: ref(false),
    syncError: ref(""),
    loadStorages: vi.fn(),
    checkLocalVaults: vi.fn(),
    runRemoteSync: mockRunRemoteSyncRaw,
    scheduleRemoteSync: vi.fn(),
    startAutoSync: vi.fn(),
    stopAutoSync: vi.fn(),
    clearSyncErrors: vi.fn(),
    getSyncStatus: vi.fn().mockReturnValue("idle"),
    getStorageInfo: mockGetStorageInfo,
    deleteStorage: vi.fn(),
    disconnectStorage: vi.fn(),
    revealStorage: vi.fn(),
  }),
}));

vi.mock("../composables/app/state/useAppStatusBanners", () => ({
  useAppStatusBanners: () => ({
    showOfflineBanner: computed(() => false),
    showSessionExpiredBanner: computed(() => false),
    showPersonalLockedBanner: computed(() => false),
    syncErrorMessage: computed(() => ""),
    showSyncErrorBanner: computed(() => false),
  }),
}));

vi.mock("../composables/app/state/useAppVaultContext", () => ({
  useAppVaultContext: () => ({
    currentStorage: ref({
      id: "remote-1",
      name: "Remote",
      kind: "remote",
      personal_vaults_enabled: true,
    }),
    selectedVaultName: ref(""),
    isSharedVault: ref(false),
    vaultContextLabel: ref(""),
  }),
}));

vi.mock("../composables/app/state/useAppComputed", () => ({
  useAppComputed: () => ({
    rememberEnabled: ref(false),
    showUnlock: ref(false),
    showSetupModal: ref(false),
    selectedItemDeleted: ref(false),
    selectedItemConflict: ref(false),
    hasPasswordField: ref(false),
  }),
}));

vi.mock("../composables/useItemDetails", () => ({
  useItemDetails: () => ({
    selectedItem: ref(null),
    detailSections: ref([]),
    revealedFields: ref(new Set()),
    clearRevealTimer: vi.fn(),
    historyEntries: ref([]),
    timeTravelActive: ref(false),
    timeTravelIndex: ref(0),
    setTimeTravelIndex: vi.fn(),
    loadItemDetail: vi.fn(),
    fetchHistoryPayload: vi.fn(),
    findPrimarySecret: vi.fn(),
    revealToggle: vi.fn(),
    addOptimisticHistory: vi.fn(),
    removeOptimisticHistory: vi.fn(),
  }),
}));

vi.mock("../composables/useConflictActions", () => ({
  useConflictActions: () => ({
    resolveConflict: vi.fn(),
  }),
}));

vi.mock("../composables/useFolders", () => ({
  useFolders: () => ({
    folderTree: ref([]),
    expandedFolders: ref(new Set()),
    selectedFolder: ref(null),
    toggleFolder: vi.fn(),
    openFolderMenu: vi.fn(),
    selectFolder: vi.fn(),
  }),
}));

vi.mock("../composables/useCreateModal", () => ({
  useCreateModal: () => ({
    createModalOpen: ref(false),
    openCreateModal: vi.fn(),
    closeCreateModal: vi.fn(),
    createItemFolder: vi.fn(),
  }),
}));

vi.mock("../composables/usePalette", () => ({
  usePalette: () => ({
    paletteOpen: ref(false),
    paletteIndex: ref(0),
    paletteItems: ref([]),
  }),
}));

vi.mock("../composables/useSession", () => ({
  useSession: () => ({
    unlockBusy: ref(false),
    unlock: vi.fn(),
    unlockWithBiometrics: vi.fn(),
    lockSession: vi.fn(),
  }),
}));

vi.mock("../composables/app/state/useAppLayout", () => ({
  useAppLayout: () => ({
    listPanel: ref(null),
    detailsPanel: ref(null),
    listWidth: ref(280),
    isResizingDetails: ref(false),
    startResizeDetails: vi.fn(),
    onListScroll: vi.fn(),
    visibleItems: ref([]),
    totalListHeight: ref(0),
    listOffset: ref(0),
    moveSelection: vi.fn(),
  }),
}));

vi.mock("../composables/app/state/useAppItemFilters", () => ({
  useAppItemFilters: () => ({
    query: ref(""),
    categoryCounts: ref({}),
    categories: ref([]),
    selectCategory: vi.fn(),
    filteredItems: ref([]),
    filteredItemCount: ref(0),
    filteredCategories: ref([]),
    selectedCategory: ref(null),
    selectedFolder: ref(null),
    openFolderMenu: vi.fn(),
    filteredFolderTree: ref([]),
    toggleFolder: vi.fn(),
    expandedFolders: ref(new Set()),
    itemsWithoutFolder: ref(0),
    isDeletedItem: vi.fn().mockReturnValue(false),
  }),
}));

vi.mock("../composables/app/actions/useAppItemActions", () => ({
  useAppItemActions: () => ({
    selectedItem: ref(null),
    loadItemDetail: vi.fn(),
    handleSelectItem: vi.fn(),
    getSelectedItemId: vi.fn().mockReturnValue(null),
    toggleFieldReveal: vi.fn(),
    copyPrimarySecret: vi.fn(),
    revealToggle: vi.fn(),
    updateItem: vi.fn(),
    deleteItem: vi.fn(),
    restoreItem: vi.fn(),
  }),
}));

vi.mock("../composables/app/actions/useAppStorageActions", () => ({
  useAppStorageActions: () => ({
    storageDropdownOpen: ref(false),
    vaultDropdownOpen: ref(false),
    deleteStorageOpen: ref(false),
    deleteStorageInfo: ref(null),
    deleteStorageBusy: ref(false),
    toggleStorageDropdown: vi.fn(),
    closeStorageDropdown: vi.fn(),
    switchStorage: vi.fn(),
    openAddStorageWizard: vi.fn(),
    openStorageSettings: vi.fn(),
    handleStorageReveal: vi.fn(),
    handleStorageDisconnect: vi.fn(),
    handleStorageDelete: vi.fn(),
    handleStorageGetInfo: vi.fn(),
    handleSignOut: vi.fn(),
    handleRemoveServer: vi.fn(),
    handleSignIn: vi.fn(),
    handleClearData: vi.fn(),
    handleFactoryReset: vi.fn(),
    handleSyncNow: vi.fn(),
    openCreateVault: vi.fn(),
    openCreateLocalVault: vi.fn(),
    toggleVaultDropdown: vi.fn(),
    closeVaultDropdown: vi.fn(),
    switchVault: vi.fn(),
    confirmDeleteStorage: vi.fn(),
    confirmDisconnectStorage: vi.fn(),
  }),
}));

vi.mock("../composables/app/actions/useAppSettingsActions", () => ({
  useAppSettingsActions: () => ({
    updateSettings: vi.fn(),
    testBiometrics: vi.fn(),
    rebindBiometrics: vi.fn(),
  }),
}));

vi.mock("../composables/app/actions/useAppEventHandlers", () => ({
  useAppEventHandlers: () => ({
    lastActivityAt: ref(Date.now()),
    altRevealAll: ref(false),
  }),
}));

vi.mock("../composables/app/actions/useAppTrashPurge", () => ({
  useAppTrashPurge: () => ({
    scheduleTrashPurge: vi.fn(),
    clearTrashPurgeTimer: vi.fn(),
  }),
}));

vi.mock("../composables/app/actions/useAppWatchers", () => ({
  useAppWatchers: vi.fn(),
}));

vi.mock("../composables/app/actions/useAppPersonalUnlock", () => ({
  useAppPersonalUnlock: () => ({
    personalUnlockOpen: ref(false),
    personalUnlockPassword: ref(""),
    personalUnlockError: ref(""),
    personalUnlockBusy: ref(false),
    openPersonalUnlock: vi.fn(),
    handleResetPersonal: vi.fn(),
    unlockPersonalVaults: vi.fn(),
    sessionExpiredStorage: ref(null),
  }),
}));

vi.mock("../composables/app/actions/useAppAuthFlow", () => ({
  useAppAuthFlow: () => ({
    setupStep: ref(""),
    setupFlow: ref(""),
    setupOpen: ref(false),
    setupPassword: ref(""),
    setupConfirm: ref(""),
    setupError: ref(""),
    setupBusy: ref(false),
    connectServerUrl: ref(""),
    connectLoginId: ref(""),
    connectVerification: ref(""),
    connectStatus: ref(""),
    connectError: ref(""),
    connectOldFp: ref(""),
    connectNewFp: ref(""),
    connectBusy: ref(false),
    authMethodOpen: ref(false),
    availableMethods: ref([]),
    passwordLoginOpen: ref(false),
    passwordLoginBusy: ref(false),
    passwordLoginError: ref(""),
    normalizeServerUrl: vi.fn((value: string) => value),
    startLocalSetup: vi.fn(),
    startConnect: vi.fn(),
    backToWelcome: vi.fn(),
    createMasterPassword: vi.fn(),
    showAuthMethodSelection: vi.fn(),
    trustFingerprint: vi.fn(),
    handleBannerSignIn: vi.fn(),
    handleSelectOidc: vi.fn(),
    handleSelectPassword: vi.fn(),
    handlePasswordAuth: vi.fn(),
  }),
}));

vi.mock("../composables/app/actions/useAppBindings", () => ({
  useAppBindings: (options: Record<string, unknown>) => {
    capturedBindingsOptions = options;
    return {
      shellBindings: {},
      modalBindings: {},
    };
  },
}));

vi.mock("../components/AppShell.vue", () => ({
  default: {
    name: "AppShellStub",
    template: "<div />",
  },
}));

vi.mock("../components/AppModals.vue", () => ({
  default: {
    name: "AppModalsStub",
    template: "<div />",
  },
}));

const flushPromises = () => new Promise((resolve) => setTimeout(resolve, 0));

afterEach(() => {
  cleanup();
  capturedBindingsOptions = null;
  mockGetStorageInfo.mockReset();
  mockRunRemoteSyncRaw.mockReset();
});

describe("App last sync time", () => {
  it("refreshes lastSyncTime on mount and after sync", async () => {
    mockGetStorageInfo
      .mockResolvedValueOnce({ last_synced: "2024-01-01T00:00:00Z" })
      .mockResolvedValueOnce({ last_synced: "2024-02-01T00:00:00Z" });
    mockRunRemoteSyncRaw.mockResolvedValue(true);

    const App = (await import("../App.vue")).default;
    render(App);

    await flushPromises();
    const lastSyncTime = (capturedBindingsOptions?.lastSyncTime as { value: string | null });
    expect(lastSyncTime.value).toBe("2024-01-01T00:00:00Z");

    await (capturedBindingsOptions?.runRemoteSync as () => Promise<boolean>)();
    await flushPromises();
    expect(lastSyncTime.value).toBe("2024-02-01T00:00:00Z");
  });
});
