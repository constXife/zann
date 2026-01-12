import { ref, computed, onMounted, onUnmounted } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, StorageSummary, StorageInfo } from "../types";
import { StorageKind } from "../constants/enums";

type Translator = (key: string, params?: Record<string, string | number>) => string;

type UseStoragesOptions = {
  selectedStorageId: Ref<string>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
  t: Translator;
  onFatalError: (message: string) => void;
  onReloadVaults: () => Promise<void>;
  onReloadItems: () => Promise<void>;
  localStorageId: string;
  onSessionExpired?: (serverUrl: string | null) => Promise<void> | void;
  localStorageVisible?: Ref<boolean>;
};

type SyncStatus = "idle" | "syncing" | "synced" | "error";

class SyncError extends Error {
  kind: string;

  constructor(kind: string, message: string) {
    super(message);
    this.kind = kind;
  }
}

export const useStorages = (options: UseStoragesOptions) => {
  const storages = ref<StorageSummary[]>([]);
  const storageSyncStatus = ref<Map<string, SyncStatus>>(new Map());
  const storageSyncErrors = ref<Map<string, string>>(new Map());
  const storagePersonalLocked = ref<Map<string, boolean>>(new Map());
  const isNetworkOnline = ref(typeof navigator === "undefined" ? true : navigator.onLine);
  const isServerReachable = ref(true);
  const isOffline = computed(() => !isNetworkOnline.value || !isServerReachable.value);
  const syncBusy = ref(false);
  const syncError = ref("");
  const autoSyncIntervalMs = 60000;
  const syncDebounceMs = 1500;
  const syncBackoffStepsMs = [2000, 5000, 10000, 30000, 60000];
  let autoSyncTimer: number | null = null;
  let debounceTimer: number | null = null;
  let backoffIndex = 0;
  let pendingSyncRequested = false;
  let pendingSyncStorageId: string | null = null;
  let queuedSyncRequested = false;
  let queuedSyncStorageId: string | null = null;

  // Remote-first: серверы показываются первыми
  const remoteStorages = computed(() =>
    storages.value.filter((s) => s.kind === StorageKind.Remote),
  );

  // Local storage (всегда существует в БД, но может быть скрыт в UI)
  const localStorage = computed(() =>
    storages.value.find((s) => s.kind === StorageKind.LocalOnly),
  );

  // Флаг для проверки наличия local vaults (устанавливается извне через checkLocalVaults)
  const hasLocalVaults = ref(false);

  // Показывать секцию "On this device" только если есть local vaults
  const showLocalSection = computed(
    () => hasLocalVaults.value && (options.localStorageVisible?.value ?? true),
  );

  const isNetworkErrorMessage = (message: string) => {
    const text = message.toLowerCase();
    return (
      text.includes("error sending request") ||
      text.includes("failed to fetch") ||
      text.includes("network") ||
      text.includes("connection refused") ||
      text.includes("connection") ||
      text.includes("dns") ||
      text.includes("timed out") ||
      text.includes("timeout")
    );
  };

  const resolveIdentityMessage = (message: string) => {
    if (message === "server_identity_invalid") {
      return options.t("errors.server_identity_invalid");
    }
    if (message === "server_identity_missing") {
      return options.t("errors.server_identity_missing");
    }
    if (message.startsWith("server_time_skew:")) {
      const seconds = Number(message.split(":")[1] ?? 0);
      const minutes = Math.max(1, Math.round(seconds / 60));
      return options.t("errors.server_time_skew", { minutes });
    }
    return null;
  };

  const resolveSyncErrorMessage = (kind: string, message?: string | null) => {
    const text = message ?? "";
    const identityMessage = resolveIdentityMessage(text);
    if (identityMessage) {
      return identityMessage;
    }
    if (kind === "session_expired") {
      return options.t("errors.session_expired");
    }
    if (kind === "vault_key_mismatch") {
      return options.t("errors.vault_key_mismatch");
    }
    if (kind === "vault_list_failed") {
      return options.t("errors.vault_list_failed");
    }
    if (kind === "system_info_failed" && isNetworkErrorMessage(text)) {
      return options.t("errors.server_unreachable");
    }
    if (kind === "server_unreachable") {
      return options.t("errors.server_unreachable");
    }
    return text || options.t("errors.remote_error");
  };

  const retryableErrorKinds = new Set([
    "vault_list_failed",
    "vault_get_failed",
    "sync_push_failed",
    "vault_key_update_failed",
  ]);

  const queueSync = (storageId: string | null) => {
    queuedSyncRequested = true;
    queuedSyncStorageId = storageId;
  };

  const flushQueuedSync = () => {
    if (!queuedSyncRequested) {
      return;
    }
    queuedSyncRequested = false;
    const nextStorage = queuedSyncStorageId;
    queuedSyncStorageId = null;
    void runRemoteSync(nextStorage);
  };

  const loadStorages = async () => {
    if (!options.initialized.value || !options.unlocked.value) {
      storages.value = [];
      return;
    }
    try {
      const response = await invoke<ApiResponse<StorageSummary[]>>("storages_list");
      if (!response.ok || !response.data) {
        const message = response.error?.message;
        const key = response.error?.kind ?? "generic";
        throw new Error(message ?? options.t(`errors.${key}`));
      }
      storages.value = response.data;
      const existing = storages.value.find((entry) => entry.id === options.selectedStorageId.value);
      const remoteList = storages.value.filter(
        (entry) => entry.kind === StorageKind.Remote,
      );

      // Remote-first: если выбран local, но есть remote — переключиться на remote
      if (existing?.kind === StorageKind.LocalOnly && remoteList.length > 0) {
        options.selectedStorageId.value = remoteList[0].id;
      } else if (!existing) {
        // Fallback: первый remote, или первый storage, или local
        const fallback = remoteList[0] ?? storages.value[0];
        if (fallback) {
          options.selectedStorageId.value = fallback.id;
        } else {
          options.selectedStorageId.value = options.localStorageId;
        }
      }
    } catch (err) {
      options.onFatalError(String(err));
    }
  };

  const runRemoteSync = async (storageId: string | null = null): Promise<boolean> => {
    if (syncBusy.value) {
      pendingSyncRequested = true;
      pendingSyncStorageId = storageId;
      return false;
    }
    syncError.value = "";
    if (!options.unlocked.value) {
      return false;
    }

    const targetStorages = storageId
      ? storages.value.filter(
          (s) => s.id === storageId && s.kind === StorageKind.Remote,
        )
      : storages.value.filter((s) => s.kind === StorageKind.Remote);

    if (targetStorages.length === 0) {
      return false;
    }

    if (isOffline.value) {
      const offlineMessage = options.t("errors.server_unreachable");
      for (const storage of targetStorages) {
        storageSyncStatus.value.set(storage.id, "error");
        storageSyncErrors.value.set(storage.id, offlineMessage);
      }
      queueSync(storageId);
      return false;
    }

    for (const storage of targetStorages) {
      storageSyncStatus.value.set(storage.id, "syncing");
      storageSyncErrors.value.delete(storage.id);
      storagePersonalLocked.value.set(storage.id, false);
    }

    syncBusy.value = true;
    let success = false;
    let retryableFailure = false;
    try {
      const response = await invoke<ApiResponse<{ locked_vaults?: string[] }>>("remote_sync", {
        storageId: storageId ?? null,
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        const message = resolveSyncErrorMessage(key, response.error?.message);
        throw new SyncError(key, message);
      }
      const lockedVaults = response.data?.locked_vaults ?? [];
      if (lockedVaults.length > 0) {
        for (const storage of targetStorages) {
          storagePersonalLocked.value.set(storage.id, true);
        }
      }

      for (const storage of targetStorages) {
        storageSyncStatus.value.set(storage.id, "synced");
      }
      isServerReachable.value = true;

      await loadStorages();
      await options.onReloadVaults();
      await options.onReloadItems();
      success = true;
    } catch (err) {
      let errorMsg = String(err);
      let errorKind = "unknown";
      let isOfflineError = false;

      if (err instanceof SyncError) {
        errorKind = err.kind;
        errorMsg = err.message;
        if (errorKind === "system_info_failed" && isNetworkErrorMessage(errorMsg)) {
          isOfflineError = true;
        }
      } else if (isNetworkErrorMessage(errorMsg)) {
        errorKind = "server_unreachable";
        errorMsg = options.t("errors.server_unreachable");
        isOfflineError = true;
      }

      if (
        errorKind === "session_expired" ||
        errorMsg.includes("session_expired") ||
        errorMsg.includes("token not set")
      ) {
        const storage = targetStorages[0];
        await options.onSessionExpired?.(storage?.server_url ?? null);
        for (const storage of targetStorages) {
          storageSyncStatus.value.set(storage.id, "error");
          storageSyncErrors.value.set(storage.id, options.t("errors.session_expired"));
        }
      } else {
        syncError.value = errorMsg;
        for (const storage of targetStorages) {
          storageSyncStatus.value.set(storage.id, "error");
          storageSyncErrors.value.set(storage.id, errorMsg);
        }
      }
      if (isOfflineError) {
        isServerReachable.value = false;
        queueSync(storageId);
      }
      retryableFailure = isOfflineError || retryableErrorKinds.has(errorKind);
    } finally {
      syncBusy.value = false;
      if (success) {
        backoffIndex = 0;
      } else if (retryableFailure) {
        backoffIndex = Math.min(backoffIndex + 1, syncBackoffStepsMs.length);
      } else {
        backoffIndex = 0;
      }
      if (pendingSyncRequested) {
        pendingSyncRequested = false;
        const nextStorage = pendingSyncStorageId;
        pendingSyncStorageId = null;
        void runRemoteSync(nextStorage);
      }
    }
    return success;
  };

  const scheduleRemoteSync = (storageId: string | null = null) => {
    if (!options.unlocked.value) {
      return;
    }
    if (debounceTimer) {
      window.clearTimeout(debounceTimer);
    }
    debounceTimer = window.setTimeout(() => {
      debounceTimer = null;
      void runRemoteSync(storageId);
    }, syncDebounceMs);
  };

  const nextAutoSyncDelay = () => {
    if (backoffIndex === 0) {
      return autoSyncIntervalMs;
    }
    const idx = Math.min(backoffIndex - 1, syncBackoffStepsMs.length - 1);
    return syncBackoffStepsMs[idx];
  };

  const scheduleNextAutoSync = () => {
    if (autoSyncTimer) {
      window.clearTimeout(autoSyncTimer);
    }
    autoSyncTimer = window.setTimeout(async () => {
      autoSyncTimer = null;
      await runRemoteSync();
      scheduleNextAutoSync();
    }, nextAutoSyncDelay());
  };

  const startAutoSync = () => {
    if (autoSyncTimer) {
      return;
    }
    scheduleNextAutoSync();
  };

  const stopAutoSync = () => {
    if (autoSyncTimer) {
      window.clearTimeout(autoSyncTimer);
      autoSyncTimer = null;
    }
    if (debounceTimer) {
      window.clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    backoffIndex = 0;
    pendingSyncRequested = false;
    pendingSyncStorageId = null;
    queuedSyncRequested = false;
    queuedSyncStorageId = null;
  };

  const clearSyncErrors = (storageId?: string | null) => {
    if (storageId) {
      storageSyncErrors.value.delete(storageId);
      storageSyncStatus.value.delete(storageId);
      return;
    }
    storageSyncErrors.value.clear();
    storageSyncStatus.value.clear();
  };

  const getSyncStatus = (storageId: string): SyncStatus => {
    return storageSyncStatus.value.get(storageId) ?? "idle";
  };

  const getStorageInfo = async (storageId: string): Promise<StorageInfo | null> => {
    try {
      const response = await invoke<ApiResponse<StorageInfo>>("storage_info", { storageId });
      if (!response.ok || !response.data) {
        return null;
      }
      return response.data;
    } catch {
      return null;
    }
  };

  const deleteStorage = async (storageId: string, moveToTrash = false): Promise<boolean> => {
    try {
      const response = await invoke<ApiResponse<void>>("storage_delete", { storageId, moveToTrash });
      if (!response.ok) {
        const message = response.error?.message ?? "Failed to delete storage";
        throw new Error(message);
      }
      await loadStorages();
      await options.onReloadVaults();
      await options.onReloadItems();
      return true;
    } catch (err) {
      options.onFatalError(String(err));
      return false;
    }
  };

  const disconnectStorage = async (storageId: string): Promise<boolean> => {
    try {
      const response = await invoke<ApiResponse<void>>("storage_disconnect", { storageId });
      if (!response.ok) {
        const message = response.error?.message ?? "Failed to disconnect storage";
        throw new Error(message);
      }
      await loadStorages();
      await options.onReloadVaults();
      await options.onReloadItems();
      return true;
    } catch (err) {
      options.onFatalError(String(err));
      return false;
    }
  };

  const revealStorage = async (storageId: string): Promise<boolean> => {
    try {
      const response = await invoke<ApiResponse<void>>("storage_reveal", { storageId });
      if (!response.ok) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  // Проверить наличие vaults в local storage
  const checkLocalVaults = async (): Promise<void> => {
    const localStore = localStorage.value;
    if (!localStore) {
      hasLocalVaults.value = false;
      return;
    }
    try {
      const response = await invoke<ApiResponse<{ id: string }[]>>("vault_list", {
        req: { storage_id: localStore.id },
      });
      hasLocalVaults.value = response.ok && (response.data?.length ?? 0) > 0;
    } catch {
      hasLocalVaults.value = false;
    }
  };

  const handleOnline = () => {
    isNetworkOnline.value = true;
    isServerReachable.value = true;
    flushQueuedSync();
  };

  const handleOffline = () => {
    isNetworkOnline.value = false;
  };

  onMounted(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
  });

  onUnmounted(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.removeEventListener("online", handleOnline);
    window.removeEventListener("offline", handleOffline);
  });

  return {
    storages,
    remoteStorages,
    localStorage,
    hasLocalVaults,
    showLocalSection,
    storageSyncStatus,
    storageSyncErrors,
    storagePersonalLocked,
    isOffline,
    syncBusy,
    syncError,
    loadStorages,
    checkLocalVaults,
    runRemoteSync,
    scheduleRemoteSync,
    startAutoSync,
    stopAutoSync,
    clearSyncErrors,
    getSyncStatus,
    getStorageInfo,
    deleteStorage,
    disconnectStorage,
    revealStorage,
  };
};
