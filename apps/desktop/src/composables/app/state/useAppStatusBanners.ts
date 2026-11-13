import { computed } from "vue";
import type { ComputedRef, Ref } from "vue";

type AppStatusBannersOptions = {
  selectedStorageId: Ref<string>;
  storageSyncErrors: Ref<Map<string, string>>;
  storagePersonalLocked: Ref<Map<string, boolean>>;
  isOffline: Ref<boolean>;
  pendingChangesByStorage: Ref<Map<string, number>>;

};

export function useAppStatusBanners({
  selectedStorageId,
  storageSyncErrors,
  storagePersonalLocked,
  isOffline,
  pendingChangesByStorage,

}: AppStatusBannersOptions) {
  const showOfflineBanner = computed(() => {
    return isOffline.value;
  });

  const showSessionExpiredBanner = computed(() => {
    const error = storageSyncErrors.value.get(selectedStorageId.value);
    if (!error) return false;
    const normalized = error.toLowerCase();
    return normalized.includes("session_expired") || normalized.includes("session expired");
  });

  const showPersonalLockedBanner = computed(() => {
    return storagePersonalLocked.value.get(selectedStorageId.value) ?? false;
  });

  const syncErrorMessage = computed(() => {
    const error = storageSyncErrors.value.get(selectedStorageId.value);
    if (!error) return "";
    if (showOfflineBanner.value || showSessionExpiredBanner.value) return "";
    return error;
  });

  const showSyncErrorBanner = computed(() => !!syncErrorMessage.value);

  const pendingChangesCount = computed(() => {
    return pendingChangesByStorage.value.get(selectedStorageId.value) ?? 0;
  });

  return {
    showOfflineBanner,
    showSessionExpiredBanner,
    showPersonalLockedBanner,
    syncErrorMessage,
    showSyncErrorBanner,
    pendingChangesCount,
  };
}
