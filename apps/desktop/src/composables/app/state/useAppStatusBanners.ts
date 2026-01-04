import { computed } from "vue";
import type { ComputedRef, Ref } from "vue";

type AppStatusBannersOptions = {
  selectedStorageId: Ref<string>;
  storageSyncErrors: Ref<Map<string, string>>;
  storagePersonalLocked: Ref<Map<string, boolean>>;
  localStorageId: string;
};

export function useAppStatusBanners({
  selectedStorageId,
  storageSyncErrors,
  storagePersonalLocked,
  localStorageId,
}: AppStatusBannersOptions) {
  const showOfflineBanner = computed(() => {
    if (selectedStorageId.value === localStorageId) return false;
    const error = storageSyncErrors.value.get(selectedStorageId.value);
    return !!(
      error &&
      (error.includes("error sending request") || error.includes("server_unavailable"))
    );
  });

  const showSessionExpiredBanner = computed(() => {
    if (selectedStorageId.value === localStorageId) return false;
    const error = storageSyncErrors.value.get(selectedStorageId.value);
    if (!error) return false;
    const normalized = error.toLowerCase();
    return normalized.includes("session_expired") || normalized.includes("session expired");
  });

  const showPersonalLockedBanner = computed(() => {
    if (selectedStorageId.value === localStorageId) return false;
    return storagePersonalLocked.value.get(selectedStorageId.value) ?? false;
  });

  const syncErrorMessage = computed(() => {
    if (selectedStorageId.value === localStorageId) return "";
    const error = storageSyncErrors.value.get(selectedStorageId.value);
    if (!error) return "";
    if (showOfflineBanner.value || showSessionExpiredBanner.value) return "";
    return error;
  });

  const showSyncErrorBanner = computed(() => !!syncErrorMessage.value);

  return {
    showOfflineBanner,
    showSessionExpiredBanner,
    showPersonalLockedBanner,
    syncErrorMessage,
    showSyncErrorBanner,
  };
}
