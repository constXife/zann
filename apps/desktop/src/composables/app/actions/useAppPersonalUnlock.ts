import { computed, ref } from "vue";
import type { ComputedRef, Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { ApiResponse, StorageSummary } from "../../../types";

type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => Promise<void> | void;
};

type AppPersonalUnlockOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  selectedStorageId: Ref<string>;
  storages: Ref<StorageSummary[]>;
  storagePersonalLocked: Ref<Map<string, boolean>>;
  clearSyncErrors: (storageId: string) => void;
  refreshStatus: () => Promise<void>;
  refreshAppStatus: () => Promise<void>;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  openConfirm: (options: ConfirmOptions) => void;
  showToast: (message: string, options?: { duration?: number }) => void;
};

export function useAppPersonalUnlock({
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
}: AppPersonalUnlockOptions) {
  const personalUnlockOpen = ref(false);
  const personalUnlockPassword = ref("");
  const personalUnlockError = ref("");
  const personalUnlockBusy = ref(false);

  const openPersonalUnlock = () => {
    personalUnlockError.value = "";
    personalUnlockPassword.value = "";
    personalUnlockOpen.value = true;
  };

  const handleResetPersonal = () => {
    const storage = storages.value.find((s) => s.id === selectedStorageId.value);
    if (!storage || storage.kind !== "remote") {
      showToast(t("errors.generic"));
      return;
    }
    openConfirm({
      title: t("status.personalLockedResetTitle"),
      message: t("status.personalLockedResetDesc", {
        server: storage.server_name ?? storage.server_url ?? "",
      }),
      confirmLabel: t("status.personalLockedReset"),
      cancelLabel: t("common.cancel"),
      onConfirm: async () => {
        try {
          const response = await invoke<ApiResponse<null>>("vault_reset_personal", {
            storageId: storage.id,
          });
          if (!response.ok) {
            const key = response.error?.kind ?? "generic";
            const message = response.error?.message ?? t(`errors.${key}`);
            throw new Error(message);
          }
          storagePersonalLocked.value.set(storage.id, false);
          clearSyncErrors(storage.id);
          await runRemoteSync(storage.id);
          showToast(t("status.personalLockedResetDone"));
        } catch (err) {
          showToast(String(err), { duration: 1800 });
        }
      },
    });
  };

  const unlockPersonalVaults = async () => {
    personalUnlockError.value = "";
    personalUnlockBusy.value = true;
    try {
      const response = await invoke<ApiResponse<null>>("session_unlock_with_password", {
        password: personalUnlockPassword.value,
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw new Error(t(`errors.${key}`));
      }
      await refreshStatus();
      await refreshAppStatus();
      await runRemoteSync(selectedStorageId.value);
      if (storagePersonalLocked.value.get(selectedStorageId.value)) {
        personalUnlockError.value = t("errors.vault_key_mismatch");
        return;
      }
      personalUnlockOpen.value = false;
      personalUnlockPassword.value = "";
    } catch (err) {
      personalUnlockError.value = String(err);
    } finally {
      personalUnlockBusy.value = false;
    }
  };

  const sessionExpiredStorage = computed(() =>
    storages.value.find((s) => s.id === selectedStorageId.value),
  );

  return {
    personalUnlockOpen,
    personalUnlockPassword,
    personalUnlockError,
    personalUnlockBusy,
    openPersonalUnlock,
    handleResetPersonal,
    unlockPersonalVaults,
    sessionExpiredStorage,
  };
}
