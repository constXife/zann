import type { Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type {
  ApiResponse,
  KeystoreStatus,
  PlainBackupExportResponse,
  PlainBackupImportResponse,
  Settings,
} from "../../../types";
import { createErrorWithCause } from "../../errors";

type AppSettingsActionsOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  settings: Ref<Settings | null>;
  keystoreStatus: Ref<KeystoreStatus | null>;
  locale: Ref<string>;
  showToast: (message: string, options?: { duration?: number }) => void;
  setError: (message: string) => void;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  syncError: Ref<string>;
};

export function useAppSettingsActions({
  t,
  settings,
  keystoreStatus,
  locale,
  showToast,
  setError,
  runRemoteSync,
  syncError,
}: AppSettingsActionsOptions) {
  const updateSettings = async (patch: Partial<Settings>) => {
    if (!settings.value) {
      return;
    }
    setError("");
    try {
      const previous = settings.value;
      const next = { ...previous, ...patch };
      if (!previous.remember_unlock && next.remember_unlock) {
        const result = await invoke<ApiResponse<null>>("keystore_enable", {
          requireBiometrics: next.require_os_auth ?? true,
        });
        if (!result.ok) {
          const key = result.error?.kind ?? "generic";
          const detail = result.error?.message
            ? `${t(`errors.${key}`)}: ${result.error.message}`
            : t(`errors.${key}`);
          throw createErrorWithCause(detail, result.error);
        }
        const ks = await invoke<ApiResponse<KeystoreStatus>>("keystore_status");
        if (ks.ok && ks.data) {
          keystoreStatus.value = ks.data;
        }
      }
      if (previous.remember_unlock && !next.remember_unlock) {
        const result = await invoke<ApiResponse<null>>("keystore_disable");
        if (!result.ok) {
          const key = result.error?.kind ?? "generic";
          const detail = result.error?.message
            ? `${t(`errors.${key}`)}: ${result.error.message}`
            : t(`errors.${key}`);
          throw createErrorWithCause(detail, result.error);
        }
      }
      settings.value = await invoke("update_settings", { settings: next });
      if (typeof next.language === "string" && next.language.length > 0) {
        locale.value = next.language;
      }
      showToast(t("common.saved"));
    } catch (err) {
      setError(String(err));
    }
  };

  const testBiometrics = async () => {
    setError("");
    try {
      await invoke("plugin:biometry|authenticate", {
        reason: t("settings.testTouchIdReason"),
        options: {},
      });
      showToast(t("settings.testTouchIdSuccess"), { duration: 1400 });
    } catch (err) {
      setError(String(err));
    }
  };

  const rebindBiometrics = async () => {
    setError("");
    try {
      const result = await invoke<ApiResponse<null>>("session_rebind_biometrics");
      if (!result.ok) {
        const key = result.error?.kind ?? "generic";
        const detail = result.error?.message
          ? `${t(`errors.${key}`)}: ${result.error.message}`
          : t(`errors.${key}`);
        throw createErrorWithCause(detail, result.error);
      }
      showToast(t("settings.rebindTouchIdSuccess"), { duration: 1400 });
    } catch (err) {
      setError(String(err));
    }
  };

  const exportPlainBackup = async (path?: string | null) => {
    setError("");
    try {
      const result = await invoke<ApiResponse<PlainBackupExportResponse>>("backup_plain_export", {
        path: path && path.trim().length > 0 ? path : null,
      });
      if (!result.ok || !result.data) {
        if (result.error?.kind === "backup_cancelled") {
          return undefined;
        }
        const key = result.error?.kind ?? "generic";
        const detail = result.error?.message
          ? `${t(`errors.${key}`)}: ${result.error.message}`
          : t(`errors.${key}`);
        throw createErrorWithCause(detail, result.error);
      }
      showToast(t("settings.backups.exportSuccess"));
      return result.data;
    } catch (err) {
      setError(String(err));
      return null;
    }
  };

  const importPlainBackup = async (path?: string | null, targetStorageId?: string | null) => {
    setError("");
    try {
      console.info("[backup] invoke import target", targetStorageId);
      const result = await invoke<ApiResponse<PlainBackupImportResponse>>("backup_plain_import", {
        payload: {
          path: path && path.trim().length > 0 ? path : null,
          target_storage_id: targetStorageId ?? null,
        },
      });
      if (!result.ok || !result.data) {
        if (result.error?.kind === "backup_cancelled") {
          return undefined;
        }
        const key = result.error?.kind ?? "generic";
        const detail = result.error?.message
          ? `${t(`errors.${key}`)}: ${result.error.message}`
          : t(`errors.${key}`);
        throw createErrorWithCause(detail, result.error);
      }
      const shouldSyncRemote =
        !!targetStorageId && targetStorageId !== "local";
      if (shouldSyncRemote) {
        showToast(t("settings.backups.importSyncStart"));
        const syncOk = await runRemoteSync(targetStorageId);
        if (syncOk) {
          showToast(t("settings.backups.importSyncDone"));
        } else {
          const message = syncError.value || t("settings.backups.importSyncFailed");
          showToast(message, { duration: 2000 });
        }
      } else {
        showToast(t("settings.backups.importSuccess"));
      }
      return result.data;
    } catch (err) {
      setError(String(err));
      return null;
    }
  };

  return {
    updateSettings,
    testBiometrics,
    rebindBiometrics,
    exportPlainBackup,
    importPlainBackup,
  };
}
