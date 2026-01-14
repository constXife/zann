import type { Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { ApiResponse, KeystoreStatus, Settings } from "../../../types";
import { createErrorWithCause } from "../../errors";

type AppSettingsActionsOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  settings: Ref<Settings | null>;
  keystoreStatus: Ref<KeystoreStatus | null>;
  locale: Ref<string>;
  showToast: (message: string, options?: { duration?: number }) => void;
  setError: (message: string) => void;
};

export function useAppSettingsActions({
  t,
  settings,
  keystoreStatus,
  locale,
  showToast,
  setError,
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

  return {
    updateSettings,
    testBiometrics,
    rebindBiometrics,
  };
}
