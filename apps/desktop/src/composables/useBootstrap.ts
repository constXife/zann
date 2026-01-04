import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, AppStatus, KeystoreStatus, Settings, Status } from "../types";

type Translator = (key: string) => string;

type UseBootstrapOptions = {
  t: Translator;
  locale: Ref<string>;
  onFatalError: (message: string) => void;
  onAfterUnlockLoad?: () => Promise<void>;
};

export const useBootstrap = (options: UseBootstrapOptions) => {
  const status = ref<Status | null>(null);
  const appStatus = ref<AppStatus | null>(null);
  const settings = ref<Settings | null>(null);
  const autoUnlockError = ref("");
  const keystoreStatus = ref<KeystoreStatus | null>(null);

  const refreshStatus = async () => {
    const response = await invoke<ApiResponse<Status>>("session_status");
    if (!response.ok || !response.data) {
      const key = response.error?.kind ?? "generic";
      throw new Error(options.t(`errors.${key}`));
    }
    status.value = response.data;
  };

  const refreshAppStatus = async () => {
    const response = await invoke<ApiResponse<AppStatus>>("app_status");
    if (!response.ok || !response.data) {
      const key = response.error?.kind ?? "generic";
      throw new Error(options.t(`errors.${key}`));
    }
    appStatus.value = response.data;
  };

  const bootstrap = async () => {
    autoUnlockError.value = "";
    try {
      await refreshAppStatus();
      const response = await invoke<{
        status: Status;
        settings: Settings;
        auto_unlock_error: string | null;
      }>("bootstrap");
      status.value = response.status;
      settings.value = response.settings;
      if (response.settings.language) {
        options.locale.value = response.settings.language;
      }
      if (response.auto_unlock_error) {
        autoUnlockError.value = response.auto_unlock_error;
      }
      if (response.status.unlocked && appStatus.value?.initialized && options.onAfterUnlockLoad) {
        await options.onAfterUnlockLoad();
      }
      const ks = await invoke<ApiResponse<KeystoreStatus>>("keystore_status");
      if (ks.ok && ks.data) {
        keystoreStatus.value = ks.data;
      }
    } catch (err) {
      options.onFatalError(String(err));
    }
  };

  return {
    status,
    appStatus,
    settings,
    autoUnlockError,
    keystoreStatus,
    refreshStatus,
    refreshAppStatus,
    bootstrap,
  };
};
