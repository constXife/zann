import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, Settings, Status } from "../types";

type Translator = (key: string) => string;

type UseSessionOptions = {
  t: Translator;
  status: Ref<Status | null>;
  settings: Ref<Settings | null>;
  onAfterUnlock: () => Promise<void>;
  onLocked: () => void;
  onError: (message: string) => void;
  clearClipboardNow: () => Promise<void>;
  clearClipboardTimer: () => void;
  clearRevealTimer: () => void;
  refreshStatus: () => Promise<void>;
  refreshAppStatus: () => Promise<void>;
};

class SessionError extends Error {}

export const useSession = (options: UseSessionOptions) => {
  const unlockBusy = ref(false);
  const normalizeError = (err: unknown) => {
    if (err instanceof SessionError) {
      return err.message;
    }
    return options.t("errors.generic");
  };

  const unlock = async (password: Ref<string>) => {
    options.onError("");
    unlockBusy.value = true;
    try {
      const response = await invoke<ApiResponse<null>>(
        "session_unlock_with_password",
        { password: password.value },
      );
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw new SessionError(options.t(`errors.${key}`));
      }
      await options.refreshStatus();
      await options.refreshAppStatus();
      await options.onAfterUnlock();
      password.value = "";
    } catch (err) {
      options.onError(normalizeError(err));
    } finally {
      unlockBusy.value = false;
    }
  };

  const unlockWithBiometrics = async () => {
    options.onError("");
    try {
      const response = await invoke<ApiResponse<null>>(
        "session_unlock_with_biometrics",
      );
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw new SessionError(options.t(`errors.${key}`));
      }
      await options.refreshStatus();
      await options.refreshAppStatus();
      await options.onAfterUnlock();
    } catch (err) {
      options.onError(normalizeError(err));
    }
  };

  const lockSession = async () => {
    options.onError("");
    try {
      await invoke<ApiResponse<null>>("session_lock");
      options.status.value = {
        unlocked: false,
        db_path: options.status.value?.db_path ?? "",
      };
      options.onLocked();
      options.clearRevealTimer();
      options.clearClipboardTimer();
      if (options.settings.value?.clipboard_clear_on_lock) {
        await options.clearClipboardNow();
      }
    } catch (err) {
      options.onError(normalizeError(err));
    }
  };

  return {
    unlockBusy,
    unlock,
    unlockWithBiometrics,
    lockSession,
  };
};
