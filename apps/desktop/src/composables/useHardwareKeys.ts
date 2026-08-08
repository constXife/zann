import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { ApiResponse, HardwareKeyEntry } from "../types";

/**
 * Enrolling and using FIDO2 authenticators as the source of the device key.
 *
 * Enrolment and unlocking both wait on a physical touch, so callers must keep
 * the prompt on screen for the whole call — the authenticator gives up after
 * about 30 seconds and the error comes back as `hardware_key_timeout`.
 */
export function useHardwareKeys() {
  const busy = ref(false);
  const error = ref("");

  const call = async <T>(command: string, args?: Record<string, unknown>) => {
    busy.value = true;
    error.value = "";
    try {
      const result = await invoke<ApiResponse<T>>(command, args);
      if (!result.ok) {
        error.value = result.error?.kind ?? "hardware_key_error";
        return null;
      }
      return result.data ?? null;
    } catch (err) {
      error.value = String(err);
      return null;
    } finally {
      busy.value = false;
    }
  };

  const supported = async () => (await call<boolean>("hardware_key_supported")) === true;

  /** Silent: no touch, no prompt. Safe to poll. */
  const present = async () => (await call<boolean>("hardware_key_present")) === true;

  /** Two touches: one to create the credential, one to prove hmac-secret works. */
  const enroll = (label: string) =>
    call<HardwareKeyEntry>("hardware_key_enroll", { label });

  const remove = (credentialId: string) =>
    call<null>("hardware_key_remove", { credentialId });

  /** One touch. */
  const unlock = async () => {
    const result = await call<null>("session_unlock_with_hardware_key");
    return result !== null || error.value === "";
  };

  return { busy, error, supported, present, enroll, remove, unlock };
}
