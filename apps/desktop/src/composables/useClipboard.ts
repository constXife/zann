import { ref } from "vue";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import type { Ref } from "vue";
import type { Settings } from "../types";

type Translator = (key: string) => string;

type UseClipboardOptions = {
  settings: Ref<Settings | null>;
  t: Translator;
  setToast: (message: string) => void;
};

export const useClipboard = (options: UseClipboardOptions) => {
  const lastClipboardValue = ref("");
  const clipboardTimer = ref<number | null>(null);

  const readClipboard = async () => readText();

  const writeClipboard = async (value: string) => {
    await writeText(value);
  };

  const clearClipboardNow = async () => {
    if (!options.settings.value) {
      return;
    }
    if (options.settings.value.clipboard_clear_if_unchanged) {
      const current = await readClipboard();
      if (current !== lastClipboardValue.value) {
        return;
      }
    }
    await writeClipboard("");
    lastClipboardValue.value = "";
  };

  const scheduleClipboardClear = () => {
    if (!options.settings.value || options.settings.value.clipboard_clear_seconds <= 0) {
      return;
    }
    if (clipboardTimer.value) {
      window.clearTimeout(clipboardTimer.value);
    }
    clipboardTimer.value = window.setTimeout(async () => {
      await clearClipboardNow();
      clipboardTimer.value = null;
    }, options.settings.value.clipboard_clear_seconds * 1000);
  };

  const clearClipboardTimer = () => {
    if (clipboardTimer.value) {
      window.clearTimeout(clipboardTimer.value);
      clipboardTimer.value = null;
    }
  };

  const copyToClipboard = async (value: string) => {
    if (!value) {
      return;
    }
    await writeClipboard(value);
    lastClipboardValue.value = value;
    scheduleClipboardClear();
    options.setToast(options.t("common.copied"));
    window.setTimeout(() => {
      options.setToast("");
    }, 1200);
  };

  return {
    lastClipboardValue,
    copyToClipboard,
    clearClipboardNow,
    scheduleClipboardClear,
    clearClipboardTimer,
  };
};
