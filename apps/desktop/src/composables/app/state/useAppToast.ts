import { ref } from "vue";

type ToastOptions = {
  actionLabel?: string;
  action?: () => void;
  duration?: number;
};

export function useAppToast() {
  const toast = ref("");
  const toastActionLabel = ref("");
  const toastAction = ref<(() => void) | null>(null);
  let toastTimer: number | null = null;

  const clearToast = () => {
    if (toastTimer) {
      window.clearTimeout(toastTimer);
      toastTimer = null;
    }
    toast.value = "";
    toastActionLabel.value = "";
    toastAction.value = null;
  };

  const showToast = (message: string, options?: ToastOptions) => {
    clearToast();
    toast.value = message;
    toastActionLabel.value = options?.actionLabel ?? "";
    toastAction.value = options?.action ?? null;
    const duration = options?.duration ?? 1200;
    if (duration > 0) {
      toastTimer = window.setTimeout(() => {
        clearToast();
      }, duration);
    }
  };

  const clearToastTimer = () => {
    if (toastTimer) {
      window.clearTimeout(toastTimer);
      toastTimer = null;
    }
  };

  return {
    toast,
    toastActionLabel,
    toastAction,
    clearToast,
    showToast,
    clearToastTimer,
  };
}
