import { ref } from "vue";

export type ToastItem = {
  id: string;
  message: string;
  actionLabel?: string;
  action?: () => void;
  timeoutId?: number | null;
};

type ToastOptions = {
  actionLabel?: string;
  action?: () => void;
  duration?: number;
};

export function useAppToast() {
  const toasts = ref<ToastItem[]>([]);
  const MAX_TOASTS = 5;

  const clearTimer = (toast: ToastItem) => {
    if (toast.timeoutId) {
      window.clearTimeout(toast.timeoutId);
      toast.timeoutId = null;
    }
  };

  const removeToast = (id: string) => {
    const index = toasts.value.findIndex((entry) => entry.id === id);
    if (index === -1) return;
    const [removed] = toasts.value.splice(index, 1);
    if (removed) {
      clearTimer(removed);
    }
  };

  const clearToast = () => {
    toasts.value.forEach((toast) => clearTimer(toast));
    toasts.value = [];
  };

  const clearToastTimer = () => {
    toasts.value.forEach((toast) => clearTimer(toast));
  };

  const showToast = (message: string, options?: ToastOptions) => {
    const id =
      globalThis.crypto?.randomUUID?.() ??
      `toast-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const toast: ToastItem = {
      id,
      message,
      actionLabel: options?.actionLabel,
      action: options?.action,
      timeoutId: null,
    };
    const duration = options?.duration ?? 1200;
    if (duration > 0) {
      toast.timeoutId = window.setTimeout(() => {
        removeToast(id);
      }, duration);
    }
    const next = [toast, ...toasts.value];
    if (next.length > MAX_TOASTS) {
      next.slice(MAX_TOASTS).forEach((entry) => clearTimer(entry));
    }
    toasts.value = next.slice(0, MAX_TOASTS);
  };

  return {
    toasts,
    clearToast,
    showToast,
    clearToastTimer,
  };
}
