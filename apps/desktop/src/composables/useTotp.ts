import { computed, onBeforeUnmount, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { ApiResponse, TotpCodeResponse, TotpFieldData } from "../types";

export const useTotp = () => {
  const code = ref("");
  const remainingSeconds = ref(0);
  const period = ref(30);
  const loading = ref(false);
  const error = ref<string | null>(null);
  let intervalId: number | null = null;

  const isExpiringSoon = computed(() => remainingSeconds.value > 0 && remainingSeconds.value <= 5);
  const progressPercent = computed(() => {
    if (!period.value) return 0;
    return Math.max(0, Math.min(100, (remainingSeconds.value / period.value) * 100));
  });

  const clearTimer = () => {
    if (intervalId) {
      window.clearInterval(intervalId);
      intervalId = null;
    }
  };

  const tick = () => {
    if (remainingSeconds.value > 0) {
      remainingSeconds.value -= 1;
    }
  };

  const fetchCode = async (data: TotpFieldData) => {
    if (!data.secret) {
      code.value = "";
      remainingSeconds.value = 0;
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      const response = await invoke<ApiResponse<TotpCodeResponse>>("totp_generate", {
        secret: data.secret,
        algorithm: data.algorithm,
        digits: data.digits,
        period: data.period,
      });
      if (!response.ok || !response.data) {
        throw new Error(response.error?.message ?? "totp failed");
      }
      code.value = response.data.code;
      remainingSeconds.value = response.data.remaining_seconds;
      period.value = response.data.period;
    } catch (err) {
      error.value = String(err);
    } finally {
      loading.value = false;
    }
  };

  const start = (data: TotpFieldData) => {
    clearTimer();
    void fetchCode(data);
    intervalId = window.setInterval(() => {
      tick();
      if (remainingSeconds.value <= 0) {
        void fetchCode(data);
      }
    }, 1000);
  };

  const stop = () => {
    clearTimer();
  };

  onBeforeUnmount(() => {
    clearTimer();
  });

  watch(
    () => [remainingSeconds.value, period.value],
    ([remaining, periodValue]) => {
      if (remaining > periodValue) {
        remainingSeconds.value = periodValue;
      }
    },
  );

  return {
    code,
    remainingSeconds,
    period,
    loading,
    error,
    isExpiringSoon,
    progressPercent,
    fetchCode,
    start,
    stop,
  };
};
