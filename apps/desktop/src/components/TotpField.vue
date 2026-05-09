<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useTotp } from "../composables/useTotp";
import type { TotpFieldData } from "../types";

type TotpFieldProps = {
  data: TotpFieldData;
  copyToClipboard: (value: string) => Promise<void>;
};

const props = defineProps<TotpFieldProps>();

const { t } = useI18n();
const { code, remainingSeconds, period, loading, error, isExpiringSoon, progressPercent, start, stop } = useTotp();

const copied = ref(false);
let copiedTimer: number | null = null;

const formattedCode = computed(() => {
  if (!code.value) return "";
  if (code.value.length === 6) {
    return `${code.value.slice(0, 3)} ${code.value.slice(3)}`;
  }
  if (code.value.length === 8) {
    return `${code.value.slice(0, 4)} ${code.value.slice(4)}`;
  }
  return code.value;
});

const copyCode = async () => {
  if (!code.value) return;
  try {
    await props.copyToClipboard(code.value);
    copied.value = true;
    if (copiedTimer) {
      window.clearTimeout(copiedTimer);
    }
    copiedTimer = window.setTimeout(() => {
      copied.value = false;
      copiedTimer = null;
    }, 1200);
  } catch {
    copied.value = false;
  }
};

const radius = 14;
const circumference = 2 * Math.PI * radius;
const strokeOffset = computed(() => {
  const progress = Math.max(0, Math.min(100, progressPercent.value));
  return circumference - (progress / 100) * circumference;
});

watch(
  () => props.data,
  (value) => {
    if (!value?.secret) {
      stop();
      return;
    }
    start(value);
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  stop();
  if (copiedTimer) {
    window.clearTimeout(copiedTimer);
  }
});
</script>

<template>
  <div class="flex items-center gap-3 -mt-1">
    <div
      v-if="error"
      class="rounded-md bg-red-500/10 border border-red-500/30 px-3 py-2 text-xs text-red-400"
    >
      {{ t("totp.error") }}
    </div>
    <template v-else>
      <button
        type="button"
        class="rounded-md bg-[var(--bg-hover)] px-3 py-1 font-mono text-sm font-semibold tracking-widest text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-active)]"
        :class="isExpiringSoon ? 'text-amber-200' : ''"
        :disabled="loading || !code"
        @click="copyCode"
      >
        <span v-if="loading" class="flex items-center gap-2 opacity-60">
          <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
            <circle class="opacity-30" cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2" />
            <path class="opacity-80" d="M21 12a9 9 0 0 1-9 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
          </svg>
          <span>------</span>
        </span>
        <span v-else-if="formattedCode">{{ formattedCode }}</span>
        <span v-else class="opacity-60">------</span>
      </button>
      <div class="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
        <div class="relative h-10 w-10">
          <svg class="h-10 w-10 -rotate-90" viewBox="0 0 36 36">
            <circle
              cx="18"
              cy="18"
              r="14"
              class="stroke-[var(--border-color)]"
              fill="none"
              stroke-width="3"
            />
            <circle
              cx="18"
              cy="18"
              r="14"
              class="transition-all"
              :class="isExpiringSoon ? 'stroke-amber-400' : 'stroke-[var(--accent)]'"
              fill="none"
              stroke-width="3"
              stroke-linecap="round"
              :stroke-dasharray="circumference"
              :stroke-dashoffset="strokeOffset"
            />
          </svg>
          <div class="absolute inset-0 flex items-center justify-center font-mono text-[10px]">
            {{ remainingSeconds }}
          </div>
        </div>
        <span v-if="copied" class="text-emerald-400">✓ {{ t("common.copied") }}</span>
        <span v-else>{{ t("totp.refreshEvery", { seconds: period }) }}</span>
      </div>
    </template>
  </div>
</template>
