<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import type { KeystoreStatus, Settings } from "../types";
import Button from "./ui/Button.vue";

type Translator = (key: string) => string;

const password = defineModel<string>("password", { required: true });

const props = withDefaults(defineProps<{
  open: boolean;
  unlockBusy: boolean;
  settings: Settings | null;
  keystoreStatus: KeystoreStatus | null;
  autoUnlockError: string;
  error: string;
  title?: string;
  subtitle?: string;
  placeholder?: string;
  allowBiometrics?: boolean;
  t: Translator;
  onUnlock: () => void;
  onUnlockWithBiometrics: () => void;
}>(), {
  allowBiometrics: true,
});

const passwordInput = ref<HTMLInputElement | null>(null);
const biometricsAttempted = ref(false);

const canUseBiometrics = computed(() => {
  if (props.allowBiometrics === false) return false;
  if (!props.settings?.remember_unlock) return false;
  if (!props.settings?.biometry_dwk_backup) return false;
  if (!props.keystoreStatus) return true;
  return props.keystoreStatus.supported && props.keystoreStatus.biometrics_available;
});

const shouldAutoBiometrics = () =>
  canUseBiometrics.value &&
  !biometricsAttempted.value &&
  props.open &&
  !props.unlockBusy;

const focusPassword = async () => {
  await nextTick();
  passwordInput.value?.focus();
};

watch(
  () => [props.open, props.settings, props.keystoreStatus, props.unlockBusy] as const,
  ([isOpen]) => {
    if (!isOpen) {
      biometricsAttempted.value = false;
      return;
    }
    void focusPassword();
  },
  { immediate: true },
);

onMounted(() => {
  if (props.open) {
    void focusPassword();
  }
});
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl"
  >
    <div class="w-full max-w-sm rounded-2xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <div class="h-5 cursor-grab" data-tauri-drag-region></div>
      <div class="flex flex-col items-center text-center">
        <div class="flex h-16 w-16 items-center justify-center rounded-full bg-apple-blue dark:bg-apple-blue-dark">
          <svg class="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </div>
        <h2 class="mt-4 text-xl font-semibold">
          {{ props.title ?? t("unlock.title") }}
        </h2>
        <p class="mt-1 text-sm text-[var(--text-secondary)]">
          {{ props.subtitle ?? t("unlock.subtitle") }}
        </p>
      </div>
      <input
        ref="passwordInput"
        v-model="password"
        class="mt-6 w-full rounded-lg bg-[var(--bg-tertiary)] px-4 py-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] disabled:opacity-50 disabled:cursor-not-allowed"
        type="password"
        :placeholder="props.placeholder ?? t('unlock.placeholder')"
        autocomplete="current-password"
        :disabled="unlockBusy"
        @keyup.enter="onUnlock"
      />
      <Button
        class="mt-4"
        size="sm"
        full-width
        :loading="unlockBusy"
        @click="onUnlock"
      >
        {{ t("common.unlock") }}
      </Button>
      <Button
        v-if="canUseBiometrics"
        class="mt-4"
        variant="outline"
        size="sm"
        full-width
        @click="onUnlockWithBiometrics"
      >
        {{ t("unlock.touchId") }}
      </Button>
      <p v-if="autoUnlockError" class="mt-2 text-xs text-[var(--text-secondary)]">
        Auto-unlock unavailable: {{ autoUnlockError }}
      </p>
      <p v-if="error" class="mt-2 text-xs text-category-security">
        {{ error }}
      </p>
    </div>
  </div>
</template>
