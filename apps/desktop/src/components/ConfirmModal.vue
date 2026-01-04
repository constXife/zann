<script setup lang="ts">
import { computed, ref, watch } from "vue";

type Translator = (key: string, params?: Record<string, unknown>) => string;

const props = defineProps<{
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  busy?: boolean;
  danger?: boolean;
  confirmInputExpected?: string;
  confirmInputLabel?: string;
  confirmInputPlaceholder?: string;
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  confirm: [];
}>();

const confirmInput = ref("");
const requiresConfirmInput = computed(() => !!props.confirmInputExpected);
const confirmDisabled = computed(
  () => requiresConfirmInput.value && confirmInput.value !== props.confirmInputExpected,
);

watch(
  () => props.open,
  (open) => {
    if (open) {
      confirmInput.value = "";
    }
  },
);
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[110]"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="flex h-10 w-10 items-center justify-center rounded-full bg-category-security/20">
            <svg class="h-5 w-5 text-category-security" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold">{{ title }}</h3>
        </div>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <p class="mt-4 text-sm text-[var(--text-secondary)]">
        {{ message }}
      </p>

      <div v-if="requiresConfirmInput" class="mt-4 space-y-2">
        <label class="text-xs font-semibold text-[var(--text-secondary)]">
          {{ confirmInputLabel }}
        </label>
        <input
          v-model="confirmInput"
          type="text"
          class="w-full rounded-lg border border-[var(--border-color)] bg-transparent px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
          :placeholder="confirmInputPlaceholder"
          autocomplete="off"
        />
      </div>

      <div class="mt-6 flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          {{ cancelLabel ?? t("common.cancel") }}
        </button>
        <button
          type="button"
          class="rounded-lg px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          :class="danger ? 'bg-category-security' : 'bg-[var(--accent)]'"
          :disabled="busy || confirmDisabled"
          @click="emit('confirm')"
        >
          <svg v-if="busy" class="inline-block h-4 w-4 animate-spin mr-1" viewBox="0 0 24 24" fill="none">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
          </svg>
          {{ confirmLabel }}
        </button>
      </div>
    </div>
  </div>
</template>
