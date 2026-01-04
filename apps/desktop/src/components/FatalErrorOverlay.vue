<script setup lang="ts">
type Translator = (key: string) => string;

defineProps<{
  message: string;
  t: Translator;
  onRetry: () => void;
}>();
</script>

<template>
  <div
    v-if="message"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur"
  >
    <div class="w-full max-w-md rounded-2xl bg-[var(--bg-secondary)] p-6 shadow-xl">
      <h2 class="text-lg font-semibold">
        {{ t("errors.generic") }}
      </h2>
      <p class="mt-2 text-sm text-[var(--text-secondary)] break-words">{{ message }}</p>
      <button
        type="button"
        class="mt-4 w-full rounded-xl bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-4 py-2 text-sm font-semibold text-white transition-colors"
        @click="onRetry"
      >
        {{ t("common.retry") }}
      </button>
    </div>
  </div>
</template>
