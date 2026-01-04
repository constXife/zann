<script setup lang="ts">
type Translator = (key: string) => string;

defineProps<{
  show: boolean;
  fatalError: string;
  t: Translator;
  onRetry: () => void;
}>();
</script>

<template>
  <div
    v-if="show"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl"
  >
    <div class="rounded-2xl bg-[var(--bg-secondary)] px-6 py-4 text-sm text-[var(--text-secondary)] shadow-xl space-y-3 max-w-sm text-center">
      <template v-if="fatalError">
        <div class="font-semibold text-[var(--text-primary)]">{{ t("errors.generic") }}</div>
        <div class="text-xs break-words">{{ fatalError }}</div>
        <button
          type="button"
          class="w-full rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-3 py-2 text-sm font-semibold text-white transition-colors"
          @click="onRetry"
        >
          {{ t("common.retry") }}
        </button>
      </template>
      <template v-else>
        {{ t("wizard.loading") }}
      </template>
    </div>
  </div>
</template>
