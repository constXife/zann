<script setup lang="ts">
type Translator = (key: string) => string;

defineProps<{
  busy: boolean;
  error: string;
  t: Translator;
}>();
</script>

<template>
  <div
    v-if="busy || error"
    class="fixed bottom-4 right-4 max-w-sm rounded-xl border border-[var(--border-color)] bg-[var(--bg-secondary)] px-4 py-3 shadow-lg text-sm"
  >
    <div class="flex items-center gap-2">
      <svg v-if="busy" class="h-4 w-4 animate-spin text-[var(--accent)]" viewBox="0 0 24 24" fill="none">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
      </svg>
      <div class="font-medium text-[var(--text-primary)]">
        {{ busy ? t("wizard.loading") : t("errors.generic") }}
      </div>
    </div>
    <p v-if="error" class="mt-1 text-xs text-category-security break-words">{{ error }}</p>
  </div>
</template>
