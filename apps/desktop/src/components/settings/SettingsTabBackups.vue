<script setup lang="ts">
type Translator = (key: string) => string;

defineProps<{
  t: Translator;
}>();
</script>

<template>
  <div class="space-y-6">
    <!-- Info banner -->
    <div class="rounded-lg bg-amber-500/10 border border-amber-500/20 p-4">
      <div class="flex items-start gap-3">
        <svg class="h-5 w-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <h4 class="font-medium text-amber-600 dark:text-amber-400">{{ t("settings.backups.localOnly") }}</h4>
          <p class="text-sm text-[var(--text-secondary)] mt-1">
            {{ t("settings.backups.description") }}
          </p>
        </div>
      </div>
    </div>

    <!-- Coming Soon -->
    <div class="flex flex-col items-center justify-center py-12 text-center">
      <div class="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--bg-tertiary)] mb-4">
        <svg class="h-8 w-8 text-[var(--text-tertiary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
        </svg>
      </div>
      <h4 class="text-lg font-medium text-[var(--text-secondary)]">{{ t("settings.backups.comingSoon") }}</h4>
      <p class="text-sm text-[var(--text-tertiary)] mt-2 max-w-sm">
        {{ t("settings.backups.comingSoonDesc") }}
      </p>
    </div>

    <!-- Warning -->
    <div class="rounded-lg bg-[var(--bg-tertiary)] p-4">
      <div class="flex items-start gap-3">
        <svg class="h-5 w-5 text-[var(--text-tertiary)] shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p class="text-sm text-[var(--text-tertiary)]">
          {{ t("settings.backups.singleWriterWarning") }}
        </p>
      </div>
    </div>
  </div>
</template>
