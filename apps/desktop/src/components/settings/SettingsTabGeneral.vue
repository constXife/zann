<script setup lang="ts">
import type { Settings } from "../../types";

type Translator = (key: string) => string;

defineProps<{
  settings: Settings | null;
  locale: string;
  t: Translator;
  updateSettings: (patch: Partial<Settings>) => void;
}>();
</script>

<template>
  <div class="space-y-6" v-if="settings">
    <!-- Appearance -->
    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.general.appearance") }}
      </h4>
      <div class="space-y-4">
        <div class="flex items-center justify-between">
          <label class="text-sm">{{ t("settings.general.language") }}</label>
          <select
            class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            :value="settings.language || locale"
            @change="updateSettings({ language: ($event.target as HTMLSelectElement).value })"
          >
            <option value="en">English</option>
            <option value="ru">Русский</option>
          </select>
        </div>
      </div>
    </div>

    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.general.trash") }}
      </h4>
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <label class="text-sm">{{ t("settings.general.trashRetention") }}</label>
          <select
            class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            :value="settings.trash_auto_purge_days"
            @change="updateSettings({ trash_auto_purge_days: Number(($event.target as HTMLSelectElement).value) })"
          >
            <option :value="0">{{ t("settings.general.trashRetentionNever") }}</option>
            <option :value="30">{{ t("settings.general.trashRetention30") }}</option>
            <option :value="90">{{ t("settings.general.trashRetention90") }}</option>
          </select>
        </div>
        <p class="text-xs text-[var(--text-tertiary)]">
          {{ t("settings.general.trashRetentionHelp") }}
        </p>
      </div>
    </div>

  </div>
</template>
