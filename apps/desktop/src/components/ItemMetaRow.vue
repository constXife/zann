<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

const props = defineProps<{
  name: string;
  typeId: string;
  typeLabel: string;
  updatedAtLabel: string;
  isSharedVault: boolean;
  fileStatusLabel?: string | null;
}>();

const initial = computed(() => props.name?.charAt(0)?.toUpperCase() ?? "");
</script>

<template>
  <div class="flex items-center gap-3">
    <div
      class="flex h-12 w-12 items-center justify-center rounded-full text-white text-lg font-medium"
      :class="`bg-category-${props.typeId}`"
    >
      {{ initial }}
    </div>
    <div class="flex-1 min-w-0">
      <div class="flex items-center gap-2">
        <div class="text-2xl font-semibold text-[var(--text-primary)]">
          {{ props.name }}
        </div>
        <span
          v-if="props.isSharedVault"
          class="rounded-full bg-category-security/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-category-security"
        >
          {{ t("nav.shared") }}
        </span>
        <span
          v-if="props.fileStatusLabel"
          class="rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-400"
        >
          {{ props.fileStatusLabel }}
        </span>
      </div>
      <div class="mt-2 flex flex-wrap items-center gap-2 text-xs text-[var(--text-tertiary)]">
        <span
          v-if="props.typeLabel"
          class="rounded-full bg-[var(--bg-tertiary)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--text-secondary)]"
        >
          {{ t("items.typeLabel", { type: props.typeLabel }) }}
        </span>
        <span v-if="props.updatedAtLabel">
          {{ t("items.updatedAtLabel", { value: props.updatedAtLabel }) }}
        </span>
      </div>
    </div>
  </div>
</template>
