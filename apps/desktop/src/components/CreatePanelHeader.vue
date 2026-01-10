<script setup lang="ts">
import CategoryIcon from "./CategoryIcon.vue";
import type { Translator } from "../types/createForm";

const props = defineProps<{
  vaultName: string;
  pathTokens: string[];
  busy: boolean;
  isEditing: boolean;
  typeMenuOpen: boolean;
  typeOptions: string[];
  typeGroups: { id: string; label: string; types: string[] }[];
  typeMeta: Record<string, { icon: string }>;
  currentTypeLabel: string;
  currentTypeIcon: string;
  getTypeLabel: (typeId: string) => string;
  t: Translator;
  onCancel: () => void;
  onSubmit: () => void;
  onToggleTypeMenu: () => void;
  onSelectType: (typeId: string) => void;
  onCloseTypeMenu: () => void;
}>();
</script>

<template>
  <div
    class="sticky top-0 z-40 border-b border-[var(--border-color)] bg-[var(--bg-secondary)]"
    data-tauri-drag-region
  >
    <div class="max-w-2xl mx-auto px-6 py-3">
      <div class="flex items-center justify-between gap-4">
        <div class="flex flex-wrap items-center gap-2 text-sm text-[var(--text-secondary)]">
          <span class="font-semibold text-[var(--text-tertiary)]">🔒 {{ props.vaultName }}</span>
          <template v-for="(token, idx) in props.pathTokens" :key="`${token}-${idx}-breadcrumb`">
            <span class="text-[var(--text-tertiary)]">/</span>
            <span>📂 {{ token }}</span>
          </template>
          <span v-if="props.pathTokens.length" class="text-[var(--text-tertiary)]">/</span>
          <span class="mx-1 h-4 w-px bg-[var(--border-color)]"></span>
          <div class="relative">
            <button
              type="button"
              class="flex items-center gap-2 rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
              data-tauri-drag-region="false"
              @click="props.onToggleTypeMenu"
              data-testid="create-type-menu"
            >
              <CategoryIcon :icon="props.currentTypeIcon" class="h-4 w-4" />
              <span>{{ props.currentTypeLabel }}</span>
              <svg class="h-3.5 w-3.5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <div
              v-if="props.typeMenuOpen"
              class="absolute left-0 top-full mt-2 w-44 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-50"
            >
              <template
                v-for="group in (props.typeGroups.length
                  ? props.typeGroups
                  : [{ id: 'default', label: 'Types', types: props.typeOptions.length ? props.typeOptions : ['login'] }])"
                :key="group.id"
              >
                <div class="px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--text-tertiary)]">
                  {{ group.label }}
                </div>
                <button
                  v-for="type in group.types"
                  :key="type"
                  type="button"
                  class="w-full flex items-center gap-2 px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
                  data-tauri-drag-region="false"
                  @click="props.onSelectType(type)"
                  :data-testid="`create-type-${type}`"
                >
                  <CategoryIcon :icon="props.typeMeta[type]?.icon ?? 'key'" class="h-4 w-4" />
                  <span>{{ props.getTypeLabel(type) }}</span>
                </button>
              </template>
            </div>
            <div
              v-if="props.typeMenuOpen"
              class="fixed inset-0 z-40"
              @click="props.onCloseTypeMenu"
            ></div>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            data-tauri-drag-region="false"
            @click="props.onCancel"
          >
            {{ props.t("common.cancel") }}
          </button>
          <button
            type="button"
            class="flex items-center gap-2 rounded-lg bg-gray-800 dark:bg-gray-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            :disabled="props.busy"
            data-tauri-drag-region="false"
            @click="props.onSubmit"
            data-testid="create-submit"
          >
            <svg
              v-if="props.busy"
              class="h-3.5 w-3.5 animate-spin"
              viewBox="0 0 24 24"
              fill="none"
            >
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
            </svg>
            <span>{{ props.isEditing ? props.t("common.save") : props.t("common.create") }}</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
