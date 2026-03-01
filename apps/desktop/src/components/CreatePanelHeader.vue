<script setup lang="ts">
import CategoryIcon from "./CategoryIcon.vue";
import TypePickerMenu from "./TypePickerMenu.vue";
import type { Translator } from "../types/createForm";

const props = defineProps<{
  vaultName: string;
  itemTitle: string;
  folderLabel: string;
  busy: boolean;
  isOffline?: boolean;
  submitDisabled: boolean;
  submitTitle: string;
  isEditing: boolean;
  typeMenuOpen: boolean;
  typeOptions: string[];
  typeGroups: { id: string; label: string; types: string[] }[];
  typeMeta: Record<string, { icon: string }>;
  showAllTypesOption?: boolean;
  onShowAllTypes?: () => void;
  currentTypeLabel: string;
  currentTypeIcon: string;
  currentTypeId: string;
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
    <div class="max-w-[640px] mx-auto px-6 py-3">
      <div class="flex items-start justify-between gap-4">
        <div class="min-w-0">
          <div
            class="text-lg font-semibold truncate"
            :class="props.itemTitle.trim() ? 'text-[var(--text-primary)]' : 'text-[var(--text-tertiary)]'"
            data-testid="create-item-title-preview"
          >
            {{ props.itemTitle.trim() ? props.itemTitle : props.t("create.itemTitlePlaceholderPanel") }}
          </div>
          <div class="mt-1 flex flex-wrap items-center gap-2 text-xs text-[var(--text-secondary)]"></div>
        </div>
        <div class="flex items-center gap-2">
          <div class="relative">
            <button
              type="button"
              class="flex items-center gap-2 rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
              data-tauri-drag-region="false"
              @click="props.onToggleTypeMenu"
              data-testid="create-type-menu"
            >
              <CategoryIcon
                :icon="props.currentTypeIcon"
                :class="['h-4 w-4', `text-category-${props.currentTypeId}`]"
              />
              <span>{{ props.currentTypeLabel }}</span>
              <svg class="h-3.5 w-3.5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <TypePickerMenu
              :open="props.typeMenuOpen"
              :type-options="props.typeOptions"
              :type-groups="props.typeGroups"
              :type-meta="props.typeMeta"
              :get-type-label="props.getTypeLabel"
              :show-all-types-option="props.showAllTypesOption"
              :show-all-types-label="props.t('create.showAllTypes')"
              :on-show-all-types="props.onShowAllTypes"
              :on-select-type="props.onSelectType"
              :on-close="props.onCloseTypeMenu"
            />
          </div>
          <button
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            data-tauri-drag-region="false"
            @click="props.onCancel"
            data-testid="create-cancel"
          >
            {{ props.t("common.cancel") }}
          </button>
          <button
            type="button"
            class="flex items-center gap-2 rounded-lg bg-gray-800 dark:bg-gray-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            :disabled="props.busy || props.submitDisabled"
            :title="props.submitTitle"
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
            <span>
              {{
                props.isEditing
                  ? props.t("common.save")
                  : props.isOffline
                    ? props.t("create.createOffline")
                    : props.t("common.create")
              }}
            </span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
