<script setup lang="ts">
import CategoryIcon from "./CategoryIcon.vue";
import type { Translator } from "../types/createForm";

const props = defineProps<{
  createMode: "vault" | "item" | null;
  isEditing: boolean;
  typeMenuOpen: boolean;
  copyMenuOpen: boolean;
  typeOptions: string[];
  typeMeta: Record<string, { icon: string }>;
  currentTypeLabel: string;
  currentTypeIcon: string;
  getTypeLabel: (typeId: string) => string;
  t: Translator;
  onToggleTypeMenu: () => void;
  onSelectType: (typeId: string) => void;
  onCloseTypeMenu: () => void;
  onToggleCopyMenu: () => void;
  onCloseCopyMenu: () => void;
  onCopyJson: () => void;
  onCopyEnv: () => void;
  onCopyRaw: () => void;
  onOpenRawEditor: () => void;
  onClose: () => void;
}>();
</script>

<template>
  <div class="flex items-center justify-between gap-3 relative">
    <div class="flex items-center gap-3">
      <div class="relative" v-if="props.createMode === 'item'">
        <button
          type="button"
          class="flex items-center gap-2 rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm font-medium hover:bg-[var(--bg-hover)] transition-colors"
          @click="props.onToggleTypeMenu"
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
          <button
            v-for="type in props.typeOptions.length ? props.typeOptions : ['login']"
            :key="type"
            type="button"
            class="w-full flex items-center gap-2 px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.onSelectType(type)"
          >
            <CategoryIcon :icon="props.typeMeta[type]?.icon ?? 'key'" class="h-4 w-4" />
            <span>{{ props.getTypeLabel(type) }}</span>
          </button>
        </div>
        <div
          v-if="props.typeMenuOpen"
          class="fixed inset-0 z-40"
          @click="props.onCloseTypeMenu"
        ></div>
      </div>
      <div>
        <h3 class="text-lg font-semibold">
          {{
            props.createMode === "vault"
              ? props.t("create.vaultTitle")
              : props.isEditing
                ? props.t("create.itemEditHeader")
                : props.t("create.itemHeader")
          }}
        </h3>
        <p class="mt-1 text-sm text-[var(--text-secondary)]">
          {{ props.createMode === "vault" ? props.t("create.vaultBody") : props.t("create.itemBody") }}
        </p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <div v-if="props.createMode === 'item'" class="relative">
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
          @click="props.onToggleCopyMenu"
          :title="props.t('items.actions')"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v.01M12 12v.01M12 18v.01" />
          </svg>
        </button>
        <div
          v-if="props.copyMenuOpen"
          class="absolute right-0 top-full mt-2 w-48 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-50"
        >
          <button
            type="button"
            class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.onCopyJson"
          >
            {{ props.t("create.copyAsJson") }}
          </button>
          <button
            type="button"
            class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.onCopyEnv"
          >
            {{ props.t("create.copyAsEnv") }}
          </button>
          <button
            type="button"
            class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.onCopyRaw"
          >
            {{ props.t("create.copyAsRaw") }}
          </button>
          <div class="my-1 border-t border-[var(--border-color)]"></div>
          <button
            type="button"
            class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.onOpenRawEditor"
          >
            {{ props.t("create.editRawJson") }}
          </button>
        </div>
        <div
          v-if="props.copyMenuOpen"
          class="fixed inset-0 z-40"
          @click="props.onCloseCopyMenu"
        ></div>
      </div>
      <button
        type="button"
        class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
        @click="props.onClose"
      >
        <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  </div>
</template>
