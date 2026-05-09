<script setup lang="ts">
import { useI18n } from "vue-i18n";
import type { FieldRow } from "../types";

const { t } = useI18n();

type DeletedFieldEntry = {
  key: string;
  field: FieldRow;
};

const props = defineProps<{
  entries: DeletedFieldEntry[];
  timeTravelActive: boolean;
  altRevealAll: boolean;
  isRevealed: (path: string) => boolean;
  toggleReveal: (path: string) => void;
  handleCopy: (field: FieldRow) => void;
  copiedField: string | null;
  showMaskedValue: (path: string) => boolean;
  applyTimeTravelField: (fieldKey: string) => void;
  formatFieldLabel: (key: string) => string;
}>();
</script>

<template>
  <div class="space-y-2">
    <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
      {{ t("items.historyDeletedSection") }}
    </div>
    <div
      v-for="entry in props.entries"
      :key="entry.key"
      class="group border-b border-white/5 py-3 last:border-b-0 bg-red-500/10"
    >
      <div class="grid grid-cols-[180px,1fr] gap-4 items-start">
        <div class="text-xs font-mono font-semibold uppercase tracking-wide text-[var(--text-tertiary)]">
          {{ props.formatFieldLabel(entry.field.key) }}
          <span class="ml-2 rounded-full bg-red-500/20 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-red-200">
            {{ t("items.historyDeletedTag") }}
          </span>
        </div>
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0 flex-1">
            <button
              type="button"
              class="min-w-0 w-full text-left font-mono text-sm text-[var(--text-primary)] px-1 py-1 transition-colors focus:outline-none"
              :class="entry.field.copyable ? 'hover:bg-[var(--bg-hover)] cursor-pointer rounded-md' : ''"
              @click="props.handleCopy(entry.field)"
            >
              <span
                v-if="entry.field.masked && props.showMaskedValue(entry.field.path)"
                class="tracking-widest text-base leading-none text-[var(--text-primary)]"
              >
                ••••••••••••
              </span>
              <span
                v-else
                class="break-words text-[var(--text-primary)] whitespace-pre-wrap"
              >
                {{ entry.field.value }}
              </span>
            </button>
          </div>
          <div class="flex items-center gap-1 opacity-100">
            <button
              v-if="entry.field.masked && entry.field.revealable && !props.timeTravelActive"
              type="button"
              class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="props.toggleReveal(entry.field.path)"
            >
              <svg v-if="!(props.altRevealAll || props.isRevealed(entry.field.path))" class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              <svg v-else class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
              </svg>
            </button>
            <button
              v-if="entry.field.copyable"
              type="button"
              class="rounded px-2 py-1 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="props.handleCopy(entry.field)"
            >
              <span v-if="props.copiedField === entry.field.path" class="text-emerald-400">
                ✓ {{ t("common.copied") }}
              </span>
              <span v-else>📋 {{ t("common.copy") }}</span>
            </button>
            <button
              v-if="props.timeTravelActive"
              type="button"
              class="rounded px-2 py-1 text-[11px] font-semibold text-red-200 hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="props.applyTimeTravelField(entry.key)"
            >
              ↩ {{ t("items.historyApplyField") }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
