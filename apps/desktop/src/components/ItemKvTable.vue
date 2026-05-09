<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import { useI18n } from "vue-i18n";
import type { FieldRow } from "../types";
import Button from "./ui/Button.vue";

const { t } = useI18n();

const kvSearch = defineModel<string>("kvSearch", { required: true });

const props = defineProps<{
  fields: FieldRow[];
  timeTravelActive: boolean;
  altRevealAll: boolean;
  isRevealed: (path: string) => boolean;
  toggleReveal: (path: string) => void;
  openLink: (field: FieldRow) => void;
  openCharView: (field: FieldRow) => void;
  handleCopy: (field: FieldRow) => void;
  handleCopyKey: (field: FieldRow) => void;
  handleCopyPair: (field: FieldRow) => void;
  copiedField: string | null;
  copyEnv: (options?: { includeProtected?: boolean }) => void;
  copyJson: (options?: { includeProtected?: boolean }) => void;
}>();

const filteredFields = computed(() => {
  const query = kvSearch.value.trim().toLowerCase();
  if (!query) {
    return props.fields;
  }
  return props.fields.filter((field) =>
    [field.key, field.value].some((value) =>
      value.toLowerCase().includes(query),
    ),
  );
});

const showMaskedValue = (path: string) => !props.altRevealAll && !props.isRevealed(path);
const matchCount = computed(() => filteredFields.value.length);
const totalCount = computed(() => props.fields.length);

const openMenuFor = ref<string | null>(null);
const revealTimers = new Map<string, number>();
const revealVersion = ref<Record<string, number>>({});
const revealDurationMs = 8000;

const toggleMenu = (path: string) => {
  openMenuFor.value = openMenuFor.value === path ? null : path;
};

const closeMenu = () => {
  openMenuFor.value = null;
};

const bumpRevealVersion = (path: string) => {
  revealVersion.value = {
    ...revealVersion.value,
    [path]: (revealVersion.value[path] ?? 0) + 1,
  };
};

const handleReveal = (path: string) => {
  const isOpen = props.isRevealed(path);
  props.toggleReveal(path);
  const existing = revealTimers.get(path);
  if (existing) {
    window.clearTimeout(existing);
    revealTimers.delete(path);
  }
  if (!isOpen) {
    bumpRevealVersion(path);
    const timer = window.setTimeout(() => {
      if (props.isRevealed(path)) {
        props.toggleReveal(path);
      }
      revealTimers.delete(path);
    }, revealDurationMs);
    revealTimers.set(path, timer);
  }
};

const handleValueClick = (field: FieldRow, event: MouseEvent) => {
  const selection = window.getSelection();
  if (selection && selection.toString().length > 0) {
    return;
  }
  if (event.shiftKey) {
    props.handleCopyKey(field);
    return;
  }
  if (event.altKey) {
    props.handleCopyPair(field);
    return;
  }
  props.handleCopy(field);
};

onBeforeUnmount(() => {
  revealTimers.forEach((timer) => window.clearTimeout(timer));
  revealTimers.clear();
});

const copiedValue = (path: string) => props.copiedField === path;
const copiedKey = (path: string) => props.copiedField === `${path}:key`;
const copiedPair = (path: string) => props.copiedField === `${path}:pair`;
</script>

<template>
  <div class="space-y-3">
    <div class="flex flex-wrap items-center justify-end gap-2">
      <div class="relative">
        <Button
          variant="outline"
          size="xs"
          :title="t('items.actions')"
          @click="openMenuFor === '__bulk__' ? closeMenu() : (openMenuFor = '__bulk__')"
        >
          {{ t("items.copyMenu") }} ▾
        </Button>
        <div
          v-if="openMenuFor === '__bulk__'"
          class="absolute right-0 mt-2 w-56 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-30"
        >
          <button
            type="button"
            class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.copyEnv(); closeMenu()"
          >
            {{ t("items.copyEnvExcludedLabel") }}
          </button>
          <button
            type="button"
            class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.copyJson(); closeMenu()"
          >
            {{ t("items.copyJsonExcludedLabel") }}
          </button>
          <div class="my-1 border-t border-[var(--border-color)]"></div>
          <button
            type="button"
            class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.copyEnv({ includeProtected: true }); closeMenu()"
          >
            {{ t("items.copyEnvInclude") }}
          </button>
          <button
            type="button"
            class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
            @click="props.copyJson({ includeProtected: true }); closeMenu()"
          >
            {{ t("items.copyJsonInclude") }}
          </button>
        </div>
      </div>
      <input
        v-model="kvSearch"
        type="search"
        class="w-48 rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-xs text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
        :placeholder="t('items.kvSearchPlaceholder')"
      />
      <span
        v-if="kvSearch.trim().length"
        class="text-[11px] text-[var(--text-tertiary)]"
      >
        {{ t("items.kvMatches", { count: matchCount, total: totalCount }) }}
      </span>
    </div>
    <div class="rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)]">
      <div
        v-if="!filteredFields.length"
        class="px-4 py-6 text-center text-xs text-[var(--text-tertiary)]"
      >
        {{ t("items.kvNoMatches") }}
      </div>
      <div
        v-for="field in filteredFields"
        :key="field.path"
        class="group grid grid-cols-[clamp(80px,25%,220px),28px,1fr,auto] items-center gap-3 border-b border-[var(--border-color)] px-4 py-3 text-sm cursor-pointer last:border-b-0 hover:bg-[var(--bg-hover)] odd:bg-white/[0.02] transition-colors"
        @click="handleValueClick(field, $event)"
      >
        <div class="truncate font-mono text-[var(--text-secondary)]" :title="field.key">
          {{ field.key }}
        </div>
        <div class="flex items-center justify-center">
          <Button
            v-if="field.masked"
            variant="ghost"
            size="icon-xs"
            class="relative text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
            :title="isRevealed(field.path) ? t('items.hideValue') : t('items.revealValue')"
            @click.stop="handleReveal(field.path)"
          >
            {{ isRevealed(field.path) ? "🔓" : "🔒" }}
            <svg
              v-if="field.masked && isRevealed(field.path)"
              :key="`reveal-${field.path}-${revealVersion[field.path] ?? 0}`"
              class="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 reveal-ring"
              width="36"
              height="36"
              viewBox="0 0 36 36"
              :style="{ animationDuration: `${revealDurationMs}ms` }"
            >
              <circle cx="18" cy="18" r="15" fill="none" stroke="currentColor" stroke-width="1.5" />
            </svg>
          </Button>
        </div>
        <div class="min-w-0">
          <div
            class="group/value min-w-0"
            :class="field.masked && showMaskedValue(field.path) ? 'text-[var(--text-secondary)]' : 'text-[var(--text-primary)]'"
          >
            <span
              v-if="field.masked && showMaskedValue(field.path)"
              class="font-mono tracking-widest text-base leading-none"
            >
              ••••••••••••
            </span>
            <span
              v-else
              class="font-mono break-words"
              :class="field.masked && !showMaskedValue(field.path) ? 'revealed-pulse' : ''"
            >
              {{ field.value }}
            </span>
          </div>
        </div>
        <div class="flex flex-wrap items-center justify-end gap-1">
          <button
            v-if="field.kind === 'url'"
            type="button"
            class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)] opacity-0 group-hover:opacity-100 transition"
            @click.stop="openLink(field)"
          >
            ↗
          </button>
          <Button
            v-if="field.masked"
            variant="ghost"
            size="icon-xs"
            class="opacity-0 group-hover:opacity-100 transition"
            :title="t('items.characterView')"
            @click.stop="props.openCharView(field)"
          >
            ⧉
          </Button>
          <Button
            v-if="field.copyable"
            variant="ghost"
            size="icon-xs"
            :title="t('items.copyValue')"
            @click.stop="props.handleCopy(field)"
          >
            <span v-if="copiedValue(field.path)" class="text-emerald-400 text-xs">✓</span>
            <svg v-else class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 7h9a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z" />
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 3H7a2 2 0 0 0-2 2v10" />
            </svg>
          </Button>
          <div class="relative">
            <Button
              variant="ghost"
              size="icon-xs"
              :class="openMenuFor === field.path ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition'"
              :title="t('items.actions')"
              @click.stop="toggleMenu(field.path)"
            >
              ⋯
            </Button>
            <div
              v-if="openMenuFor === field.path"
              class="absolute right-0 mt-2 w-52 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-30"
            >
              <button
                v-if="field.masked && field.revealable && !timeTravelActive"
                type="button"
                class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
                @click.stop="handleReveal(field.path); closeMenu()"
              >
                {{ isRevealed(field.path) ? t("items.hideValue") : t("items.revealValue") }}
              </button>
              <button
                type="button"
                class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
                @click.stop="props.openCharView(field); closeMenu()"
              >
                {{ t("items.characterView") }}
              </button>
              <button
                v-if="field.copyable"
                type="button"
                class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
                @click.stop="props.handleCopyKey(field); closeMenu()"
              >
                <span v-if="copiedKey(field.path)" class="text-emerald-400">
                  ✓ {{ t("items.copiedKey") }}
                </span>
                <span v-else>{{ t("items.copyKey") }}</span>
              </button>
              <button
                v-if="field.copyable"
                type="button"
                class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
                @click.stop="props.handleCopyPair(field); closeMenu()"
              >
                <span v-if="copiedPair(field.path)" class="text-emerald-400">
                  ✓ {{ t("items.copiedPair") }}
                </span>
                <span v-else>{{ t("items.copyPair") }}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div
      v-if="openMenuFor"
      class="fixed inset-0 z-20"
      @click="closeMenu"
    ></div>
  </div>
</template>

<style scoped>
.reveal-ring {
  color: rgba(16, 185, 129, 0.5);
  stroke-dasharray: 94;
  stroke-dashoffset: 0;
  animation-name: reveal-ring;
  animation-timing-function: linear;
  animation-fill-mode: forwards;
}

@keyframes reveal-ring {
  to {
    stroke-dashoffset: 94;
  }
}

.revealed-pulse {
  animation: soft-pulse 2s ease-in-out infinite;
}

@keyframes soft-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}
</style>
