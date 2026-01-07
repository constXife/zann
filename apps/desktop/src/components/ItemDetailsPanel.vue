<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import { useI18n } from "vue-i18n";
import ItemCharViewModal from "./ItemCharViewModal.vue";
import type {
  DetailSection,
  EncryptedPayload,
  FieldRow,
  ItemDetail,
  ItemHistorySummary,
} from "../types";

const { t } = useI18n();

const props = defineProps<{
  query: string;
  detailLoading: boolean;
  errorMessage: string;
  selectedItem: ItemDetail | null;
  detailSections: DetailSection[];
  historyEntries: ItemHistorySummary[];
  historyLoading: boolean;
  historyError: string;
  isRevealed: (path: string) => boolean;
  altRevealAll: boolean;
  toggleReveal: (path: string) => void;
  copyField: (field: FieldRow) => void;
  copyEnv: () => void;
  copyJson: () => void;
  copyRaw: () => void;
  copyHistoryPassword: (version: number) => void;
  restoreHistoryVersion: (entry: ItemHistorySummary) => void;
  fetchHistoryPayload: (version: number) => Promise<{
    v: number;
    typeId: string;
    fields: Record<string, { kind: string; value: string }>;
  } | null>;
  openExternal: (url: string) => void;
  selectFolder?: (path: string) => void;
  openEditItem: () => void;
  deleteItem: () => void;
  isDeleted: boolean;
  restoreItem: () => void;
  purgeItem: () => void;
  vaultName: string;
  isSharedVault: boolean;
  isConflict: boolean;
  resolveConflict: () => void;
  timeTravelActive: boolean;
  timeTravelIndex: number;
  timeTravelPayload: EncryptedPayload | null;
  timeTravelBasePayload: EncryptedPayload | null;
  timeTravelLoading: boolean;
  timeTravelError: string;
  timeTravelHasDraft: boolean;
  openTimeTravel: () => void;
  closeTimeTravel: () => void;
  setTimeTravelIndex: (index: number) => void;
  applyTimeTravelField: (fieldKey: string) => void;
}>();

const emit = defineEmits<{ (e: "update:query", value: string): void }>();

const searchInput = ref<HTMLInputElement | null>(null);
const copiedField = ref<string | null>(null);
const actionMenuOpen = ref(false);
const headerCopyNotice = ref("");
let headerCopyTimer: number | null = null;
const expandedFields = ref(new Set<string>());
let copiedTimer: number | null = null;
const charViewOpen = ref(false);
const charViewLabel = ref("");
const charViewValue = ref("");

defineExpose({ searchInput, focusSearch: () => searchInput.value?.focus() });

const formatFieldLabel = (key: string) => key;

const formatUpdatedAt = (value?: string | null) => {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
};

type DiffStatus = "same" | "modified" | "added" | "deleted";

const timeTravelActive = computed(() => props.timeTravelActive);

const fileStatus = computed(() => {
  if (!props.selectedItem || props.selectedItem.type_id !== "file_secret") {
    return null;
  }
  const extra = props.selectedItem.payload?.extra ?? {};
  const uploadState = extra.upload_state;
  if (!uploadState) {
    return null;
  }
  const key = uploadState.toLowerCase();
  const label = t(`items.fileStatus.${key}`);
  return {
    key,
    label: label.includes("items.fileStatus.") ? uploadState : label,
  };
});

const timeTravelEntry = computed(() => props.historyEntries[props.timeTravelIndex] ?? null);

const timeTravelTitle = computed(() =>
  timeTravelEntry.value ? formatUpdatedAt(timeTravelEntry.value.created_at) : "",
);

const timeTravelTotal = computed(() => props.historyEntries.length);

const timeTravelPosition = computed(() => {
  if (!timeTravelTotal.value) {
    return 0;
  }
  return timeTravelSliderIndex.value + 1;
});

const timeTravelPercent = computed(() => {
  if (timeTravelSliderMax.value === 0) {
    return 0;
  }
  return Math.round((timeTravelSliderIndex.value / timeTravelSliderMax.value) * 100);
});

const timeTravelTimeline = computed(() => {
  const entries = props.historyEntries.map((entry, historyIndex) => ({
    entry,
    historyIndex,
    ts: Date.parse(entry.created_at),
  }));
  return entries
    .slice()
    .sort((a, b) => {
      const aOk = Number.isFinite(a.ts);
      const bOk = Number.isFinite(b.ts);
      if (aOk && bOk) {
        return a.ts - b.ts;
      }
      if (aOk) return -1;
      if (bOk) return 1;
      return a.historyIndex - b.historyIndex;
    })
    .map((entry, timelineIndex) => ({
      ...entry,
      timelineIndex,
    }));
});

const timeTravelSliderMax = computed(() =>
  Math.max(0, timeTravelTimeline.value.length - 1),
);

const timeTravelSliderIndex = computed(() => {
  const match = timeTravelTimeline.value.find(
    (entry) => entry.historyIndex === props.timeTravelIndex,
  );
  return match?.timelineIndex ?? 0;
});

const timeTravelSegments = computed(() => {
  const total = timeTravelTotal.value;
  if (!total) {
    return [];
  }
  const max = Math.max(0, timeTravelSliderMax.value);
  const widthPercent = total > 0 ? 100 / total : 100;
  return timeTravelTimeline.value.map((entry) => {
    const percent = max > 0 ? (entry.timelineIndex / max) * 100 : 0;
    const left = Math.min(100 - widthPercent, Math.max(0, percent - widthPercent / 2));
    return {
      ...entry,
      percent,
      left,
      width: widthPercent,
    };
  });
});

const getBaseField = (key: string) => props.timeTravelBasePayload?.fields?.[key];

const timeTravelSnapPulse = ref(false);
let timeTravelSnapTimer: number | null = null;

const triggerTimeTravelSnap = () => {
  timeTravelSnapPulse.value = true;
  if (timeTravelSnapTimer) {
    window.clearTimeout(timeTravelSnapTimer);
  }
  timeTravelSnapTimer = window.setTimeout(() => {
    timeTravelSnapPulse.value = false;
    timeTravelSnapTimer = null;
  }, 160);
};

const setTimeTravelByTimelineIndex = (timelineIndex: number) => {
  const entry = timeTravelTimeline.value[timelineIndex];
  if (!entry) {
    return;
  }
  props.setTimeTravelIndex(entry.historyIndex);
  triggerTimeTravelSnap();
};

const timeTravelSliderPercent = computed(() => {
  if (timeTravelSliderMax.value === 0) {
    return 0;
  }
  return Math.round((timeTravelSliderIndex.value / timeTravelSliderMax.value) * 100);
});

const isRevealed = (path: string) => props.isRevealed(path);

const showMaskedValue = (path: string) =>
  !(props.altRevealAll || isRevealed(path) || timeTravelActive.value);

const diffStatus = (field: FieldRow): DiffStatus => {
  if (!timeTravelActive.value) {
    return "same";
  }
  const base = getBaseField(field.path);
  if (!base) {
    return "added";
  }
  if (base.kind === field.kind && base.value === field.value) {
    return "same";
  }
  return "modified";
};

const diffPreviousValue = (field: FieldRow) => getBaseField(field.path)?.value ?? "";

const diffPreviousMasked = (field: FieldRow) => {
  const base = getBaseField(field.path);
  if (!base) {
    return false;
  }
  return base.meta?.masked ?? (base.kind === "password" || base.kind === "otp");
};

const deletedTimeTravelFields = computed(() => {
  if (!timeTravelActive.value || !props.timeTravelBasePayload || !props.timeTravelPayload) {
    return [];
  }
  const baseFields = props.timeTravelBasePayload.fields ?? {};
  const currentFields = props.timeTravelPayload.fields ?? {};
  const keys = Object.keys(baseFields).filter((key) => !(key in currentFields));
  keys.sort((a, b) => a.localeCompare(b));
  return keys.map((key) => {
    const entry = baseFields[key];
    const masked = entry.meta?.masked ?? (entry.kind === "password" || entry.kind === "otp");
    const copyable = entry.meta?.copyable ?? true;
    const revealable = entry.meta?.masked ?? masked;
    return {
      key,
      field: {
        key,
        value: entry.value,
        path: `history-base:${key}`,
        kind: entry.kind,
        masked,
        copyable,
        revealable,
      },
    };
  });
});

const folderSegments = computed(() => {
  if (!props.selectedItem) {
    return [];
  }
  const parts = props.selectedItem.path.split("/").filter(Boolean);
  return parts.slice(0, Math.max(0, parts.length - 1));
});

const breadcrumbs = computed(() => {
  const parts = folderSegments.value;
  const crumbs: { label: string; path: string }[] = [];
  parts.forEach((segment, idx) => {
    crumbs.push({
      label: segment,
      path: parts.slice(0, idx + 1).join("/"),
    });
  });
  return crumbs;
});

const isLongValue = (field: FieldRow) =>
  field.value.length > 120 || field.value.includes("\n");

const isExpanded = (field: FieldRow) => expandedFields.value.has(field.path);

const openCharView = (field: FieldRow) => {
  charViewLabel.value = formatFieldLabel(field.key);
  charViewValue.value = field.value ?? "";
  charViewOpen.value = true;
};

const closeCharView = () => {
  charViewOpen.value = false;
  charViewValue.value = "";
  charViewLabel.value = "";
};

const toggleExpanded = (field: FieldRow) => {
  const next = new Set(expandedFields.value);
  if (next.has(field.path)) {
    next.delete(field.path);
  } else {
    next.add(field.path);
  }
  expandedFields.value = next;
};

const handleCopy = async (field: FieldRow) => {
  if (!field.copyable) {
    return;
  }
  await props.copyField(field);
  copiedField.value = field.path;
  if (copiedTimer) {
    window.clearTimeout(copiedTimer);
  }
  copiedTimer = window.setTimeout(() => {
    copiedField.value = null;
    copiedTimer = null;
  }, 2000);
};

const showHeaderCopyNotice = (message: string) => {
  headerCopyNotice.value = message;
  if (headerCopyTimer) {
    window.clearTimeout(headerCopyTimer);
  }
  headerCopyTimer = window.setTimeout(() => {
    headerCopyNotice.value = "";
    headerCopyTimer = null;
  }, 1800);
};

const handleHeaderCopy = async (kind: "env" | "json" | "raw") => {
  if (kind === "env") {
    await props.copyEnv();
    showHeaderCopyNotice(t("common.copied"));
    return;
  }
  if (kind === "json") {
    await props.copyJson();
    showHeaderCopyNotice(t("common.copied"));
    return;
  }
  await props.copyRaw();
  showHeaderCopyNotice(t("common.copied"));
};

const openLink = (field: FieldRow) => {
  if (field.kind !== "url") {
    return;
  }
  props.openExternal(field.value);
};

const selectBreadcrumb = (crumb: { path: string }) => {
  if (!props.selectFolder) {
    return;
  }
  props.selectFolder(crumb.path);
};

onBeforeUnmount(() => {
  if (copiedTimer) {
    window.clearTimeout(copiedTimer);
    copiedTimer = null;
  }
  if (headerCopyTimer) {
    window.clearTimeout(headerCopyTimer);
    headerCopyTimer = null;
  }
  if (timeTravelSnapTimer) {
    window.clearTimeout(timeTravelSnapTimer);
    timeTravelSnapTimer = null;
  }
});
</script>

<template>
  <section
    class="flex flex-1 min-w-0 flex-col border-l border-[var(--border-color)] bg-[var(--bg-secondary)]"
  >
    <div class="p-3">
      <div class="relative">
        <svg class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          ref="searchInput"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] py-2 pl-9 pr-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
          type="search"
          :value="props.query"
          :placeholder="t('items.searchPlaceholder')"
          @input="emit('update:query', ($event.target as HTMLInputElement).value)"
        />
      </div>
    </div>

    <div class="flex-1 overflow-auto px-4 pb-4">
      <div
        v-if="detailLoading"
        class="space-y-3 animate-pulse"
      >
        <div class="h-4 w-24 rounded bg-[var(--bg-hover)]"></div>
        <div class="h-3 rounded bg-[var(--bg-hover)]"></div>
        <div class="h-3 rounded bg-[var(--bg-hover)]"></div>
      </div>
      <div
        v-else-if="errorMessage"
        class="rounded-lg border border-red-200 bg-red-500/10 px-4 py-3 text-sm text-red-700 dark:border-red-500/30 dark:text-red-300"
      >
        {{ errorMessage }}
      </div>
      <div v-else-if="selectedItem" class="space-y-6">
        <div class="space-y-3">
          <div class="flex items-center justify-between gap-4">
            <div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
              <span class="font-semibold text-[var(--text-tertiary)]">🔒 {{ vaultName }}</span>
              <template v-for="crumb in breadcrumbs" :key="crumb.path">
                <span class="text-[var(--text-tertiary)]">/</span>
                <button
                  type="button"
                  class="text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                  @click="selectBreadcrumb(crumb)"
                >
                  📂 {{ crumb.label }}
                </button>
              </template>
              <span v-if="breadcrumbs.length" class="text-[var(--text-tertiary)]">/</span>
            </div>
            <div class="flex items-center gap-2">
              <button
                type="button"
                class="rounded-lg px-2 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] disabled:opacity-50"
                :class="timeTravelActive ? 'bg-[var(--bg-active)] text-[var(--text-primary)]' : ''"
                :disabled="historyLoading || !!historyError || !historyEntries.length"
                @click="timeTravelActive ? closeTimeTravel() : openTimeTravel()"
              >
                <span class="mr-1">🕒</span>
                {{ timeTravelActive ? t("items.historyClose") : t("items.historyOpen") }}
              </button>
              <button
                v-if="isDeleted"
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-semibold text-white bg-[var(--accent)] hover:opacity-90"
                @click="restoreItem"
              >
                <svg class="mr-1 inline-block h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v6h6M21 17a8 8 0 0 1-14 0M21 7a8 8 0 0 0-14 0" />
                </svg>
                {{ t("items.restore") }}
              </button>
              <button
                v-else-if="isConflict"
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-semibold text-white bg-amber-500 hover:bg-amber-400"
                @click="resolveConflict"
              >
                {{ t("items.resolveConflict") }}
              </button>
              <button
                v-else
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-semibold text-white bg-[var(--accent)] hover:opacity-90"
                @click="openEditItem"
              >
                {{ t("common.edit") }}
              </button>
              <div class="relative">
                <button
                  type="button"
                  class="rounded-lg px-2 py-1 text-xs font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                  @click="actionMenuOpen = !actionMenuOpen"
                >
                  ⋯
                </button>
                <div
                  v-if="actionMenuOpen"
                  class="absolute right-0 mt-2 w-44 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-50"
                >
                  <button
                    type="button"
                    class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
                    @click="handleHeaderCopy('env'); actionMenuOpen = false"
                  >
                    {{ t("items.copyEnv") }}
                  </button>
                  <button
                    type="button"
                    class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
                    @click="handleHeaderCopy('json'); actionMenuOpen = false"
                  >
                    {{ t("items.copyJson") }}
                  </button>
                  <button
                    type="button"
                    class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
                    @click="handleHeaderCopy('raw'); actionMenuOpen = false"
                  >
                    {{ t("items.copyRaw") }}
                  </button>
                  <div class="my-1 border-t border-[var(--border-color)]"></div>
                  <button
                    v-if="!isDeleted"
                    type="button"
                    class="w-full px-3 py-2 text-sm text-left text-category-security hover:bg-[var(--bg-hover)] transition-colors"
                    @click="deleteItem(); actionMenuOpen = false"
                  >
                    {{ t("items.moveToTrash") }}
                  </button>
                  <button
                    v-if="isDeleted"
                    type="button"
                    class="w-full px-3 py-2 text-sm text-left text-category-security hover:bg-[var(--bg-hover)] transition-colors"
                    @click="purgeItem(); actionMenuOpen = false"
                  >
                    {{ t("items.deleteForever") }}
                  </button>
                </div>
                <div
                  v-if="actionMenuOpen"
                  class="fixed inset-0 z-40"
                  @click="actionMenuOpen = false"
                ></div>
              </div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <div
              class="flex h-12 w-12 items-center justify-center rounded-full text-white text-lg font-medium"
              :class="`bg-category-${selectedItem.type_id}`"
            >
              {{ selectedItem.name.charAt(0).toUpperCase() }}
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2">
                <div class="text-2xl font-semibold text-[var(--text-primary)]">
                  {{ selectedItem.name }}
                </div>
                <span
                  v-if="isSharedVault"
                  class="rounded-full bg-category-security/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-category-security"
                >
                  {{ t('nav.shared') }}
                </span>
                <span
                  v-if="fileStatus"
                  class="rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-400"
                >
                  {{ fileStatus.label }}
                </span>
              </div>
              <div class="text-xs text-[var(--text-tertiary)] mt-2">
                {{ formatUpdatedAt(selectedItem.updated_at) }}
              </div>
            </div>
          </div>
        </div>

        <div
          v-if="timeTravelActive"
          class="sticky top-0 z-10 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)]/90 px-3 py-2 text-xs text-[var(--text-primary)] backdrop-blur"
        >
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-semibold">{{ t("items.historyTimeTravelTitle") }}</span>
              <span class="text-[var(--text-tertiary)]">· {{ timeTravelTitle }}</span>
            </div>
            <div class="flex items-center gap-2 text-[var(--text-tertiary)]">
              <span>{{ t("items.historyPosition", { current: timeTravelPosition, total: timeTravelTotal }) }}</span>
              <span>{{ timeTravelPercent }}%</span>
            </div>
          </div>
          <div class="mt-2">
            <div class="flex items-center justify-between gap-2 text-[10px] text-[var(--text-tertiary)]">
              <button
                type="button"
                class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
                :disabled="!timeTravelEntry || timeTravelEntry.pending"
                @click="timeTravelEntry && restoreHistoryVersion(timeTravelEntry)"
              >
                {{ t("items.historyRestore") }}
              </button>
              <div class="flex items-center gap-1">
                <button
                  type="button"
                  class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
                  :disabled="timeTravelSliderIndex >= timeTravelSliderMax"
                  @click="setTimeTravelByTimelineIndex(timeTravelSliderIndex + 1)"
                >
                  ◀
                </button>
                <button
                  type="button"
                  class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
                  :disabled="timeTravelSliderIndex <= 0"
                  @click="setTimeTravelByTimelineIndex(timeTravelSliderIndex - 1)"
                >
                  ▶
                </button>
              </div>
            </div>
            <div
              class="relative mt-2"
              :class="timeTravelSnapPulse ? 'time-travel-snap' : ''"
            >
              <div class="absolute inset-0 pointer-events-none">
                <span
                  v-for="entry in timeTravelSegments"
                  :key="entry.entry.version"
                  class="absolute top-1/2 h-2 -translate-y-1/2 rounded-full bg-[var(--bg-tertiary)]/70"
                  :style="{ left: `${entry.left}%`, width: `${entry.width}%` }"
                ></span>
              </div>
              <input
                class="time-travel-range w-full"
                type="range"
                min="0"
                :max="timeTravelSliderMax"
                step="1"
                :value="timeTravelSliderIndex"
                @input="setTimeTravelByTimelineIndex(Number(($event.target as HTMLInputElement).value))"
              />
            </div>
            <div class="mt-1 flex items-center justify-between text-[10px] text-[var(--text-tertiary)]">
              <span v-if="timeTravelTimeline.length">
                {{ formatUpdatedAt(timeTravelTimeline[0].entry.created_at) }}
              </span>
              <span v-if="timeTravelTimeline.length">
                {{ formatUpdatedAt(timeTravelTimeline[timeTravelTimeline.length - 1].entry.created_at) }}
              </span>
            </div>
          </div>
          <div v-if="timeTravelLoading" class="mt-2 text-[var(--text-tertiary)]">
            {{ t("items.historyVersionLoading") }}
          </div>
          <div v-else-if="timeTravelError" class="mt-2 text-red-400">
            {{ timeTravelError }}
          </div>
          <div v-else-if="timeTravelHasDraft" class="mt-2 text-[var(--text-tertiary)]">
            {{ t("items.historyDraftNotice") }}
          </div>
        </div>

        <div
          class="transition-all"
          :class="timeTravelActive ? 'opacity-80 translate-y-1' : ''"
        >
          <div
            v-for="section in detailSections"
            :key="section.title"
            class="space-y-2"
          >
            <div v-if="section.title" class="text-xs font-medium text-[var(--text-secondary)] mb-3">
              {{ section.title }}
            </div>
            <div
              v-for="field in section.fields"
              :key="field.path"
              class="group border-b border-white/5 py-3 last:border-b-0"
              :class="timeTravelActive && diffStatus(field) === 'modified'
                ? 'bg-amber-500/10'
                : timeTravelActive && diffStatus(field) === 'added'
                  ? 'bg-emerald-500/10'
                  : ''"
            >
              <div class="grid grid-cols-[180px,1fr] gap-4 items-start">
                <div class="text-xs font-mono font-semibold uppercase tracking-wide text-[var(--text-tertiary)]">
                  {{ formatFieldLabel(field.key) }}
                  <span
                    v-if="timeTravelActive && diffStatus(field) === 'added'"
                    class="ml-2 rounded-full bg-emerald-500/20 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-emerald-200"
                  >
                    {{ t("items.historyAddedTag") }}
                  </span>
                  <span
                    v-else-if="timeTravelActive && diffStatus(field) === 'modified'"
                    class="ml-2 rounded-full bg-amber-500/20 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-amber-200"
                  >
                    {{ t("items.historyModifiedTag") }}
                  </span>
                </div>
                <div class="flex items-start justify-between gap-3">
                  <div class="min-w-0 flex-1">
                    <button
                      type="button"
                    class="min-w-0 w-full text-left font-mono text-sm text-[var(--text-primary)] px-1 py-1 transition-colors focus:outline-none"
                    :class="[
                      field.copyable ? 'hover:bg-[var(--bg-hover)] cursor-pointer rounded-md' : '',
                      timeTravelActive && diffStatus(field) === 'modified' ? 'bg-emerald-500/10 rounded-md' : '',
                    ]"
                    @click="handleCopy(field)"
                  >
                  <span
                    v-if="field.masked && showMaskedValue(field.path)"
                    class="tracking-widest text-base leading-none text-[var(--text-primary)]"
                  >
                    ••••••••••••
                  </span>
                      <span
                        v-else
                        class="break-words text-[var(--text-primary)]"
                        :class="isLongValue(field) && !isExpanded(field) ? 'truncate whitespace-nowrap' : 'whitespace-pre-wrap'"
                      >
                        {{ field.value }}
                      </span>
                    </button>
                    <div
                      v-if="timeTravelActive && diffStatus(field) === 'modified'"
                      class="mt-2 rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs text-red-200"
                    >
                      <div class="text-[9px] font-semibold uppercase tracking-wide text-red-300">
                        {{ t("items.historyPreviousValue") }}
                      </div>
                      <div
                      class="mt-1 font-mono whitespace-pre-wrap"
                        :class="diffPreviousMasked(field) && showMaskedValue(field.path) ? 'tracking-widest text-base leading-none' : ''"
                      >
                        <span
                          v-if="diffPreviousMasked(field) && showMaskedValue(field.path)"
                        >
                          ••••••••••••
                        </span>
                        <span v-else>{{ diffPreviousValue(field) }}</span>
                      </div>
                    </div>
                  </div>
                  <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      v-if="field.kind === 'url'"
                      type="button"
                      class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                      @click.stop="openLink(field)"
                    >
                      ↗
                    </button>
                    <button
                      type="button"
                      class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                      @click.stop="openCharView(field)"
                      title="Character view"
                    >
                      ⧉
                    </button>
                    <button
                      v-if="isLongValue(field)"
                      type="button"
                      class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                      @click.stop="toggleExpanded(field)"
                    >
                      {{ isExpanded(field) ? t('common.hide') : t('common.reveal') }}
                    </button>
                    <button
                      v-if="field.masked && field.revealable && !timeTravelActive"
                      type="button"
                      class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                      @click.stop="toggleReveal(field.path)"
                    >
                      <svg v-if="!(props.altRevealAll || isRevealed(field.path))" class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                      </svg>
                      <svg v-else class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                      </svg>
                    </button>
                  <button
                    v-if="field.copyable"
                    type="button"
                    class="rounded px-2 py-1 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                    @click.stop="handleCopy(field)"
                  >
                    <span v-if="copiedField === field.path" class="text-emerald-400">
                      ✓ {{ t('common.copied') }}
                    </span>
                    <span v-else>📋 {{ t('common.copy') }}</span>
                  </button>
                  <button
                    v-if="timeTravelActive && (diffStatus(field) === 'modified' || diffStatus(field) === 'added')"
                    type="button"
                    class="rounded px-2 py-1 text-[11px] font-semibold text-amber-200 hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                    @click.stop="applyTimeTravelField(field.path)"
                  >
                    ↩ {{ t("items.historyApplyField") }}
                  </button>
                </div>
              </div>
            </div>
          </div>
          </div>

          <div
            v-if="timeTravelActive && deletedTimeTravelFields.length"
            class="space-y-2"
          >
            <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
              {{ t("items.historyDeletedSection") }}
            </div>
            <div
              v-for="entry in deletedTimeTravelFields"
              :key="entry.key"
              class="group border-b border-white/5 py-3 last:border-b-0 bg-red-500/10"
            >
              <div class="grid grid-cols-[180px,1fr] gap-4 items-start">
                <div class="text-xs font-mono font-semibold uppercase tracking-wide text-[var(--text-tertiary)]">
                  {{ formatFieldLabel(entry.field.key) }}
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
                      @click="handleCopy(entry.field)"
                    >
                    <span
                      v-if="entry.field.masked && showMaskedValue(entry.field.path)"
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
                  <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      v-if="entry.field.masked && entry.field.revealable && !timeTravelActive"
                      type="button"
                      class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                      @click.stop="toggleReveal(entry.field.path)"
                    >
                      <svg v-if="!(props.altRevealAll || isRevealed(entry.field.path))" class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                    @click.stop="handleCopy(entry.field)"
                  >
                    <span v-if="copiedField === entry.field.path" class="text-emerald-400">
                      ✓ {{ t('common.copied') }}
                    </span>
                    <span v-else>📋 {{ t('common.copy') }}</span>
                  </button>
                  <button
                    v-if="timeTravelActive"
                    type="button"
                    class="rounded px-2 py-1 text-[11px] font-semibold text-red-200 hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
                    @click.stop="applyTimeTravelField(entry.key)"
                  >
                    ↩ {{ t("items.historyApplyField") }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
        </div>

        <div v-if="timeTravelActive && !historyEntries.length" class="mt-6 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] px-4 py-3 text-xs text-[var(--text-tertiary)]">
          {{ t("items.historyEmpty") }}
        </div>

      </div>

      <ItemCharViewModal
        :open="charViewOpen"
        :label="charViewLabel"
        :value="charViewValue"
        @close="closeCharView"
      />
      <div
        v-if="!selectedItem && !detailLoading && !errorMessage"
        class="flex flex-col items-center justify-center h-full text-[var(--text-secondary)]"
      >
        <svg class="h-16 w-16 opacity-20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
        <div class="mt-4 text-sm font-medium">
          {{ t('items.selectItem') }}
        </div>
        <p class="mt-1 text-xs text-center max-w-[200px]">
          {{ t('items.detailsHint') }}
        </p>
      </div>
    </div>
  </section>
</template>

<style scoped>
.time-travel-range {
  -webkit-appearance: none;
  appearance: none;
  height: 10px;
  background: linear-gradient(90deg, rgba(99, 102, 241, 0.2), rgba(16, 185, 129, 0.2));
  border-radius: 999px;
  cursor: pointer;
}

.time-travel-range:focus {
  outline: none;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
}

.time-travel-range::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 20px;
  height: 20px;
  border-radius: 999px;
  background: var(--accent);
  border: 2px solid rgba(255, 255, 255, 0.6);
  box-shadow: 0 6px 18px rgba(15, 23, 42, 0.35);
  transition: transform 120ms ease;
}

.time-travel-range::-moz-range-thumb {
  width: 20px;
  height: 20px;
  border-radius: 999px;
  background: var(--accent);
  border: 2px solid rgba(255, 255, 255, 0.6);
  box-shadow: 0 6px 18px rgba(15, 23, 42, 0.35);
  transition: transform 120ms ease;
}

.time-travel-range::-webkit-slider-runnable-track {
  height: 10px;
  border-radius: 999px;
}

.time-travel-range::-moz-range-track {
  height: 10px;
  border-radius: 999px;
}

.time-travel-snap .time-travel-range::-webkit-slider-thumb {
  transform: scale(1.08);
}

.time-travel-snap .time-travel-range::-moz-range-thumb {
  transform: scale(1.08);
}
</style>
