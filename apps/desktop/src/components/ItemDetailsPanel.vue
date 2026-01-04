<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import { useI18n } from "vue-i18n";
import ItemCharViewModal from "./ItemCharViewModal.vue";
import type {
  DetailSection,
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
  hasPasswordField: boolean;
  isRevealed: (path: string) => boolean;
  altRevealAll: boolean;
  toggleReveal: (path: string) => void;
  copyField: (field: FieldRow) => void;
  copyEnv: () => void;
  copyJson: () => void;
  copyRaw: () => void;
  copyHistoryPassword: (version: number) => void;
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

const formatHistoryActor = (entry: ItemHistorySummary) =>
  entry.changed_by_name ?? entry.changed_by_email;

const latestHistoryEntry = computed(() => props.historyEntries[0] ?? null);
const currentPasswordField = computed(() =>
  props.detailSections
    .flatMap((section) => section.fields)
    .find((field) => field.kind === "password"),
);

const historyViewerOpen = ref(false);
const historyViewerLoading = ref(false);
const historyViewerError = ref("");
const historyViewerTitle = ref("");
const historyViewerPayload = ref("");

const openHistoryViewer = async (entry: ItemHistorySummary) => {
  historyViewerOpen.value = true;
  historyViewerLoading.value = true;
  historyViewerError.value = "";
  historyViewerTitle.value = formatUpdatedAt(entry.created_at);
  historyViewerPayload.value = "";
  try {
    const payload = await props.fetchHistoryPayload(entry.version);
    historyViewerPayload.value = payload
      ? JSON.stringify(payload, null, 2)
      : "";
    if (!historyViewerPayload.value) {
      historyViewerError.value = t("items.historyVersionMissing");
    }
  } catch (err) {
    historyViewerError.value = String(err);
  } finally {
    historyViewerLoading.value = false;
  }
};

const closeHistoryViewer = () => {
  historyViewerOpen.value = false;
  historyViewerLoading.value = false;
  historyViewerError.value = "";
  historyViewerTitle.value = "";
  historyViewerPayload.value = "";
};

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
              </div>
              <div class="text-xs text-[var(--text-tertiary)] mt-2">
                {{ formatUpdatedAt(selectedItem.updated_at) }}
              </div>
            </div>
          </div>
        </div>

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
          >
            <div class="grid grid-cols-[180px,1fr] gap-4 items-start">
              <div class="text-xs font-mono font-semibold uppercase tracking-wide text-[var(--text-tertiary)]">
                {{ formatFieldLabel(field.key) }}
              </div>
              <div class="flex items-start justify-between gap-3">
                <button
                  type="button"
                  class="min-w-0 flex-1 text-left font-mono text-sm text-[var(--text-primary)] px-1 py-1 transition-colors focus:outline-none"
                  :class="field.copyable ? 'hover:bg-[var(--bg-hover)] cursor-pointer rounded-md' : ''"
                  @click="handleCopy(field)"
                >
                  <span
                    v-if="field.masked && !(props.altRevealAll || isRevealed(field.path))"
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
                    v-if="field.masked && field.revealable"
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
                </div>
              </div>
            </div>
          </div>
        </div>

        <div v-if="hasPasswordField" class="mt-10">
          <div class="flex items-center justify-between gap-3">
            <div class="text-xs font-semibold uppercase tracking-widest text-[var(--text-tertiary)]">
              {{ t("items.previousPasswords") }}
            </div>
            <div class="flex items-center gap-2">
              <button
                type="button"
                class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
                :disabled="!currentPasswordField"
                @click="currentPasswordField && copyField(currentPasswordField)"
              >
                {{ t("items.copyCurrentPassword") }}
              </button>
              <button
                type="button"
                class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
                :disabled="!latestHistoryEntry || historyLoading || !!historyError"
                @click="latestHistoryEntry && copyHistoryPassword(latestHistoryEntry.version)"
              >
                {{ t("items.copyPreviousPassword") }}
              </button>
              <button
                type="button"
                class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
                :disabled="!latestHistoryEntry || historyLoading || !!historyError"
                @click="latestHistoryEntry && openHistoryViewer(latestHistoryEntry)"
              >
                {{ t("items.viewHistoryVersion") }}
              </button>
            </div>
          </div>
          <div class="mt-1 text-[10px] text-[var(--text-tertiary)]">
            {{ t("items.previousPasswordsNote") }}
          </div>
          <div
            v-if="historyLoading"
            class="mt-3 text-xs text-[var(--text-tertiary)]"
          >
            {{ t("items.previousPasswordsLoading") }}
          </div>
          <div
            v-else-if="historyError"
            class="mt-3 text-xs text-red-500"
          >
            {{ historyError }}
          </div>
          <div class="mt-3 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)]">
            <div
              v-if="!historyEntries.length && !historyLoading && !historyError"
              class="px-4 py-3 text-xs italic text-[var(--text-tertiary)]"
            >
              {{ t("items.previousPasswordsEmpty") }}
            </div>
            <div
              v-for="entry in historyEntries"
              :key="entry.version"
              class="flex items-center justify-between gap-3 px-4 py-3 text-sm text-[var(--text-primary)] border-b border-[var(--border-color)] last:border-b-0"
            >
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span>{{ formatUpdatedAt(entry.created_at) }}</span>
                  <span class="text-[var(--text-tertiary)]">• v{{ entry.version }}</span>
                  <span
                    v-if="entry.pending"
                    class="rounded-full bg-[var(--bg-hover)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--text-tertiary)]"
                  >
                    {{ t("items.historyPending") }}
                  </span>
                </div>
                <div class="text-xs text-[var(--text-tertiary)]">
                  {{ formatHistoryActor(entry) }}
                </div>
              </div>
              <div class="flex items-center gap-1">
                <button
                  type="button"
                  class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
                  :title="t('items.historyCopyTitle')"
                  @click="copyHistoryPassword(entry.version)"
                >
                  📋
                </button>
                <button
                  type="button"
                  class="rounded p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
                  :title="t('items.historyViewTitle')"
                  @click="openHistoryViewer(entry)"
                >
                  👁️
                </button>
              </div>
            </div>
          </div>
        </div>

      </div>

      <div
        v-if="historyViewerOpen"
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-md"
        @click.self="closeHistoryViewer"
      >
        <div class="w-full max-w-2xl rounded-xl border border-[var(--border-color)] bg-[var(--bg-secondary)] p-5 shadow-2xl">
          <div class="flex items-center justify-between gap-3">
            <div class="text-sm font-semibold text-[var(--text-primary)]">
              {{ t("items.historyVersionTitle") }} · {{ historyViewerTitle }}
            </div>
            <button
              type="button"
              class="rounded-md px-2 py-1 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              @click="closeHistoryViewer"
            >
              {{ t("common.close") }}
            </button>
          </div>
          <div v-if="historyViewerLoading" class="mt-4 text-xs text-[var(--text-tertiary)]">
            {{ t("items.historyVersionLoading") }}
          </div>
          <div v-else-if="historyViewerError" class="mt-4 text-xs text-red-500">
            {{ historyViewerError }}
          </div>
          <pre
            v-else
            class="mt-4 max-h-[60vh] overflow-auto rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] px-4 py-3 text-xs text-[var(--text-primary)]"
          >{{ historyViewerPayload }}</pre>
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
