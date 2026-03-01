<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import ItemCharViewModal from "./ItemCharViewModal.vue";
import ItemDetailsHeader from "./ItemDetailsHeader.vue";
import ItemDetailsDiffView from "./ItemDetailsDiffView.vue";
import ItemDetailsState from "./ItemDetailsState.vue";
import ItemDetailsTimeTravelPanel from "./ItemDetailsTimeTravelPanel.vue";
import ItemFieldList from "./ItemFieldList.vue";
import ItemKvTable from "./ItemKvTable.vue";
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
  listLoading: boolean;
  listError: string;
  filteredItemsCount: number;
  categories: { id: string; label: string }[];
  selectedCategory: string | null;
  selectedFolder: string | null;
  openCreateItem: (typeId?: string) => void;
  openPalette: () => void;
  showOfflineBanner: boolean;
  showSessionExpiredBanner: boolean;
  showPersonalLockedBanner: boolean;
  showSyncErrorBanner: boolean;
  showGlobalBanner: boolean;
  syncBusy: boolean;
  syncErrorMessage: string;
  pendingChangesCount: number;
  lastSyncTime: string | null;
  onSignIn: () => void;
  onUnlockPersonal: () => void;
  onResetPersonal: () => void;
  retrySync: () => void;
  selectedItem: ItemDetail | null;
  detailSections: DetailSection[];
  historyEntries: ItemHistorySummary[];
  historyLoading: boolean;
  historyError: string;
  isRevealed: (path: string) => boolean;
  altRevealAll: boolean;
  toggleReveal: (path: string) => void;
  copyField: (field: FieldRow) => void;
  copyEnv: (options?: { includeProtected?: boolean }) => void;
  copyJson: (options?: { includeProtected?: boolean }) => void;
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
const expandedFields = ref(new Set<string>());
let copiedTimer: number | null = null;
const charViewOpen = ref(false);
const charViewLabel = ref("");
const charViewValue = ref("");
const charViewField = ref<FieldRow | null>(null);

defineExpose({ searchInput, focusSearch: () => searchInput.value?.focus() });

const formatFieldLabel = (key: string) => key;

const contextLabel = computed(() => {
  if (props.selectedFolder !== null) {
    if (props.selectedFolder === "") {
      return t("nav.noFolder");
    }
    return props.selectedFolder;
  }
  if (props.selectedCategory && props.selectedCategory !== "all") {
    return props.categories.find((cat) => cat.id === props.selectedCategory)?.label ?? t("nav.allItems");
  }
  return t("nav.allItems");
});

const showEmptyListState = computed(
  () =>
    !props.listLoading &&
    !props.listError &&
    props.filteredItemsCount === 0,
);

const showNoSelectionState = computed(
  () =>
    !props.listLoading &&
    !props.listError &&
    !props.selectedItem &&
    props.filteredItemsCount > 0,
);

const showListErrorState = computed(() => !props.listLoading && !!props.listError);

const platformHint = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`.toLowerCase();
const isMac = computed(() => platformHint.includes("mac"));

const createShortcut = computed(() => (isMac.value ? "⌘N" : "Ctrl+N"));
const searchShortcut = computed(() => (isMac.value ? "⌘K" : "Ctrl+K"));
const kvSearch = ref("");

const typeLabel = computed(() => {
  const typeId = props.selectedItem?.type_id ?? "";
  if (!typeId) {
    return "";
  }
  const key = `types.${typeId}`;
  const label = t(key);
  return label !== key ? label : typeId;
});

const updatedAtLabel = computed(() =>
  props.selectedItem ? formatUpdatedAt(props.selectedItem.updated_at) : "",
);

const isKvType = computed(() => props.selectedItem?.type_id === "kv");

const kvFields = computed(() =>
  props.detailSections.flatMap((section) => section.fields),
);

const allCurrentFields = computed(() =>
  props.detailSections.flatMap((section) => section.fields),
);

const baseFieldsMap = computed(() =>
  props.timeTravelBasePayload?.fields ?? {},
);

watch(
  () => props.selectedItem?.id ?? null,
  () => {
    kvSearch.value = "";
  },
);

const systemState = computed(() => {
  if (props.showPersonalLockedBanner) return "personalLocked";
  if (props.showSessionExpiredBanner) return "sessionExpired";
  if (props.showGlobalBanner) return null;
  if (props.showSyncErrorBanner) return "syncError";
  if (props.showOfflineBanner) return "offline";
  return null;
});

const showSystemState = computed(() => systemState.value !== null);
const interactionsBlocked = computed(
  () => props.showPersonalLockedBanner || props.showSessionExpiredBanner,
);

const detailsStateVariant = computed(() => {
  if (showSystemState.value) return "system";
  if (showListErrorState.value) return "list-error";
  if (showEmptyListState.value) return "empty";
  if (showNoSelectionState.value) return "no-selection";
  return null;
});

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

const formattedLastSync = computed(() => {
  if (!props.lastSyncTime) return null;
  const date = new Date(props.lastSyncTime);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return t("time.justNow");
  if (diffMins < 60) return `${diffMins} ${t("time.minutesAgo")}`;
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)} ${t("time.hoursAgo")}`;
  return date.toLocaleDateString();
});

type DiffStatus = "same" | "modified" | "added" | "removed";

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


const getBaseField = (key: string) => props.timeTravelBasePayload?.fields?.[key];

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
  charViewField.value = field;
};

const closeCharView = () => {
  charViewOpen.value = false;
  charViewValue.value = "";
  charViewLabel.value = "";
  charViewField.value = null;
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

const markCopied = (path: string) => {
  copiedField.value = path;
  if (copiedTimer) {
    window.clearTimeout(copiedTimer);
  }
  copiedTimer = window.setTimeout(() => {
    copiedField.value = null;
    copiedTimer = null;
  }, 2000);
};

const handleCopy = async (field: FieldRow) => {
  if (!field.copyable) {
    return;
  }
  await props.copyField(field);
  markCopied(field.path);
};

const handleCopyKey = async (field: FieldRow) => {
  await props.copyField({
    ...field,
    value: field.key,
    path: `${field.path}:key`,
    copyable: true,
  });
  markCopied(`${field.path}:key`);
};

const handleCopyPair = async (field: FieldRow) => {
  await props.copyField({
    ...field,
    value: `${field.key}=${field.value}`,
    path: `${field.path}:pair`,
    copyable: true,
  });
  markCopied(`${field.path}:pair`);
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
});
</script>

<template>
  <section
    class="flex min-w-0 shrink-0 flex-col border-l border-[var(--border-color)] bg-[var(--bg-secondary)]"
  >
    <div class="p-3">
      <div class="relative">
        <svg class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          ref="searchInput"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] py-2 pl-9 pr-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] disabled:opacity-60"
          type="search"
          :value="props.query"
          :disabled="interactionsBlocked"
          :placeholder="t('items.searchPlaceholder')"
          @input="emit('update:query', ($event.target as HTMLInputElement).value)"
        />
      </div>
    </div>

    <div class="flex-1 overflow-auto px-4 pb-4">
      <div
        v-if="syncBusy"
        class="mb-2 flex items-center gap-2 text-[11px] text-[var(--text-tertiary)]"
      >
        <span class="h-2.5 w-2.5 animate-spin rounded-full border border-[var(--border-color)] border-t-[var(--text-secondary)]"></span>
        <span>{{ t("status.syncing") }}</span>
      </div>
      <ItemDetailsState
        v-if="detailsStateVariant"
        :variant="detailsStateVariant"
        :context-label="contextLabel"
        :list-error="listError"
        :filtered-items-count="filteredItemsCount"
        :create-shortcut="createShortcut"
        :search-shortcut="searchShortcut"
        :open-create-item="openCreateItem"
        :open-palette="openPalette"
        :system-state="systemState ?? undefined"
        :sync-error-message="syncErrorMessage"
        :formatted-last-sync="formattedLastSync"
        :pending-changes-count="pendingChangesCount"
        :on-sign-in="onSignIn"
        :on-unlock-personal="onUnlockPersonal"
        :on-reset-personal="onResetPersonal"
        :retry-sync="retrySync"
      />
      <div
        v-else-if="detailLoading"
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
      <div v-else-if="selectedItem" class="space-y-4">
        <ItemDetailsHeader
          :vault-name="vaultName"
          :breadcrumbs="breadcrumbs"
          :on-select-breadcrumb="selectBreadcrumb"
          :name="selectedItem.name"
          :type-id="selectedItem.type_id"
          :type-label="typeLabel"
          :updated-at-label="updatedAtLabel"
          :is-shared-vault="isSharedVault"
          :file-status-label="fileStatus?.label ?? null"
          :time-travel-active="timeTravelActive"
          :history-loading="historyLoading"
          :history-error="historyError"
          :open-time-travel="openTimeTravel"
          :close-time-travel="closeTimeTravel"
          :is-deleted="isDeleted"
          :is-conflict="isConflict"
          :restore-item="restoreItem"
          :resolve-conflict="resolveConflict"
          :open-edit-item="openEditItem"
          :delete-item="deleteItem"
          :purge-item="purgeItem"
          :copy-env="copyEnv"
          :copy-json="copyJson"
          :copy-raw="copyRaw"
        />

        <ItemDetailsTimeTravelPanel
          v-if="timeTravelActive"
          :history-entries="historyEntries"
          :history-loading="historyLoading"
          :history-error="historyError"
          :time-travel-index="timeTravelIndex"
          :time-travel-has-draft="timeTravelHasDraft"
          :restore-history-version="restoreHistoryVersion"
          :set-time-travel-index="setTimeTravelIndex"
        />

        <div>
          <ItemDetailsDiffView
            v-if="timeTravelActive"
            :current-fields="allCurrentFields"
            :base-fields="baseFieldsMap"
            :show-masked-value="showMaskedValue"
            :handle-copy="handleCopy"
            :copied-field="copiedField"
            :apply-time-travel-field="applyTimeTravelField"
            :format-field-label="formatFieldLabel"
          />
          <ItemKvTable
            v-else-if="isKvType"
            v-model:kv-search="kvSearch"
            :fields="kvFields"
            :time-travel-active="timeTravelActive"
            :alt-reveal-all="props.altRevealAll"
            :is-revealed="isRevealed"
            :toggle-reveal="toggleReveal"
            :open-link="openLink"
            :open-char-view="openCharView"
            :handle-copy="handleCopy"
            :handle-copy-key="handleCopyKey"
            :handle-copy-pair="handleCopyPair"
            :copied-field="copiedField"
            :copy-env="copyEnv"
            :copy-json="copyJson"
          />
          <ItemFieldList
            v-else
            :detail-sections="detailSections"
            :time-travel-active="timeTravelActive"
            :alt-reveal-all="props.altRevealAll"
            :is-revealed="isRevealed"
            :toggle-reveal="toggleReveal"
            :is-expanded="isExpanded"
            :is-long-value="isLongValue"
            :toggle-expanded="toggleExpanded"
            :open-link="openLink"
            :open-char-view="openCharView"
            :handle-copy="handleCopy"
            :copied-field="copiedField"
            :diff-status="diffStatus"
            :diff-previous-value="diffPreviousValue"
            :diff-previous-masked="diffPreviousMasked"
            :show-masked-value="showMaskedValue"
            :apply-time-travel-field="applyTimeTravelField"
            :format-field-label="formatFieldLabel"
          />
        </div>

        <div v-if="timeTravelActive && !historyEntries.length" class="mt-6 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] px-4 py-3 text-xs text-[var(--text-tertiary)]">
          {{ t("items.historyEmpty") }}
        </div>

      </div>

      <ItemCharViewModal
        :open="charViewOpen"
        :label="charViewLabel"
        :value="charViewValue"
        :can-copy="Boolean(charViewField?.copyable)"
        :on-copy="charViewField ? () => handleCopy(charViewField) : undefined"
        @close="closeCharView"
      />
    </div>
  </section>
</template>
