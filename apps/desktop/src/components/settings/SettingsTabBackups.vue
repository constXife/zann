<script setup lang="ts">
import { ref } from "vue";
import type { PlainBackupExportResponse, PlainBackupImportResponse } from "../../types";

type Translator = (key: string) => string;

const props = defineProps<{
  t: Translator;
  onExportPlain: (path?: string | null) => Promise<PlainBackupExportResponse | null>;
  onImportPlain: (path: string) => Promise<PlainBackupImportResponse | null>;
}>();

const exportPath = ref("");
const importPath = ref("");
const exportBusy = ref(false);
const importBusy = ref(false);
const exportResult = ref<PlainBackupExportResponse | null>(null);
const importResult = ref<PlainBackupImportResponse | null>(null);
const exportError = ref("");
const importError = ref("");

const runExport = async () => {
  if (exportBusy.value) return;
  exportBusy.value = true;
  exportError.value = "";
  exportResult.value = null;
  const result = await props.onExportPlain(exportPath.value || null);
  exportBusy.value = false;
  if (!result) {
    exportError.value = props.t("settings.backups.exportFailed");
    return;
  }
  exportResult.value = result;
};

const runImport = async () => {
  if (importBusy.value) return;
  importError.value = "";
  importResult.value = null;
  if (!importPath.value.trim()) {
    importError.value = props.t("settings.backups.importPathRequired");
    return;
  }
  importBusy.value = true;
  const result = await props.onImportPlain(importPath.value.trim());
  importBusy.value = false;
  if (!result) {
    importError.value = props.t("settings.backups.importFailed");
    return;
  }
  importResult.value = result;
};
</script>

<template>
  <div class="space-y-6">
    <div class="rounded-lg bg-amber-500/10 border border-amber-500/20 p-4">
      <div class="flex items-start gap-3">
        <svg class="h-5 w-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <h4 class="font-medium text-amber-600 dark:text-amber-400">{{ t("settings.backups.plainWarningTitle") }}</h4>
          <p class="text-sm text-[var(--text-secondary)] mt-1">
            {{ t("settings.backups.plainWarningDesc") }}
          </p>
        </div>
      </div>
    </div>

    <div class="rounded-lg border border-[var(--border-color)] p-4 space-y-3">
      <div>
        <h4 class="font-medium">{{ t("settings.backups.exportTitle") }}</h4>
        <p class="text-sm text-[var(--text-secondary)]">{{ t("settings.backups.exportDesc") }}</p>
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">{{ t("settings.backups.exportPathLabel") }}</label>
        <input
          v-model="exportPath"
          type="text"
          :placeholder="t('settings.backups.exportPathPlaceholder')"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-amber-500"
        />
      </div>
      <div class="flex items-center gap-3">
        <button
          type="button"
          class="rounded-lg bg-amber-500 px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          :disabled="exportBusy"
          @click="runExport"
        >
          {{ exportBusy ? t("common.loading") : t("settings.backups.exportAction") }}
        </button>
        <p v-if="exportError" class="text-xs text-category-security">{{ exportError }}</p>
      </div>
      <div v-if="exportResult" class="rounded-lg bg-[var(--bg-tertiary)] p-3 text-xs text-[var(--text-secondary)] space-y-1">
        <div>{{ t("settings.backups.exportedPath", { path: exportResult.path }) }}</div>
        <div>{{ t("settings.backups.exportedCounts", { storages: exportResult.storages_count, vaults: exportResult.vaults_count, items: exportResult.items_count }) }}</div>
      </div>
    </div>

    <div class="rounded-lg border border-[var(--border-color)] p-4 space-y-3">
      <div>
        <h4 class="font-medium">{{ t("settings.backups.importTitle") }}</h4>
        <p class="text-sm text-[var(--text-secondary)]">{{ t("settings.backups.importDesc") }}</p>
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">{{ t("settings.backups.importPathLabel") }}</label>
        <input
          v-model="importPath"
          type="text"
          :placeholder="t('settings.backups.importPathPlaceholder')"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-amber-500"
        />
      </div>
      <div class="flex items-center gap-3">
        <button
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-4 py-2 text-sm font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          :disabled="importBusy"
          @click="runImport"
        >
          {{ importBusy ? t("common.loading") : t("settings.backups.importAction") }}
        </button>
        <p v-if="importError" class="text-xs text-category-security">{{ importError }}</p>
      </div>
      <div v-if="importResult" class="rounded-lg bg-[var(--bg-tertiary)] p-3 text-xs text-[var(--text-secondary)] space-y-1">
        <div>{{ t("settings.backups.importedCounts", { imported: importResult.imported_items, skipped: importResult.skipped_existing }) }}</div>
        <div>{{ t("settings.backups.importedSkippedMissing", { missingStorages: importResult.skipped_missing_storage, missingVaults: importResult.skipped_missing_vault, deleted: importResult.skipped_deleted }) }}</div>
      </div>
    </div>

    <div class="rounded-lg bg-[var(--bg-tertiary)] p-4">
      <div class="flex items-start gap-3">
        <svg class="h-5 w-5 text-[var(--text-tertiary)] shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p class="text-sm text-[var(--text-tertiary)]">
          {{ t("settings.backups.singleWriterWarning") }}
        </p>
      </div>
    </div>
  </div>
</template>
