<script setup lang="ts">
import { ref, computed, watch } from "vue";
import type { StorageSummary, StorageInfo } from "../types";
import { StorageKind } from "../constants/enums";

type Translator = (key: string, params?: Record<string, unknown>) => string;

const props = defineProps<{
  open: boolean;
  storages: StorageSummary[];
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  reveal: [storageId: string];
  disconnect: [storageId: string];
  delete: [storageId: string];
  addStorage: [];
  getInfo: [storageId: string, callback: (info: StorageInfo | null) => void];
}>();

const storageInfoMap = ref<Map<string, StorageInfo | null>>(new Map());
const loadingInfo = ref<Set<string>>(new Set());

const localStorages = computed(() =>
  props.storages.filter((s) => s.kind === StorageKind.LocalOnly),
);
const remoteStorages = computed(() =>
  props.storages.filter((s) => s.kind === StorageKind.Remote),
);

watch(
  () => props.open,
  async (open) => {
    if (open) {
      for (const storage of props.storages) {
        if (!storageInfoMap.value.has(storage.id)) {
          loadingInfo.value.add(storage.id);
          emit("getInfo", storage.id, (info) => {
            storageInfoMap.value.set(storage.id, info);
            loadingInfo.value.delete(storage.id);
          });
        }
      }
    }
  }
);

const getInfo = (storageId: string): StorageInfo | null => {
  return storageInfoMap.value.get(storageId) ?? null;
};

const formatFileSize = (bytes: number | null | undefined): string => {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDate = (isoDate: string | null | undefined): string => {
  if (!isoDate) return "";
  const date = new Date(isoDate);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins} min ago`;
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)} hours ago`;
  return date.toLocaleDateString();
};
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[110]"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-lg rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl max-h-[80vh] overflow-y-auto">
      <!-- Header -->
      <div class="flex items-center justify-between gap-3">
        <h3 class="text-lg font-semibold">{{ t("storage.settings") }}</h3>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="mt-6 space-y-6">
        <!-- Local Vaults Section -->
        <div v-if="localStorages.length > 0">
          <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-3">
            {{ t("storage.localVaults") }}
          </h4>
          <div class="space-y-3">
            <div
              v-for="storage in localStorages"
              :key="storage.id"
              class="rounded-lg bg-[var(--bg-tertiary)] p-4"
            >
              <div class="flex items-start gap-3">
                <!-- Icon -->
                <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-hover)]">
                  <svg class="h-5 w-5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                  </svg>
                </div>

                <!-- Info -->
                <div class="flex-1 min-w-0">
                  <div class="font-medium">{{ storage.name }}</div>
                  <div class="text-xs text-[var(--text-tertiary)] truncate" :title="getInfo(storage.id)?.file_path ?? ''">
                    {{ getInfo(storage.id)?.file_path?.replace(/^.*\//, '') ?? '...' }}
                  </div>
                  <div class="text-xs text-[var(--text-tertiary)] mt-0.5">
                    <template v-if="getInfo(storage.id)?.file_size">
                      {{ formatFileSize(getInfo(storage.id)?.file_size) }}
                    </template>
                    <template v-if="getInfo(storage.id)?.last_modified">
                      &bull; {{ formatDate(getInfo(storage.id)?.last_modified) }}
                    </template>
                  </div>
                </div>
              </div>

              <!-- Actions -->
              <div class="mt-3 flex gap-2 flex-wrap">
                <button
                  type="button"
                  class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                  @click="emit('reveal', storage.id)"
                >
                  {{ t("storage.reveal") }}
                </button>
                <button
                  type="button"
                  class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                  @click="emit('disconnect', storage.id)"
                >
                  {{ t("storage.disconnect") }}
                </button>
                <button
                  type="button"
                  class="rounded-lg px-3 py-1.5 text-xs font-medium text-category-security bg-category-security/10 hover:bg-category-security/20 transition-colors"
                  @click="emit('delete', storage.id)"
                >
                  {{ t("storage.delete") }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Remote Servers Section -->
        <div v-if="remoteStorages.length > 0">
          <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-3">
            {{ t("storage.remoteServers") }}
          </h4>
          <div class="space-y-3">
            <div
              v-for="storage in remoteStorages"
              :key="storage.id"
              class="rounded-lg bg-[var(--bg-tertiary)] p-4"
            >
              <div class="flex items-start gap-3">
                <!-- Icon -->
                <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-hover)]">
                  <svg class="h-5 w-5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                  </svg>
                </div>

                <!-- Info -->
                <div class="flex-1 min-w-0">
                  <div class="font-medium">{{ storage.server_name ?? storage.name }}</div>
                  <div class="text-xs text-[var(--text-tertiary)]">
                    {{ storage.account_subject ?? storage.server_url }}
                  </div>
                  <div v-if="getInfo(storage.id)?.last_synced" class="text-xs text-[var(--text-tertiary)] mt-0.5">
                    {{ t("storage.lastSynced") }}: {{ formatDate(getInfo(storage.id)?.last_synced) }}
                  </div>
                </div>
              </div>

              <!-- Actions -->
              <div class="mt-3 flex gap-2 flex-wrap">
                <button
                  type="button"
                  class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                  @click="emit('disconnect', storage.id)"
                >
                  {{ t("storage.disconnect") }}
                </button>
                <button
                  type="button"
                  class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                  @click="emit('delete', storage.id)"
                >
                  {{ t("storage.eraseCache") }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Empty state -->
        <div v-if="storages.length === 0" class="text-center py-8 text-[var(--text-secondary)]">
          No storages configured.
        </div>
      </div>

      <!-- Footer -->
      <div class="mt-6 flex justify-between">
        <button
          type="button"
          class="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium text-[var(--accent)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="emit('addStorage')"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          {{ t("storage.addStorage") }}
        </button>
        <button
          type="button"
          class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          {{ t("common.close") }}
        </button>
      </div>
    </div>
  </div>
</template>
