<script setup lang="ts">
import { ref, computed, watch } from "vue";
import type { StorageInfo } from "../types";

type Translator = (key: string, params?: Record<string, unknown>) => string;

const props = defineProps<{
  open: boolean;
  storage: StorageInfo | null;
  busy: boolean;
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  delete: [moveToTrash: boolean];
  disconnect: [eraseCache: boolean];
}>();

const confirmText = ref("");
const eraseCache = ref(false);

watch(
  () => props.open,
  (open) => {
    if (!open) {
      confirmText.value = "";
      eraseCache.value = false;
    }
  }
);

const isLocal = computed(() => props.storage?.kind === "local_only");
const canConfirm = computed(() => isLocal.value ? confirmText.value === "DELETE" : true);

const formatFileSize = (bytes: number | null | undefined): string => {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDate = (isoDate: string | null | undefined): string => {
  if (!isoDate) return "";
  return new Date(isoDate).toLocaleString();
};

const onDelete = (moveToTrash: boolean) => {
  emit("delete", moveToTrash);
};

const onDisconnect = () => {
  emit("disconnect", eraseCache.value);
};
</script>

<template>
  <div
    v-if="open && storage"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[110]"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <!-- Header -->
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="flex h-10 w-10 items-center justify-center rounded-full bg-category-security/20">
            <svg class="h-5 w-5 text-category-security" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold">
            {{ isLocal ? t("storage.deleteTitle") : t("storage.disconnectTitle") }}
          </h3>
        </div>
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

      <div class="mt-4 space-y-4">
        <!-- Warning message -->
        <p class="text-sm text-[var(--text-secondary)]">
          {{ isLocal ? t("storage.deleteWarning") : t("storage.disconnectWarning") }}
        </p>

        <!-- Storage info -->
        <div class="rounded-lg bg-[var(--bg-tertiary)] p-3 space-y-2">
          <template v-if="isLocal">
            <div class="flex justify-between text-sm">
              <span class="text-[var(--text-secondary)]">{{ t("storage.fileInfo") }}</span>
              <span class="font-mono text-xs truncate max-w-[200px]" :title="storage.file_path ?? ''">
                {{ storage.file_path?.split('/').pop() }}
              </span>
            </div>
            <div v-if="storage.file_size" class="flex justify-between text-sm">
              <span class="text-[var(--text-secondary)]">{{ t("storage.sizeInfo") }}</span>
              <span>{{ formatFileSize(storage.file_size) }}</span>
            </div>
            <div v-if="storage.last_modified" class="flex justify-between text-sm">
              <span class="text-[var(--text-secondary)]">{{ t("storage.modifiedInfo") }}</span>
              <span>{{ formatDate(storage.last_modified) }}</span>
            </div>
          </template>
          <template v-else>
            <div class="flex justify-between text-sm">
              <span class="text-[var(--text-secondary)]">{{ t("storage.serverInfo") }}</span>
              <span>{{ storage.server_name ?? storage.server_url }}</span>
            </div>
            <div v-if="storage.account_subject" class="flex justify-between text-sm">
              <span class="text-[var(--text-secondary)]">{{ t("storage.accountInfo") }}</span>
              <span>{{ storage.account_subject }}</span>
            </div>
          </template>
        </div>

        <!-- Remote not affected notice (for local) -->
        <p v-if="isLocal" class="text-sm text-[var(--text-tertiary)]">
          {{ t("storage.remoteNotAffected") }}
        </p>

        <!-- Confirmation input for local -->
        <div v-if="isLocal" class="space-y-2">
          <label class="block text-sm font-medium">{{ t("storage.confirmDelete") }}</label>
          <input
            v-model="confirmText"
            type="text"
            placeholder="DELETE"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-category-security"
          />
        </div>

        <!-- Erase cache checkbox for remote -->
        <label v-if="!isLocal" class="flex items-center gap-2 text-sm cursor-pointer">
          <input
            v-model="eraseCache"
            type="checkbox"
            class="rounded border-[var(--border)] bg-[var(--bg-tertiary)]"
          />
          <span>{{ t("storage.alsoEraseCache") }}</span>
        </label>
      </div>

      <!-- Actions -->
      <div class="mt-6 flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          {{ t("storage.cancel") }}
        </button>

        <template v-if="isLocal">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium bg-[var(--bg-tertiary)] hover:bg-[var(--bg-hover)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy || !canConfirm"
            @click="onDelete(true)"
          >
            {{ t("storage.moveToTrash") }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-category-security px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy || !canConfirm"
            @click="onDelete(false)"
          >
            <svg v-if="busy" class="inline-block h-4 w-4 animate-spin mr-1" viewBox="0 0 24 24" fill="none">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
            </svg>
            {{ t("common.delete") }}
          </button>
        </template>

        <button
          v-else
          type="button"
          class="rounded-lg bg-category-security px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          :disabled="busy"
          @click="onDisconnect"
        >
          <svg v-if="busy" class="inline-block h-4 w-4 animate-spin mr-1" viewBox="0 0 24 24" fill="none">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
          </svg>
          {{ t("storage.disconnect") }}
        </button>
      </div>
    </div>
  </div>
</template>
