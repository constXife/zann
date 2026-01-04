<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import type { ItemSummary } from "../types";

type Category = { id: string; icon: string; label: string };

const { t } = useI18n();

const props = defineProps<{
  sidebarCollapsed: boolean;
  categories: Category[];
  selectedCategory: string | null;
  showOfflineBanner: boolean;
  showSessionExpiredBanner: boolean;
  showPersonalLockedBanner: boolean;
  showSyncErrorBanner: boolean;
  syncErrorMessage: string;
  onSignIn: () => void;
  onUnlockPersonal: () => void;
  onResetPersonal: () => void;
  lastSyncTime: string | null;
  retrySync: () => void;
  filteredItems: ItemSummary[];
  listLoading: boolean;
  totalListHeight: number;
  listOffset: number;
  visibleItems: ItemSummary[];
  selectedItemId: string | null;
  vaultContextLabel: string;
  isSharedVault: boolean;
  onListScroll: () => void;
  selectItem: (itemId: string) => void;
  openCreateItem: () => void;
  onEmptyTrash: () => void;
}>();

const emit = defineEmits<{ (e: "expandSidebar"): void }>();

const listContainer = ref<HTMLDivElement | null>(null);

defineExpose({ listContainer });

const selectedCategoryLabel = computed(() => {
  if (props.selectedCategory && props.selectedCategory !== "all") {
    return props.categories.find((cat) => cat.id === props.selectedCategory)?.label ?? "All";
  }
  return "All";
});

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

const showEmptyTrash = computed(
  () => props.selectedCategory === "trash" && props.filteredItems.length > 0,
);

const formatDeletedAt = (value?: string | null) => {
  if (!value) {
    return t("time.justNow");
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
};

const handleSelectItem = (itemId: string) => {
  console.info("[item_list] select_item", { itemId });
  props.selectItem(itemId);
};
</script>

<template>
  <section class="relative flex flex-col bg-[var(--bg-secondary)]">
    <button
      v-if="sidebarCollapsed"
      type="button"
      class="absolute left-[84px] top-[8px] rounded-lg p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors z-[60]"
      data-tauri-drag-region="false"
      @click="emit('expandSidebar')"
      :title="t('sidebar.expand')"
    >
      <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 4H5a1 1 0 00-1 1v14a1 1 0 001 1h4m0-16v16m0-16h10a1 1 0 011 1v14a1 1 0 01-1 1H9" />
      </svg>
    </button>

    <div
      v-if="showOfflineBanner"
      class="flex items-center gap-3 bg-amber-500/10 border-b border-amber-500/20 px-4 py-2.5"
      :class="{ 'pl-[130px]': sidebarCollapsed }"
    >
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/20">
        <svg class="h-4 w-4 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636a9 9 0 010 12.728M5.636 5.636a9 9 0 000 12.728M12 12v.01M8.464 15.536a5 5 0 010-7.072m7.072 0a5 5 0 010 7.072" />
          <line x1="4" y1="4" x2="20" y2="20" stroke-width="2" />
        </svg>
      </div>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-amber-700 dark:text-amber-300">
          {{ t("status.offline") }}
        </div>
        <div v-if="formattedLastSync" class="text-xs text-amber-600/80 dark:text-amber-400/80">
          {{ t("storage.lastSynced") }}: {{ formattedLastSync }}
        </div>
      </div>
      <button
        type="button"
        class="shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium text-amber-700 dark:text-amber-300 bg-amber-500/20 hover:bg-amber-500/30 transition-colors"
        @click="retrySync"
      >
        {{ t("common.retry") }}
      </button>
    </div>

    <div
      v-else-if="showSessionExpiredBanner"
      class="flex items-center gap-3 bg-red-500/10 border-b border-red-500/20 px-4 py-2.5"
      :class="{ 'pl-[130px]': sidebarCollapsed }"
    >
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/20">
        <svg class="h-4 w-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      </div>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-red-700 dark:text-red-300">
          {{ t("status.sessionExpired") }}
        </div>
      </div>
      <button
        type="button"
        class="shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 bg-red-500/20 hover:bg-red-500/30 transition-colors"
        @click="onSignIn"
      >
        {{ t("auth.signIn") }}
      </button>
    </div>

    <div
      v-else-if="showPersonalLockedBanner"
      class="flex items-center gap-3 bg-amber-500/10 border-b border-amber-500/20 px-4 py-2.5"
      :class="{ 'pl-[130px]': sidebarCollapsed }"
    >
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/20">
        <svg class="h-4 w-4 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-amber-700 dark:text-amber-300">
          {{ t("status.personalLocked") }}
        </div>
        <div class="text-xs text-amber-600/80 dark:text-amber-400/80">
          {{ t("status.personalLockedDesc") }}
        </div>
        <div class="text-xs text-amber-600/80 dark:text-amber-400/80">
          {{ t("errors.vault_key_mismatch") }}
        </div>
      </div>
      <div class="flex shrink-0 items-center gap-2">
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs font-medium text-amber-700 dark:text-amber-300 bg-amber-500/20 hover:bg-amber-500/30 transition-colors"
          @click="onUnlockPersonal"
        >
          {{ t("status.personalLockedAction") }}
        </button>
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 bg-red-500/20 hover:bg-red-500/30 transition-colors"
          @click="onResetPersonal"
        >
          {{ t("status.personalLockedReset") }}
        </button>
      </div>
    </div>

    <div
      v-else-if="showSyncErrorBanner"
      class="flex items-center gap-3 bg-red-500/10 border-b border-red-500/20 px-4 py-2.5"
      :class="{ 'pl-[130px]': sidebarCollapsed }"
    >
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/20">
        <svg class="h-4 w-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      </div>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-red-700 dark:text-red-300">
          {{ t("status.syncError") }}
        </div>
        <div class="text-xs text-red-600/80 dark:text-red-400/80 break-words">
          {{ syncErrorMessage }}
        </div>
      </div>
      <button
        type="button"
        class="shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 bg-red-500/20 hover:bg-red-500/30 transition-colors"
        @click="retrySync"
      >
        {{ t("common.retry") }}
      </button>
    </div>

    <div
      class="flex items-center justify-between px-4 pt-3 pb-2"
      :class="{ 'pl-[130px]': sidebarCollapsed }"
      data-tauri-drag-region
    >
      <div class="flex items-center gap-3">
        <div>
          <div class="flex items-center gap-2 text-sm font-semibold leading-none">
            <span>{{ selectedCategoryLabel }}</span>
            <span
              v-if="isSharedVault"
              class="rounded-full bg-category-security/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-category-security"
            >
              {{ t("nav.shared") }}
            </span>
          </div>
          <div class="text-xs text-[var(--text-secondary)] leading-none mt-1">{{ filteredItems.length }} items</div>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button
          v-if="showEmptyTrash"
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-2.5 py-1 text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          data-tauri-drag-region="false"
          @click="onEmptyTrash"
        >
          {{ t("items.emptyTrash") }}
        </button>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          data-tauri-drag-region="false"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12" />
          </svg>
        </button>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          data-tauri-drag-region="false"
          @click="openCreateItem"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v16m8-8H4" />
          </svg>
        </button>
      </div>
    </div>

    <div
      ref="listContainer"
      class="flex-1 overflow-auto"
      @scroll="onListScroll"
    >
      <div v-if="listLoading" class="space-y-1 p-2">
        <div
          v-for="n in 6"
          :key="n"
          class="h-14 rounded-lg bg-[var(--bg-hover)] animate-pulse"
        ></div>
      </div>
      <div v-if="!listLoading" :style="{ height: `${totalListHeight}px` }">
        <div :style="{ transform: `translateY(${listOffset}px)` }">
          <button
            v-for="item in visibleItems"
            :key="item.id"
            type="button"
            class="w-full px-4 py-2.5 text-left transition h-[72px]"
            :class="
              item.id === selectedItemId
                ? 'bg-[var(--bg-active)]'
                : 'hover:bg-[var(--bg-hover)]'
            "
            @click="handleSelectItem(item.id)"
          >
            <div class="flex items-center gap-3">
              <div
                class="flex h-9 w-9 items-center justify-center rounded-full text-white text-xs font-medium"
                :class="`bg-category-${item.type_id}`"
              >
                {{ item.name.charAt(0).toUpperCase() }}
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 min-w-0">
                  <div class="font-medium truncate">
                    {{ item.name }}
                  </div>
                  <span
                    v-if="item.sync_status === 'conflict'"
                    class="shrink-0 rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-600 dark:text-red-400"
                  >
                    {{ t("status.conflict") }}
                  </span>
                  <span
                    v-else-if="item.sync_status && item.sync_status !== 'synced'"
                    class="shrink-0 inline-flex items-center justify-center rounded-full bg-amber-500/15 p-1 text-amber-700 dark:text-amber-400"
                    :title="t('status.pending')"
                  >
                    <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 15a4 4 0 0 1 .5-8 5 5 0 0 1 9.6 1.5A3.5 3.5 0 0 1 17.5 15H7z" />
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v6m0 0l-2-2m2 2l2-2" />
                    </svg>
                  </span>
                </div>
                <div class="text-xs text-[var(--text-secondary)] truncate">
                  <template v-if="selectedCategory !== 'trash'">
                    {{ item.path || 'no username' }}
                  </template>
                  <template v-else>
                    {{ t("items.deletedAt") }}: {{ formatDeletedAt(item.deleted_at) }}
                    <span v-if="isSharedVault" class="ml-1">
                      · {{ t("items.deletedBy") }}:
                      {{ item.deleted_by || t("items.deletedByUnknown") }}
                    </span>
                  </template>
                </div>
              </div>
            </div>
          </button>
        </div>
      </div>
      <div
        v-if="!listLoading && !filteredItems.length"
        class="mx-6 my-8 flex flex-col items-center justify-center rounded-xl border border-dashed border-[var(--border-color)] px-6 py-12 text-[var(--text-secondary)]"
      >
        <svg class="h-12 w-12 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
        </svg>
        <div class="mt-3 text-sm text-center">{{ t('items.noItems') }}</div>
        <button
          type="button"
          class="mt-3 rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-3 py-1.5 text-xs text-white transition-colors"
          @click="openCreateItem"
        >
          {{ t('onboarding.createItem') }}
        </button>
      </div>
    </div>
  </section>
</template>
