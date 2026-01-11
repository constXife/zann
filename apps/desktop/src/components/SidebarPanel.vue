<script setup lang="ts">
import CategoryIcon from "./CategoryIcon.vue";
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import type { FolderNode, StorageSummary, VaultSummary } from "../types";

type Category = { id: string; icon: string; label: string };
type SyncStatus = "idle" | "syncing" | "synced" | "error";

const { t } = useI18n();

const props = defineProps<{
  onCollapse: () => void;
  storageDropdownOpen: boolean;
  storages: StorageSummary[];
  remoteStorages: StorageSummary[];
  localStorage?: StorageSummary;
  showLocalSection: boolean;
  hasLocalVaults: boolean;
  selectedStorageId: string;
  currentStorage?: StorageSummary;
  getSyncStatus: (storageId: string) => SyncStatus;
  storageSyncErrors: Map<string, string>;
  lastSyncTime: string | null;
  toggleStorageDropdown: () => void;
  closeStorageDropdown: () => void;
  openAddStorageWizard: () => void;
  openStorageSettings: () => void;
  openCreateLocalVault: () => void;
  openSettings: (tab?: "general" | "accounts") => void;
  switchStorage: (storageId: string) => void;
  vaultDropdownOpen: boolean;
  vaults: VaultSummary[];
  listLoading: boolean;
  personalVaults: VaultSummary[];
  sharedVaults: VaultSummary[];
  selectedVaultId: string | null;
  toggleVaultDropdown: () => void;
  closeVaultDropdown: () => void;
  switchVault: (vaultId: string) => void;
  openCreateVault: () => void;
  categories: Category[];
  categoryCounts: Record<string, number>;
  selectedCategory: string | null;
  selectCategory: (categoryId: string) => void;
  folderTree: FolderNode[];
  expandedFolders: Set<string>;
  selectedFolder: string | null;
  itemsWithoutFolder: number;
  toggleFolder: (path: string) => void;
  openFolderMenu: (event: MouseEvent, folder: FolderNode) => void;
  selectFolder: (path: string | null) => void;
}>();

const staleSyncLevel = computed(() => {
  if (!props.lastSyncTime || props.currentStorage?.kind !== "remote") {
    return null;
  }
  const last = new Date(props.lastSyncTime);
  if (Number.isNaN(last.getTime())) {
    return null;
  }
  const diffDays = (Date.now() - last.getTime()) / 86400000;
  if (diffDays >= 30) {
    return "critical";
  }
  if (diffDays >= 7) {
    return "warning";
  }
  return null;
});

const staleSyncTitle = computed(() => {
  if (!props.lastSyncTime) {
    return "";
  }
  const last = new Date(props.lastSyncTime);
  if (Number.isNaN(last.getTime())) {
    return "";
  }
  return `${t("storage.lastSynced")}: ${last.toLocaleDateString()}`;
});
</script>

<template>
  <aside
    class="relative flex flex-col border-r border-[var(--border-color)] bg-[var(--bg-primary)] transition-all duration-200 overflow-hidden"
  >
    <button
      type="button"
      class="absolute right-3 top-[8px] z-[60] rounded-lg p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
      @click="onCollapse"
      :title="t('sidebar.collapse')"
      data-tauri-drag-region="false"
    >
      <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 4H5a1 1 0 00-1 1v14a1 1 0 001 1h4m0-16v16m0-16h10a1 1 0 011 1v14a1 1 0 01-1 1H9" />
      </svg>
    </button>

    <div
      class="relative flex items-center gap-3 p-3 pt-12"
      data-tauri-drag-region
    >
      <button
        type="button"
        class="flex h-9 w-9 items-center justify-center rounded-full bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
        @click="openSettings('accounts')"
        :title="t('common.settings')"
        data-tauri-drag-region="false"
      >
        <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
      </button>

      <button
        type="button"
        class="flex-1 min-w-0 flex items-center gap-2 rounded-lg px-2 py-1.5 -ml-2 hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors text-left"
        @click.stop="toggleStorageDropdown"
        data-tauri-drag-region="false"
      >
        <span class="flex-shrink-0 text-sm">
          {{ currentStorage?.kind === 'remote' ? '☁️' : '📁' }}
        </span>

        <div class="flex-1 min-w-0">
          <div class="text-sm font-medium truncate">
            {{ currentStorage?.name ?? t('nav.vaults') }}
          </div>
          <div class="text-xs text-[var(--text-secondary)] truncate">
            {{ currentStorage?.kind === 'local_only' ? t('storage.localVault') : (currentStorage?.server_name ?? currentStorage?.server_url ?? t('nav.sections')) }}
          </div>
        </div>

        <span v-if="currentStorage?.kind === 'remote'" class="flex-shrink-0">
          <svg
            v-if="getSyncStatus(currentStorage.id) === 'syncing'"
            class="h-4 w-4 animate-spin text-[var(--accent)]"
            viewBox="0 0 24 24"
            fill="none"
          >
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
          </svg>
          <svg
            v-else-if="getSyncStatus(currentStorage.id) === 'error'"
            class="h-4 w-4 text-category-security"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            :title="storageSyncErrors.get(currentStorage.id)"
            data-testid="sync-status-error"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <svg
            v-else-if="staleSyncLevel"
            class="h-4 w-4"
            :class="staleSyncLevel === 'critical' ? 'text-red-500' : 'text-amber-500'"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            :title="staleSyncTitle"
            data-testid="sync-status-stale"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <svg
            v-else-if="getSyncStatus(currentStorage.id) === 'synced'"
            class="h-4 w-4 text-green-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            data-testid="sync-status-synced"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
        </span>

        <svg
          class="h-4 w-4 text-[var(--text-secondary)] flex-shrink-0 transition-transform duration-200"
          :class="{ 'rotate-180': storageDropdownOpen }"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <div
        v-if="storageDropdownOpen"
        class="absolute left-3 right-3 top-full mt-1 z-50 rounded-xl bg-[var(--bg-secondary)] border border-[var(--border-color)] shadow-xl overflow-hidden"
      >
        <div class="max-h-80 overflow-y-auto py-1">
          <!-- SERVERS section -->
          <template v-if="remoteStorages.length > 0">
            <div class="px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-[var(--text-secondary)]">
              {{ t('storage.servers') }}
            </div>
            <button
              v-for="storage in remoteStorages"
              :key="storage.id"
              type="button"
              class="w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors"
              :class="
                storage.id === selectedStorageId
                  ? 'bg-[var(--bg-active)]'
                  : 'hover:bg-[var(--bg-hover)]'
              "
              @click="switchStorage(storage.id)"
            >
              <span class="text-sm flex-shrink-0">☁️</span>

              <div class="flex-1 min-w-0">
                <div class="text-sm font-medium truncate">
                  {{ storage.name }}
                </div>
                <div class="text-xs text-[var(--text-secondary)] truncate">
                  {{ storage.account_subject ?? storage.server_url }}
                </div>
              </div>

              <span class="flex-shrink-0">
                <svg
                  v-if="getSyncStatus(storage.id) === 'syncing'"
                  class="h-4 w-4 animate-spin text-[var(--accent)]"
                  viewBox="0 0 24 24"
                  fill="none"
                >
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
                </svg>
                <svg
                  v-else-if="getSyncStatus(storage.id) === 'synced'"
                  class="h-4 w-4 text-green-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
                <svg
                  v-else-if="getSyncStatus(storage.id) === 'error'"
                  class="h-4 w-4 text-category-security"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  :title="storageSyncErrors.get(storage.id)"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </span>

              <svg
                v-if="storage.id === selectedStorageId"
                class="h-4 w-4 text-[var(--accent)] flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </button>
          </template>

          <!-- No servers message -->
          <div
            v-if="remoteStorages.length === 0"
            class="px-3 py-3 text-sm text-[var(--text-secondary)] text-center"
          >
            {{ t('storage.noServers') }}
          </div>

          <!-- Add Server button -->
          <button
            type="button"
            class="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-[var(--bg-hover)] transition-colors text-[var(--accent)]"
            @click="openAddStorageWizard"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            <span class="text-sm font-medium">{{ t('storage.addServer') }}</span>
          </button>

          <!-- ON THIS DEVICE section (only if has local vaults) -->
          <template v-if="showLocalSection && localStorage">
            <div class="border-t border-[var(--border-color)] my-1"></div>
            <div class="px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-[var(--text-secondary)]">
              {{ t('storage.onThisDevice') }}
            </div>
            <button
              type="button"
              class="w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors"
              :class="
                localStorage.id === selectedStorageId
                  ? 'bg-[var(--bg-active)]'
                  : 'hover:bg-[var(--bg-hover)]'
              "
              @click="switchStorage(localStorage.id)"
            >
              <span class="text-sm flex-shrink-0">📱</span>

              <div class="flex-1 min-w-0">
                <div class="text-sm font-medium truncate">
                  {{ localStorage.name }}
                </div>
                <div class="text-xs text-[var(--text-secondary)] truncate">
                  {{ t('storage.notSynced') }}
                </div>
              </div>

              <svg
                v-if="localStorage.id === selectedStorageId"
                class="h-4 w-4 text-[var(--accent)] flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </button>
          </template>

          <!-- Create local vault (if no local vaults yet) -->
          <template v-if="!showLocalSection">
            <div class="border-t border-[var(--border-color)] my-1"></div>
            <button
              type="button"
              class="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-[var(--bg-hover)] transition-colors text-[var(--text-secondary)]"
              @click="openCreateLocalVault"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
              </svg>
              <span class="text-sm">
                {{ hasLocalVaults ? t('storage.showLocalVaults') : t('storage.createLocalVault') }}
              </span>
            </button>
          </template>
        </div>

        <div class="border-t border-[var(--border-color)]"></div>

        <button
          type="button"
          class="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-[var(--bg-hover)] transition-colors text-[var(--text-secondary)]"
          @click="openStorageSettings"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          <span class="text-sm font-medium">{{ t('storage.settings') }}</span>
        </button>
      </div>
    </div>

    <div
      v-if="storageDropdownOpen"
      class="fixed inset-0 z-40"
      @click="closeStorageDropdown"
    ></div>

    <div class="relative px-3 pb-2">
      <button
        type="button"
        class="w-full flex items-center gap-2 rounded-lg px-3 py-2 hover:bg-[var(--bg-hover)] transition-colors text-left"
        @click.stop="toggleVaultDropdown"
        data-tauri-drag-region="false"
      >
        <span class="flex-shrink-0 text-sm">
          {{ selectedVaultId && sharedVaults.some(v => v.id === selectedVaultId) ? '👥' : '👤' }}
        </span>

        <div class="flex-1 min-w-0">
          <div class="text-sm font-medium truncate">
            {{ vaults.find(v => v.id === selectedVaultId)?.name ?? t('nav.vaults') }}
          </div>
        </div>

        <svg
          class="h-4 w-4 text-[var(--text-secondary)] flex-shrink-0 transition-transform duration-200"
          :class="{ 'rotate-180': vaultDropdownOpen }"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <div
        v-if="vaultDropdownOpen"
        class="absolute left-3 right-3 top-full mt-1 z-50 rounded-xl bg-[var(--bg-secondary)] border border-[var(--border-color)] shadow-xl overflow-hidden"
      >
        <div class="max-h-64 overflow-y-auto py-1">
          <template v-if="currentStorage?.personal_vaults_enabled && personalVaults.length">
            <div class="px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-[var(--text-secondary)]">
              {{ t('nav.personal') }}
            </div>
            <button
              v-for="vault in personalVaults"
              :key="vault.id"
              type="button"
              class="w-full flex items-center gap-3 px-3 py-2 text-left transition-colors"
              :class="
                vault.id === selectedVaultId
                  ? 'bg-[var(--bg-active)]'
                  : 'hover:bg-[var(--bg-hover)]'
              "
              @click="switchVault(vault.id)"
            >
              <span class="text-sm flex-shrink-0">👤</span>
              <span class="flex-1 text-sm truncate">{{ vault.name }}</span>
              <svg
                v-if="vault.id === selectedVaultId"
                class="h-4 w-4 text-[var(--accent)] flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </button>
          </template>

          <template v-if="sharedVaults.length">
            <div class="px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-[var(--text-secondary)]">
              {{ t('nav.shared') }}
            </div>
            <button
              v-for="vault in sharedVaults"
              :key="vault.id"
              type="button"
              class="w-full flex items-center gap-3 px-3 py-2 text-left transition-colors"
              :class="
                vault.id === selectedVaultId
                  ? 'bg-[var(--bg-active)]'
                  : 'hover:bg-[var(--bg-hover)]'
              "
              @click="switchVault(vault.id)"
            >
              <span class="text-sm flex-shrink-0">👥</span>
              <span class="flex-1 text-sm truncate">{{ vault.name }}</span>
              <svg
                v-if="vault.id === selectedVaultId"
                class="h-4 w-4 text-[var(--accent)] flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
            </button>
          </template>

          <div
            v-if="!vaults.length && !listLoading"
            class="px-3 py-2 text-xs text-[var(--text-secondary)]"
          >
            {{ t('onboarding.createFirstVault') }}
          </div>
        </div>

        <div class="border-t border-[var(--border-color)]"></div>

        <button
          type="button"
          class="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-[var(--bg-hover)] transition-colors text-[var(--accent)]"
          @click="openCreateVault"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          <span class="text-sm font-medium">{{ t('onboarding.createVault') }}</span>
        </button>
      </div>
    </div>

    <div
      v-if="vaultDropdownOpen"
      class="fixed inset-0 z-40"
      @click="closeVaultDropdown"
    ></div>

    <div class="space-y-0.5 px-2 py-2">
      <button
        v-for="cat in categories"
        :key="cat.id"
        type="button"
        class="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors"
        :class="selectedCategory === cat.id || (!selectedCategory && cat.id === 'all')
          ? 'bg-[var(--bg-active)] font-medium'
          : 'hover:bg-[var(--bg-hover)]'"
        @click="selectCategory(cat.id)"
      >
        <span
          class="flex h-6 w-6 items-center justify-center rounded-md"
          :class="{
            'bg-category-all/15 text-category-all': cat.id === 'all',
            'bg-category-login/15 text-category-login': cat.id === 'login',
            'bg-category-note/15 text-category-note': cat.id === 'note',
            'bg-category-card/15 text-category-card': cat.id === 'card',
            'bg-category-identity/15 text-category-identity': cat.id === 'identity',
            'bg-category-api/15 text-category-api': cat.id === 'api',
            'bg-category-kv/15 text-category-kv': cat.id === 'kv',
            'bg-category-infra/15 text-category-infra': cat.id === 'infra',
            'bg-category-security/15 text-category-security': cat.id === 'trash',
          }"
        >
          <CategoryIcon :icon="cat.icon" class="h-3.5 w-3.5" />
        </span>
        <span class="flex-1">{{ cat.label }}</span>
        <span class="text-xs text-[var(--text-secondary)] tabular-nums">{{ categoryCounts[cat.id] }}</span>
      </button>
    </div>

    <div class="px-2 py-2 border-t border-[var(--border-color)]">
      <div class="px-3 py-1">
        <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">
          {{ t('nav.folders') }}
        </span>
      </div>

      <button
        type="button"
        class="w-full flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm transition-colors"
        :class="selectedFolder === '' ? 'bg-[var(--bg-active)] font-medium' : 'hover:bg-[var(--bg-hover)]'"
        @click="selectFolder(selectedFolder === '' ? null : '')"
      >
        <span class="w-4 text-center text-[var(--text-secondary)]">📄</span>
        <span class="flex-1 truncate">{{ t('nav.noFolder') }}</span>
        <span class="text-xs text-[var(--text-secondary)] tabular-nums">{{ itemsWithoutFolder }}</span>
      </button>

      <template v-for="folder0 in folderTree" :key="folder0.path">
        <button
          type="button"
          class="w-full flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm transition-colors"
          :class="selectedFolder === folder0.path ? 'bg-[var(--bg-active)] font-medium' : 'hover:bg-[var(--bg-hover)]'"
          @click="selectFolder(selectedFolder === folder0.path ? null : folder0.path)"
          @contextmenu="openFolderMenu($event, folder0)"
        >
          <span
            v-if="folder0.children.length"
            class="w-4 text-center text-xs text-[var(--text-secondary)] cursor-pointer select-none"
            @click.stop="toggleFolder(folder0.path)"
          >{{ expandedFolders.has(folder0.path) ? '▼' : '▶' }}</span>
          <span v-else class="w-4"></span>
          <span class="text-[var(--text-secondary)]">📁</span>
          <span class="flex-1 truncate">{{ folder0.name }}</span>
          <span class="text-xs text-[var(--text-secondary)] tabular-nums">{{ folder0.totalCount }}</span>
        </button>

        <template v-if="expandedFolders.has(folder0.path)">
          <template v-for="folder1 in folder0.children" :key="folder1.path">
            <button
              type="button"
              class="w-full flex items-center gap-2 rounded-lg py-1.5 text-sm transition-colors"
              style="padding-left: 24px; padding-right: 12px;"
              :class="selectedFolder === folder1.path ? 'bg-[var(--bg-active)] font-medium' : 'hover:bg-[var(--bg-hover)]'"
              @click="selectFolder(selectedFolder === folder1.path ? null : folder1.path)"
              @contextmenu="openFolderMenu($event, folder1)"
            >
              <span
                v-if="folder1.children.length"
                class="w-4 text-center text-xs text-[var(--text-secondary)] cursor-pointer select-none"
                @click.stop="toggleFolder(folder1.path)"
              >{{ expandedFolders.has(folder1.path) ? '▼' : '▶' }}</span>
              <span v-else class="w-4"></span>
              <span class="text-[var(--text-secondary)]">📁</span>
              <span class="flex-1 truncate">{{ folder1.name }}</span>
              <span class="text-xs text-[var(--text-secondary)] tabular-nums">{{ folder1.totalCount }}</span>
            </button>

            <template v-if="expandedFolders.has(folder1.path)">
              <button
                v-for="folder2 in folder1.children"
                :key="folder2.path"
                type="button"
                class="w-full flex items-center gap-2 rounded-lg py-1.5 text-sm transition-colors"
                style="padding-left: 36px; padding-right: 12px;"
                :class="selectedFolder === folder2.path ? 'bg-[var(--bg-active)] font-medium' : 'hover:bg-[var(--bg-hover)]'"
                @click="selectFolder(selectedFolder === folder2.path ? null : folder2.path)"
                @contextmenu="openFolderMenu($event, folder2)"
              >
                <span class="w-4"></span>
                <span class="text-[var(--text-secondary)]">📁</span>
                <span class="flex-1 truncate">{{ folder2.name }}</span>
                <span class="text-xs text-[var(--text-secondary)] tabular-nums">{{ folder2.totalCount }}</span>
              </button>
            </template>
          </template>
        </template>
      </template>
    </div>
  </aside>
</template>
