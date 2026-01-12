<script setup lang="ts">
import { ref, watch, computed } from "vue";
import type { StorageSummary, StorageInfo } from "../../types";

type Translator = (key: string, params?: Record<string, unknown>) => string;

const props = defineProps<{
  localStorage: StorageSummary | null;
  remoteStorages: StorageSummary[];
  showLocalSection: boolean;
  hasLocalVaults: boolean;
  error: string;
  t: Translator;
  getStorageInfo: (storageId: string) => Promise<StorageInfo | null>;
  onSignOut: (storageId: string, eraseCache: boolean) => Promise<void>;
  onSignIn: (storageId: string) => Promise<void>;
  onRemoveServer: (storageId: string) => Promise<void>;
  onClearData: (alsoClearRemoteCache: boolean, alsoRemoveConnections: boolean) => Promise<void>;
  onFactoryReset: () => Promise<void>;
  onRevealStorage: (storageId: string) => void;
  onAddServer: () => void;
  onCreateLocalVault: () => void;
  onSyncNow: (storageId: string) => Promise<void>;
  onResetSyncCursor: (storageId: string) => Promise<void>;
}>();

const localInfo = ref<StorageInfo | null>(null);
const remoteInfoMap = ref<Map<string, StorageInfo>>(new Map());
const expandedFingerprints = ref<Set<string>>(new Set());

const showClearDataModal = ref(false);
const showFactoryResetModal = ref(false);
const showSignOutModal = ref<string | null>(null);
const showRemoveModal = ref<string | null>(null);
const showResetCursorModal = ref<string | null>(null);

const clearDataRemoteCache = ref(true);
const clearDataRemoveConnections = ref(false);
const clearDataConfirm = ref("");
const factoryResetConfirm = ref("");
const signOutEraseCache = ref(true);
const busy = ref(false);
const hideCreateLocalVault = computed(() => props.remoteStorages.length === 0);

watch(
  () => props.localStorage,
  async (storage) => {
    if (storage) {
      localInfo.value = await props.getStorageInfo(storage.id);
    }
  },
  { immediate: true }
);

watch(
  () => props.remoteStorages,
  async (storages) => {
    for (const storage of storages) {
      if (!remoteInfoMap.value.has(storage.id)) {
        const info = await props.getStorageInfo(storage.id);
        if (info) {
          remoteInfoMap.value.set(storage.id, info);
        }
      }
    }
  },
  { immediate: true }
);

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
  if (diffMins < 1) return props.t("time.justNow");
  if (diffMins < 60) return `${diffMins} ${props.t("time.minutesAgo")}`;
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)} ${props.t("time.hoursAgo")}`;
  return date.toLocaleDateString();
};

const truncateFingerprint = (fp: string | null | undefined): string => {
  if (!fp) return "";
  if (fp.length <= 20) return fp;
  return fp.substring(0, 20) + "...";
};

const toggleFingerprint = (storageId: string) => {
  if (expandedFingerprints.value.has(storageId)) {
    expandedFingerprints.value.delete(storageId);
  } else {
    expandedFingerprints.value.add(storageId);
  }
};

const resetClearDataModal = () => {
  showClearDataModal.value = false;
  clearDataRemoteCache.value = true;
  clearDataRemoveConnections.value = false;
  clearDataConfirm.value = "";
};

const resetFactoryResetModal = () => {
  showFactoryResetModal.value = false;
  factoryResetConfirm.value = "";
};

const handleClearData = async () => {
  if (clearDataConfirm.value !== "RESET") return;
  busy.value = true;
  await props.onClearData(clearDataRemoteCache.value, clearDataRemoveConnections.value);
  busy.value = false;
  resetClearDataModal();
};

const handleFactoryReset = async () => {
  if (factoryResetConfirm.value !== "DELETE") return;
  busy.value = true;
  await props.onFactoryReset();
  busy.value = false;
  resetFactoryResetModal();
};

const handleSignOut = async (storageId: string) => {
  busy.value = true;
  await props.onSignOut(storageId, signOutEraseCache.value);
  busy.value = false;
  showSignOutModal.value = null;
  signOutEraseCache.value = true;
};

const handleRemove = async (storageId: string) => {
  busy.value = true;
  await props.onRemoveServer(storageId);
  busy.value = false;
  showRemoveModal.value = null;
};

const handleResetCursor = async (storageId: string) => {
  busy.value = true;
  await props.onResetSyncCursor(storageId);
  busy.value = false;
  showResetCursorModal.value = null;
};
</script>

<template>
  <div class="space-y-6">
    <!-- Error -->
    <p v-if="error" class="text-sm text-red-500">{{ error }}</p>

    <!-- Remote Servers (shown first) -->
    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.accounts.connectedServers") }}
      </h4>

      <div v-if="remoteStorages.length === 0" class="text-center py-6 text-[var(--text-secondary)] text-sm">
        {{ t("settings.accounts.noServers") }}
      </div>

      <div v-else class="space-y-3">
        <div
          v-for="storage in remoteStorages"
          :key="storage.id"
          class="rounded-lg bg-[var(--bg-tertiary)] p-4"
        >
          <div class="flex items-start gap-3">
            <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-hover)]">
              <svg class="h-5 w-5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
              </svg>
            </div>
            <div class="flex-1 min-w-0">
              <div class="font-medium">{{ storage.server_name ?? storage.name }}</div>
              <div class="text-xs text-[var(--text-tertiary)]">
                {{ storage.account_subject ?? storage.server_url }}
              </div>
              <div v-if="!storage.account_subject" class="text-xs text-[var(--text-tertiary)] mt-0.5">
                {{ t("settings.accounts.notSignedIn") }}
              </div>
              <div v-if="remoteInfoMap.get(storage.id)?.last_synced" class="text-xs text-[var(--text-tertiary)] mt-0.5">
                {{ t("settings.accounts.lastSynced") }}: {{ formatDate(remoteInfoMap.get(storage.id)?.last_synced) }}
              </div>

              <!-- Fingerprint -->
              <div v-if="remoteInfoMap.get(storage.id)?.fingerprint" class="mt-2 text-xs">
                <span class="text-[var(--text-tertiary)]">{{ t("settings.accounts.fingerprint") }}: </span>
                <code v-if="!expandedFingerprints.has(storage.id)" class="font-mono text-[var(--text-secondary)]">
                  {{ truncateFingerprint(remoteInfoMap.get(storage.id)?.fingerprint) }}
                </code>
                <code v-else class="font-mono text-[var(--text-secondary)] break-all">
                  {{ remoteInfoMap.get(storage.id)?.fingerprint }}
                </code>
                <button
                  type="button"
                  class="ml-2 text-[var(--accent)] hover:underline"
                  @click="toggleFingerprint(storage.id)"
                >
                  {{ expandedFingerprints.has(storage.id) ? t("common.hide") : t("settings.accounts.viewFingerprint") }}
                </button>
              </div>
            </div>
          </div>

          <div class="mt-4 flex gap-2 flex-wrap">
            <template v-if="storage.account_subject">
              <button
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                @click="onSyncNow(storage.id)"
              >
                {{ t("settings.accounts.syncNow") }}
              </button>
              <button
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                @click="showResetCursorModal = storage.id"
              >
                {{ t("settings.accounts.resetSyncCursor") }}
              </button>
              <button
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
                @click="showSignOutModal = storage.id"
              >
                {{ t("settings.accounts.signOut") }}
              </button>
            </template>
            <template v-else>
              <button
                type="button"
                class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-colors"
                @click="onSignIn(storage.id)"
              >
                {{ t("settings.accounts.signIn") }}
              </button>
            </template>
            <button
              type="button"
              class="rounded-lg px-3 py-1.5 text-xs font-medium text-category-security bg-category-security/10 hover:bg-category-security/20 transition-colors"
              @click="showRemoveModal = storage.id"
            >
              {{ t("settings.accounts.remove") }}
            </button>
          </div>
        </div>
      </div>

      <button
        type="button"
        class="mt-4 flex items-center gap-2 text-sm font-medium text-[var(--accent)] hover:underline"
        @click="onAddServer"
      >
        <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        {{ t("settings.accounts.addServer") }}
      </button>
    </div>

    <!-- Local Vault (shown only if user created local vaults) -->
    <div v-if="showLocalSection && localStorage">
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("storage.onThisDevice") }}
      </h4>
      <div class="rounded-lg bg-[var(--bg-tertiary)] p-4">
        <div class="flex items-start gap-3">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-hover)]">
            <svg class="h-5 w-5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div class="flex-1 min-w-0">
            <div class="font-medium">{{ localStorage.name }}</div>
            <div class="text-xs text-[var(--text-tertiary)]">
              {{ t("storage.notSynced") }}
            </div>
            <div v-if="localInfo?.file_path" class="text-xs text-[var(--text-tertiary)] truncate mt-0.5" :title="localInfo.file_path">
              {{ localInfo.file_path.split('/').pop() }}
              <template v-if="localInfo?.file_size"> &bull; {{ formatFileSize(localInfo.file_size) }}</template>
            </div>
          </div>
        </div>
        <div class="mt-4 flex gap-2 flex-wrap">
          <button
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
            @click="onRevealStorage(localStorage.id)"
          >
            {{ t("settings.accounts.revealInFinder") }}
          </button>
          <button
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--bg-hover)] hover:bg-[var(--bg-active)] transition-colors"
            @click="showClearDataModal = true"
          >
            {{ t("settings.accounts.clearData") }}
          </button>
          <button
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-medium text-category-security bg-category-security/10 hover:bg-category-security/20 transition-colors"
            @click="showFactoryResetModal = true"
          >
            {{ t("settings.accounts.factoryReset") }}
          </button>
        </div>
      </div>
    </div>

    <!-- Create Local Vault (shown when no local vaults exist) -->
    <div v-else-if="!showLocalSection && !hideCreateLocalVault">
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("storage.onThisDevice") }}
      </h4>
      <div class="rounded-lg border border-dashed border-[var(--border-color)] p-4 text-center">
        <p class="text-sm text-[var(--text-secondary)] mb-3">
          {{ t("storage.notSynced") }}
        </p>
        <button
          type="button"
          class="inline-flex items-center gap-2 text-sm font-medium text-[var(--accent)] hover:underline"
          @click="onCreateLocalVault"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          {{ t("storage.createLocalVault") }}
        </button>
      </div>
    </div>

    <!-- Clear Data Modal -->
    <div
      v-if="showClearDataModal"
      class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[120]"
      @click.self="resetClearDataModal"
    >
      <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <div class="flex items-center gap-3 mb-4">
          <div class="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20">
            <svg class="h-5 w-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold">{{ t("settings.accounts.clearData") }}</h3>
        </div>

        <p class="text-sm text-[var(--text-secondary)] mb-4">
          {{ t("settings.accounts.clearDataDesc") }}
        </p>

        <div class="space-y-3 mb-4">
          <label class="flex items-center gap-2 text-sm cursor-pointer">
            <input v-model="clearDataRemoteCache" type="checkbox" class="rounded" />
            <span>{{ t("settings.accounts.clearCacheForRemote") }}</span>
          </label>
          <label class="flex items-center gap-2 text-sm cursor-pointer">
            <input v-model="clearDataRemoveConnections" type="checkbox" class="rounded" />
            <span>{{ t("settings.accounts.alsoRemoveConnections") }}</span>
          </label>
        </div>

        <div class="mb-4">
          <label class="block text-sm font-medium mb-2">{{ t("settings.accounts.confirmClearData") }}</label>
          <input
            v-model="clearDataConfirm"
            type="text"
            placeholder="RESET"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-amber-500"
          />
        </div>

        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="resetClearDataModal"
          >
            {{ t("common.cancel") }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-amber-500 px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy || clearDataConfirm !== 'RESET'"
            @click="handleClearData"
          >
            {{ t("settings.accounts.clearData") }}
          </button>
        </div>
      </div>
    </div>

    <!-- Factory Reset Modal -->
    <div
      v-if="showFactoryResetModal"
      class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[120]"
      @click.self="resetFactoryResetModal"
    >
      <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <div class="flex items-center gap-3 mb-4">
          <div class="flex h-10 w-10 items-center justify-center rounded-full bg-category-security/20">
            <svg class="h-5 w-5 text-category-security" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold">{{ t("settings.accounts.factoryReset") }}</h3>
        </div>

        <p class="text-sm text-[var(--text-secondary)] mb-4">
          {{ t("settings.accounts.factoryResetDesc") }}
        </p>

        <div class="rounded-lg bg-category-security/10 border border-category-security/20 p-3 mb-4">
          <p class="text-xs text-category-security">
            {{ t("settings.accounts.factoryResetWarning") }}
          </p>
        </div>

        <div class="mb-4">
          <label class="block text-sm font-medium mb-2">{{ t("settings.accounts.confirmFactoryReset") }}</label>
          <input
            v-model="factoryResetConfirm"
            type="text"
            placeholder="DELETE"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-category-security"
          />
        </div>

        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="resetFactoryResetModal"
          >
            {{ t("common.cancel") }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-category-security px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy || factoryResetConfirm !== 'DELETE'"
            @click="handleFactoryReset"
          >
            {{ t("settings.accounts.factoryReset") }}
          </button>
        </div>
      </div>
    </div>

    <!-- Sign Out Modal -->
    <div
      v-if="showSignOutModal"
      class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[120]"
      @click.self="showSignOutModal = null"
    >
      <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <h3 class="text-lg font-semibold mb-4">{{ t("settings.accounts.signOut") }}</h3>

        <p class="text-sm text-[var(--text-secondary)] mb-4">
          {{ t("settings.accounts.signOutDesc") }}
        </p>

        <label class="flex items-center gap-2 text-sm cursor-pointer mb-4">
          <input v-model="signOutEraseCache" type="checkbox" class="rounded" />
          <span>{{ t("settings.accounts.alsoClearCache") }}</span>
        </label>

        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="showSignOutModal = null"
          >
            {{ t("common.cancel") }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy"
            @click="handleSignOut(showSignOutModal)"
          >
            {{ t("settings.accounts.signOut") }}
          </button>
        </div>
      </div>
    </div>

    <!-- Remove Server Modal -->
    <div
      v-if="showRemoveModal"
      class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[120]"
      @click.self="showRemoveModal = null"
    >
      <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <div class="flex items-center gap-3 mb-4">
          <div class="flex h-10 w-10 items-center justify-center rounded-full bg-category-security/20">
            <svg class="h-5 w-5 text-category-security" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold">{{ t("settings.accounts.remove") }}</h3>
        </div>

        <p class="text-sm text-[var(--text-secondary)] mb-4">
          {{ t("settings.accounts.removeDesc") }}
        </p>

        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="showRemoveModal = null"
          >
            {{ t("common.cancel") }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-category-security px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy"
            @click="handleRemove(showRemoveModal)"
          >
            {{ t("settings.accounts.remove") }}
          </button>
        </div>
      </div>
    </div>

    <!-- Reset Sync Cursor Modal -->
    <div
      v-if="showResetCursorModal"
      class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[120]"
      @click.self="showResetCursorModal = null"
    >
      <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <div class="flex items-center gap-3 mb-4">
          <div class="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20">
            <svg class="h-5 w-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold">{{ t("settings.accounts.resetSyncCursor") }}</h3>
        </div>

        <p class="text-sm text-[var(--text-secondary)] mb-4">
          {{ t("settings.accounts.resetSyncCursorDesc") }}
        </p>

        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="showResetCursorModal = null"
          >
            {{ t("common.cancel") }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-amber-500 px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            :disabled="busy"
            @click="handleResetCursor(showResetCursorModal)"
          >
            {{ t("settings.accounts.resetSyncCursor") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
