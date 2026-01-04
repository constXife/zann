<script setup lang="ts">
import { ref, computed, watch } from "vue";
import type { KeystoreStatus, Settings, StorageSummary, StorageInfo } from "../../types";
import SettingsTabGeneral from "./SettingsTabGeneral.vue";
import SettingsTabSecurity from "./SettingsTabSecurity.vue";
import SettingsTabAccounts from "./SettingsTabAccounts.vue";
import SettingsTabBackups from "./SettingsTabBackups.vue";
import SettingsTabAbout from "./SettingsTabAbout.vue";

type Translator = (key: string, params?: Record<string, unknown>) => string;

type Tab = "general" | "security" | "accounts" | "backups" | "about";

const props = defineProps<{
  open: boolean;
  initialTab?: Tab;
  settings: Settings | null;
  rememberEnabled: boolean;
  error: string;
  locale: string;
  t: Translator;
  updateSettings: (patch: Partial<Settings>) => void;
  keystoreStatus: KeystoreStatus | null;
  onTestBiometrics: () => void;
  onRebindBiometrics: () => void;
  storages: StorageSummary[];
  showLocalSection: boolean;
  hasLocalVaults: boolean;
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
}>();

const emit = defineEmits<{
  "update:open": [boolean];
}>();

const activeTab = ref<Tab>(props.initialTab ?? "general");

const tabs: { id: Tab; icon: string; labelKey: string }[] = [
  { id: "general", icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z", labelKey: "settings.tabs.general" },
  { id: "security", icon: "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z", labelKey: "settings.tabs.security" },
  { id: "accounts", icon: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z", labelKey: "settings.tabs.accounts" },
  { id: "backups", icon: "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12", labelKey: "settings.tabs.backups" },
  { id: "about", icon: "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z", labelKey: "settings.tabs.about" },
];

const localStorage = computed(() => props.storages.find((s) => s.kind === "local_only"));
const remoteStorages = computed(() => props.storages.filter((s) => s.kind === "remote"));

watch(() => props.open, (isOpen) => {
  if (isOpen) {
    activeTab.value = props.initialTab ?? "general";
  }
});
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[100]"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-3xl h-[80vh] max-h-[600px] rounded-xl bg-[var(--bg-secondary)] shadow-2xl overflow-hidden flex flex-col">
      <!-- Header -->
      <div class="flex items-center justify-between px-6 py-4 border-b border-[var(--border-color)] shrink-0">
        <h3 class="text-lg font-semibold">{{ t("settings.title") }}</h3>
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

      <!-- Body -->
      <div class="flex flex-1 min-h-0">
        <!-- Sidebar -->
        <nav class="w-48 shrink-0 border-r border-[var(--border-color)] p-3 space-y-1 overflow-y-auto">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            type="button"
            class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
            :class="activeTab === tab.id
              ? 'bg-[var(--accent)] text-white'
              : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]'"
            @click="activeTab = tab.id"
          >
            <svg class="h-5 w-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="tab.icon" />
            </svg>
            {{ t(tab.labelKey) }}
          </button>
        </nav>

        <!-- Content -->
        <div class="flex-1 overflow-y-auto p-6">
          <SettingsTabGeneral
            v-if="activeTab === 'general'"
            :settings="settings"
            :locale="locale"
            :t="t"
            :update-settings="updateSettings"
          />
          <SettingsTabSecurity
            v-else-if="activeTab === 'security'"
            :settings="settings"
            :remember-enabled="rememberEnabled"
            :error="error"
            :t="t"
            :update-settings="updateSettings"
            :keystore-status="keystoreStatus"
            :on-test-biometrics="onTestBiometrics"
            :on-rebind-biometrics="onRebindBiometrics"
          />
          <SettingsTabAccounts
            v-else-if="activeTab === 'accounts'"
            :local-storage="localStorage ?? null"
            :remote-storages="remoteStorages"
            :show-local-section="showLocalSection"
            :has-local-vaults="hasLocalVaults"
            :error="error"
            :t="t"
            :get-storage-info="getStorageInfo"
            :on-sign-out="onSignOut"
            :on-sign-in="onSignIn"
            :on-remove-server="onRemoveServer"
            :on-clear-data="onClearData"
            :on-factory-reset="onFactoryReset"
            :on-reveal-storage="onRevealStorage"
            :on-add-server="onAddServer"
            :on-create-local-vault="onCreateLocalVault"
            :on-sync-now="onSyncNow"
          />
          <SettingsTabBackups
            v-else-if="activeTab === 'backups'"
            :t="t"
          />
          <SettingsTabAbout
            v-else-if="activeTab === 'about'"
            :t="t"
          />
        </div>
      </div>
    </div>
  </div>
</template>
