<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { StorageKind } from "../constants/enums";
import type { Ref } from "vue";
import SidebarPanel from "./SidebarPanel.vue";
import ItemListPanel from "./ItemListPanel.vue";
import ItemDetailsPanel from "./ItemDetailsPanel.vue";
import CreateModal from "./CreateModal.vue";
import PanelResizeHandle from "./PanelResizeHandle.vue";
import { CATEGORY_TYPES, categoryTypes, type ItemCategoryId } from "../utils/itemCategories";

type Translator = (key: string, params?: { [key: string]: unknown }) => string;

type AppShellProps = {
  t: Translator;
  uiSettings: unknown;
  openConfirm: unknown;
  storageDropdownOpen: unknown;
  storages: unknown;
  remoteStorages: unknown;
  localStorageRef: unknown;
  showLocalSection: unknown;
  hasLocalVaults: unknown;
  selectedStorageId: unknown;
  currentStorage: unknown;
  getSyncStatus: unknown;
  storageSyncErrors: unknown;
  toggleStorageDropdown: unknown;
  closeStorageDropdown: unknown;
  openAddStorageWizard: unknown;
  openStorageSettings: unknown;
  openCreateLocalVault: unknown;
  switchStorage: unknown;
  vaultDropdownOpen: unknown;
  vaults: unknown;
  listLoading: unknown;
  listError: unknown;
  personalVaults: unknown;
  sharedVaults: unknown;
  selectedVaultId: unknown;
  toggleVaultDropdown: unknown;
  closeVaultDropdown: unknown;
  switchVault: unknown;
  openCreateVault: unknown;
  categories: unknown;
  categoryCounts: unknown;
  selectedCategory: unknown;
  selectCategory: unknown;
  folderTree: unknown;
  expandedFolders: unknown;
  selectedFolder: unknown;
  itemsWithoutFolder: unknown;
  toggleFolder: unknown;
  openFolderMenu: unknown;
  selectFolderFilter: unknown;
  listPanel: unknown;
  filteredItems: unknown;
  totalListHeight: unknown;
  listOffset: unknown;
  visibleItems: unknown;
  selectedItemId: unknown;
  vaultContextLabel: unknown;
  isSharedVault: unknown;
  onListScroll: unknown;
  selectItemById: unknown;
  openCreateModal: unknown;
  emptyTrash: unknown;
  showOfflineBanner: unknown;
  showSessionExpiredBanner: unknown;
  showPersonalLockedBanner: unknown;
  showSyncErrorBanner: unknown;
  syncErrorMessage: unknown;
  pendingChangesCount: unknown;
  syncBusy: unknown;
  lastSyncTime: unknown;
  handleBannerSignIn: unknown;
  openPersonalUnlock: unknown;
  handleResetPersonal: unknown;
  runRemoteSync: unknown;
  openSettings: unknown;
  listWidth: unknown;
  isResizingDetails: unknown;
  startResizeDetails: unknown;
  retryLoadItems: unknown;
  createModalOpen: unknown;
  createMode: unknown;
  createItemVaultId: unknown;
  createItemType: unknown;
  createItemTitle: unknown;
  createItemFolder: unknown;
  kvFilter: unknown;
  advancedOpen: unknown;
  createVaultName: unknown;
  createVaultKind: unknown;
  createVaultCachePolicy: unknown;
  createVaultDefault: unknown;
  showFolderSuggestions: unknown;
  flatFolderPaths: unknown;
  createItemFields: unknown;
  filteredKvFields: unknown;
  mainFields: unknown;
  advancedFields: unknown;
  customFields: unknown;
  typeOptions: unknown;
  typeGroups: unknown;
  showAllTypesOption?: unknown;
  enableAllTypes?: unknown;
  openTypeMenuOnOpen?: unknown;
  consumeOpenTypeMenu?: unknown;
  createVaultError: unknown;
  createItemError: unknown;
  createItemErrorKey: unknown;
  createItemBusy: unknown;
  createItemValid: unknown;
  createVaultBusy: unknown;
  createVaultValid: unknown;
  createEditingItemId: unknown;
  createTypeLocked?: unknown;
  revealedFields: unknown;
  altRevealAll: unknown;
  getFieldLabel: unknown;
  addCustomField: unknown;
  removeField: unknown;
  buildPayload: unknown;
  applyPayload: unknown;
  loadTypeOptions?: unknown;
  submitCreate: unknown;
  detailsPanel: unknown;
  query: unknown;
  detailLoading: unknown;
  itemDetailError: unknown;
  openPalette: unknown;
  selectedItem: unknown;
  detailSections: unknown;
  historyEntries: unknown;
  historyLoading: unknown;
  historyError: unknown;
  selectedItemConflict: unknown;
  isRevealed: unknown;
  toggleReveal: unknown;
  copyField: unknown;
  copyEnv: unknown;
  copyJson: unknown;
  copyRaw: unknown;
  copyHistoryPassword: unknown;
  restoreHistoryVersion: unknown;
  fetchHistoryPayload: unknown;
  openExternal: unknown;
  openEditItem: unknown;
  deleteItem: unknown;
  selectedItemDeleted: unknown;
  restoreItem: unknown;
  purgeItem: unknown;
  selectedVaultName: unknown;
  resolveConflict: unknown;
  timeTravelActive: unknown;
  timeTravelIndex: unknown;
  timeTravelPayload: unknown;
  timeTravelBasePayload: unknown;
  timeTravelLoading: unknown;
  timeTravelError: unknown;
  timeTravelHasDraft: unknown;
  applyTimeTravelField: unknown;
  openTimeTravel: unknown;
  closeTimeTravel: unknown;
  setTimeTravelIndex: unknown;
};

const props = defineProps<AppShellProps>();
const t = props.t;
const isLocalStorage = computed(
  () => (props.currentStorage as { kind?: number } | null)?.kind === StorageKind.LocalOnly,
);

const modelRef = <T>(key: keyof AppShellProps) =>
  computed<T>({
    get: () => {
      const value = props[key] as unknown;
      if (value && typeof value === "object" && "value" in (value as { value?: unknown })) {
        return (value as Ref<T>).value;
      }
      return value as T;
    },
    set: (next) => {
      const value = props[key] as unknown;
      if (value && typeof value === "object" && "value" in (value as { value?: unknown })) {
        (value as Ref<T>).value = next;
      }
    },
  });

const createModalOpen = modelRef<unknown>("createModalOpen");
const createMode = modelRef<unknown>("createMode");
const createItemVaultId = modelRef<unknown>("createItemVaultId");
const createItemType = modelRef<unknown>("createItemType");
const createItemTitle = modelRef<unknown>("createItemTitle");
const createItemFolder = modelRef<unknown>("createItemFolder");
const kvFilter = modelRef<unknown>("kvFilter");
const advancedOpen = modelRef<unknown>("advancedOpen");
const typeOptions = modelRef<unknown>("typeOptions");
const createVaultName = modelRef<unknown>("createVaultName");
const createVaultKind = modelRef<unknown>("createVaultKind");
const createVaultCachePolicy = modelRef<unknown>("createVaultCachePolicy");
const createVaultDefault = modelRef<unknown>("createVaultDefault");
const showFolderSuggestions = modelRef<unknown>("showFolderSuggestions");
const query = modelRef<unknown>("query");

const uiSettings = modelRef<unknown>("uiSettings");
const openConfirm = props.openConfirm as (options: {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => Promise<void> | void;
}) => void;
const selectItemById = props.selectItemById as (itemId: string) => void;

const viewportWidth = ref(typeof window !== "undefined" ? window.innerWidth : 0);
const updateViewport = () => {
  viewportWidth.value = window.innerWidth;
};

onMounted(() => {
  updateViewport();
  window.addEventListener("resize", updateViewport);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", updateViewport);
});

const listHidden = computed(
  () =>
    createModalOpen.value &&
    createMode.value === "item" &&
    !props.createEditingItemId &&
    createItemType.value !== "kv" &&
    viewportWidth.value < 1200,
);

const defaultTypeOrder = [
  "login",
  "card",
  "note",
  "identity",
  "api",
  "kv",
  "ssh_key",
  "database",
  "cloud_iam",
  "server_credentials",
  "file_secret",
];

const resolvedTypeOptions = computed(() => {
  const value = typeOptions.value as string[] | undefined;
  const base = value && value.length ? value : defaultTypeOrder;
  return Array.from(new Set(base));
});

  const listCreateTypes = computed(() => {
    const selected = props.selectedCategory as string | null;
    if (selected && selected !== "all" && selected !== "trash") {
      return categoryTypes(selected as any);
    }
    return resolvedTypeOptions.value;
  });

  const mappedTypeIds = new Set(Object.values(CATEGORY_TYPES).flat());
  const listCreateTypeGroups = computed(() => {
    const available = new Set(listCreateTypes.value);
    const orderedTypes = resolvedTypeOptions.value;
    const resolveTypes = (categoryId: ItemCategoryId) =>
      orderedTypes.filter(
        (typeId) => available.has(typeId) && categoryTypes(categoryId).includes(typeId),
      );
    const otherTypes = orderedTypes.filter(
      (typeId) => available.has(typeId) && !mappedTypeIds.has(typeId),
    );
    const groups = [
      { id: "login", label: t("create.typeGroupLogins"), types: resolveTypes("login") },
      { id: "card", label: t("create.typeGroupCards"), types: resolveTypes("card") },
      { id: "note", label: t("create.typeGroupNotes"), types: resolveTypes("note") },
      { id: "kv", label: t("create.typeGroupVariables"), types: resolveTypes("kv") },
      { id: "infra", label: t("create.typeGroupInfra"), types: resolveTypes("infra") },
    ];
    if (otherTypes.length) {
      groups.push({ id: "other", label: t("create.typeGroupOther"), types: otherTypes });
    }
    return groups.filter((group) => group.types.length > 0);
  });

const prepareCreateTypes = async () => {
  const load = props.loadTypeOptions as (() => Promise<void>) | undefined;
  if (load) {
    await load();
  }
};

const openCreateWithType = (typeId?: string | Event) => {
  const resolvedTypeId = typeof typeId === "string" ? typeId : undefined;
  (props.openCreateModal as (mode: "item", options?: { openTypeMenu?: boolean; typeId?: string }) => void)(
    "item",
    resolvedTypeId
      ? { typeId: resolvedTypeId }
      : { openTypeMenu: true },
  );
};

const handleSelectItem = (itemId: string) => {
  if (createModalOpen.value && createMode.value === "item") {
    openConfirm({
      title: t("create.discardTitle"),
      message: t("create.discardBody"),
      confirmLabel: t("create.discardConfirm"),
      cancelLabel: t("common.cancel"),
      onConfirm: () => {
        createModalOpen.value = false;
        selectItemById(itemId);
      },
    });
    return;
  }
  selectItemById(itemId);
};
const listBlocked = computed(
  () =>
    props.showPersonalLockedBanner ||
    props.showSessionExpiredBanner,
);
const listBlockedMessage = computed(() => {
  if (props.showPersonalLockedBanner) {
    return t("items.listLocked");
  }
  if (props.showSessionExpiredBanner) {
    return t("items.listSessionExpired");
  }
  return t("items.listBlocked");
});

const showGlobalBanner = computed(
  () => props.showOfflineBanner || props.showSyncErrorBanner,
);

const bannerTitle = computed(() =>
  props.showSyncErrorBanner ? t("status.syncError") : t("status.offlineTitle"),
);

const bannerBody = computed(() => {
  if (props.showSyncErrorBanner) {
    return props.syncErrorMessage || t("status.syncErrorHint");
  }
  return t("status.offlineHint");
});

const formattedLastSync = computed(() => {
  if (!props.lastSyncTime) return null;
  const date = new Date(props.lastSyncTime as string);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return t("time.justNow");
  if (diffMins < 60) return `${diffMins} ${t("time.minutesAgo")}`;
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)} ${t("time.hoursAgo")}`;
  return date.toLocaleDateString();
});
</script>

<template>
  <div class="flex h-full overflow-hidden bg-[var(--bg-primary)]">
    <SidebarPanel
      :style="{ width: uiSettings.sidebarCollapsed ? '0px' : uiSettings.sidebarWidth + 'px' }"
      :hidden="uiSettings.sidebarCollapsed"
      :on-collapse="() => (uiSettings.sidebarCollapsed = true)"
      :storage-dropdown-open="storageDropdownOpen"
      :storages="storages"
      :remote-storages="remoteStorages"
      :local-storage="localStorageRef"
      :show-local-section="showLocalSection"
      :has-local-vaults="hasLocalVaults"
      :selected-storage-id="selectedStorageId"
      :current-storage="currentStorage"
      :get-sync-status="getSyncStatus"
      :storage-sync-errors="storageSyncErrors"
      :last-sync-time="lastSyncTime"
      :toggle-storage-dropdown="toggleStorageDropdown"
      :close-storage-dropdown="closeStorageDropdown"
      :open-add-storage-wizard="openAddStorageWizard"
      :open-storage-settings="openStorageSettings"
      :open-create-local-vault="openCreateLocalVault"
      :open-settings="openSettings"
      :switch-storage="switchStorage"
      :vault-dropdown-open="vaultDropdownOpen"
      :vaults="vaults"
      :list-loading="listLoading"
      :personal-vaults="personalVaults"
      :shared-vaults="sharedVaults"
      :selected-vault-id="selectedVaultId"
      :toggle-vault-dropdown="toggleVaultDropdown"
      :close-vault-dropdown="closeVaultDropdown"
      :switch-vault="switchVault"
      :open-create-vault="openCreateVault"
      :categories="categories"
      :category-counts="categoryCounts"
      :selected-category="selectedCategory"
      :select-category="selectCategory"
      :folder-tree="folderTree"
      :expanded-folders="expandedFolders"
      :selected-folder="selectedFolder"
      :items-without-folder="itemsWithoutFolder"
      :toggle-folder="toggleFolder"
      :open-folder-menu="openFolderMenu"
      :select-folder="selectFolderFilter"
    />

    <PanelResizeHandle
      variant="opacity"
      :hidden="uiSettings.sidebarCollapsed"
      class="hidden"
    />

    <div class="flex min-w-0 flex-1 flex-col">
      <div
        v-if="showGlobalBanner"
        class="flex flex-col gap-3 border-b border-[var(--border-color)] bg-[var(--bg-secondary)] px-4 py-3 sm:flex-row sm:items-start"
      >
        <div
          class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg"
          :class="showSyncErrorBanner ? 'bg-red-500/20' : 'bg-amber-500/20'"
        >
          <svg
            class="h-4 w-4"
            :class="showSyncErrorBanner ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400'"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              v-if="showSyncErrorBanner"
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
            <path
              v-else
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M18.364 5.636a9 9 0 010 12.728M5.636 5.636a9 9 0 000 12.728M12 12v.01M8.464 15.536a5 5 0 010-7.072m7.072 0a5 5 0 010 7.072"
            />
          </svg>
        </div>
        <div class="flex-1 min-w-0">
          <div class="text-sm font-semibold text-[var(--text-primary)]">
            {{ bannerTitle }}
          </div>
          <div class="text-xs text-[var(--text-secondary)] break-words">
            {{ bannerBody }}
          </div>
          <div v-if="formattedLastSync" class="mt-1 text-xs text-[var(--text-tertiary)]">
            {{ t("storage.lastSynced") }}: {{ formattedLastSync }}
          </div>
          <div v-if="pendingChangesCount > 0" class="text-xs text-[var(--text-tertiary)]">
            {{ t("status.pendingChanges", { count: pendingChangesCount }) }}
          </div>
        </div>
        <div class="flex items-center gap-2 sm:ml-auto">
          <button
            type="button"
            class="shrink-0 rounded-lg border border-[var(--border-color)] px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="openSettings('accounts')"
          >
            {{ t("status.details") }}
          </button>
          <button
            type="button"
            class="shrink-0 rounded-lg border border-[var(--border-color)] px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
            @click="runRemoteSync()"
          >
            {{ t("common.retry") }}
          </button>
        </div>
      </div>

      <div class="relative flex min-w-0 flex-1 overflow-hidden">
      <ItemListPanel
        v-if="!listHidden"
        ref="listPanel"
        class="shrink-0"
          :sidebar-collapsed="uiSettings.sidebarCollapsed"
          :categories="categories"
          :selected-category="selectedCategory"
          :filtered-items="filteredItems"
          :list-loading="listLoading"
          :list-error="listError"
          :total-list-height="totalListHeight"
          :list-offset="listOffset"
          :visible-items="visibleItems"
          :selected-item-id="selectedItemId"
        :vault-context-label="vaultContextLabel"
        :is-shared-vault="isSharedVault"
        :is-local-storage="isLocalStorage"
        :sync-busy="syncBusy"
        :on-list-scroll="onListScroll"
        :select-item="handleSelectItem"
          :open-create-item="openCreateWithType"
          :create-type-options="listCreateTypes"
          :create-type-groups="listCreateTypeGroups"
          :prepare-create-types="prepareCreateTypes"
          :retry-load-items="retryLoadItems"
          :on-empty-trash="emptyTrash"
          :list-blocked="listBlocked"
          :list-blocked-message="listBlockedMessage"
          @expandSidebar="() => (uiSettings.sidebarCollapsed = false)"
          :style="{ width: listWidth + 'px', minWidth: listWidth + 'px' }"
        />

        <PanelResizeHandle
          v-if="!listHidden"
          variant="color"
          :active="isResizingDetails"
          @mousedown="startResizeDetails"
        />

        <CreateModal
          v-if="createModalOpen && createMode === 'item'"
          v-model:open="createModalOpen"
          v-model:create-item-vault-id="createItemVaultId"
          v-model:create-item-type="createItemType"
          v-model:create-item-title="createItemTitle"
          v-model:create-item-folder="createItemFolder"
          v-model:kv-filter="kvFilter"
          v-model:advanced-open="advancedOpen"
          v-model:create-vault-name="createVaultName"
          v-model:create-vault-kind="createVaultKind"
          v-model:create-vault-cache-policy="createVaultCachePolicy"
          v-model:create-vault-default="createVaultDefault"
          v-model:show-folder-suggestions="showFolderSuggestions"
          :create-mode="createMode"
          :variant="'panel'"
          :is-offline="showOfflineBanner"
          :vaults="vaults"
          :flat-folder-paths="flatFolderPaths"
          :create-item-fields="createItemFields"
          :filtered-kv-fields="filteredKvFields"
          :main-fields="mainFields"
          :advanced-fields="advancedFields"
          :custom-fields="customFields"
          :type-options="typeOptions"
          :type-groups="typeGroups"
          :show-all-types-option="showAllTypesOption"
          :enable-all-types="enableAllTypes"
          :open-type-menu-on-open="openTypeMenuOnOpen"
          :consume-open-type-menu="consumeOpenTypeMenu"
          :create-vault-error="createVaultError"
          :create-item-error="createItemError"
          :create-item-error-key="createItemErrorKey"
          :create-item-busy="createItemBusy"
          :create-item-valid="createItemValid"
          :create-vault-busy="createVaultBusy"
          :create-vault-valid="createVaultValid"
          :create-editing-item-id="createEditingItemId"
          :type-locked="createTypeLocked"
          :revealed-fields="revealedFields"
          :alt-reveal-all="altRevealAll"
          :t="t"
          :open-confirm="openConfirm"
          :get-field-label="getFieldLabel"
          :add-custom-field="addCustomField"
          :remove-field="removeField"
          :build-payload="buildPayload"
          :apply-payload="applyPayload"
          :submit-create="submitCreate"
          :style="{ width: uiSettings.detailsWidth + 'px', minWidth: uiSettings.detailsWidth + 'px' }"
        />

        <ItemDetailsPanel
          v-else
          ref="detailsPanel"
          v-model:query="query"
          :detail-loading="detailLoading"
          :error-message="itemDetailError"
          :list-loading="listLoading"
          :list-error="listError"
          :filtered-items-count="filteredItems.length"
          :categories="categories"
          :selected-category="selectedCategory"
          :selected-folder="selectedFolder"
          :open-create-item="openCreateWithType"
          :open-palette="openPalette"
      :show-offline-banner="showOfflineBanner"
      :show-session-expired-banner="showSessionExpiredBanner"
      :show-personal-locked-banner="showPersonalLockedBanner"
      :show-sync-error-banner="showSyncErrorBanner"
      :show-global-banner="showGlobalBanner"
          :sync-busy="syncBusy"
          :sync-error-message="syncErrorMessage"
          :pending-changes-count="pendingChangesCount"
          :last-sync-time="lastSyncTime"
          :on-sign-in="handleBannerSignIn"
          :on-unlock-personal="openPersonalUnlock"
          :on-reset-personal="handleResetPersonal"
          :retry-sync="() => runRemoteSync()"
          :selected-item="selectedItem"
          :detail-sections="detailSections"
          :history-entries="historyEntries"
          :history-loading="historyLoading"
          :history-error="historyError"
          :is-conflict="selectedItemConflict"
          :is-revealed="isRevealed"
          :alt-reveal-all="altRevealAll"
          :toggle-reveal="toggleReveal"
          :copy-field="copyField"
          :copy-env="copyEnv"
          :copy-json="copyJson"
          :copy-raw="copyRaw"
          :copy-history-password="copyHistoryPassword"
          :restore-history-version="restoreHistoryVersion"
          :fetch-history-payload="fetchHistoryPayload"
          :open-external="openExternal"
          :select-folder="selectFolderFilter"
          :open-edit-item="openEditItem"
          :delete-item="deleteItem"
          :is-deleted="selectedItemDeleted"
          :restore-item="restoreItem"
          :purge-item="purgeItem"
          :vault-name="selectedVaultName"
          :is-shared-vault="isSharedVault"
          :resolve-conflict="resolveConflict"
          :time-travel-active="timeTravelActive"
          :time-travel-index="timeTravelIndex"
          :time-travel-payload="timeTravelPayload"
          :time-travel-base-payload="timeTravelBasePayload"
          :time-travel-loading="timeTravelLoading"
          :time-travel-error="timeTravelError"
          :time-travel-has-draft="timeTravelHasDraft"
          :apply-time-travel-field="applyTimeTravelField"
          :open-time-travel="openTimeTravel"
          :close-time-travel="closeTimeTravel"
          :set-time-travel-index="setTimeTravelIndex"
          :style="{ width: uiSettings.detailsWidth + 'px', minWidth: uiSettings.detailsWidth + 'px' }"
        />
      </div>
    </div>
  </div>
</template>
