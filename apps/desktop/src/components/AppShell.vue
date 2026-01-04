<script setup lang="ts">
import { computed } from "vue";
import type { Ref } from "vue";
import SidebarPanel from "./SidebarPanel.vue";
import ItemListPanel from "./ItemListPanel.vue";
import ItemDetailsPanel from "./ItemDetailsPanel.vue";
import CreateModal from "./CreateModal.vue";
import PanelResizeHandle from "./PanelResizeHandle.vue";

type Translator = (key: string, params?: { [key: string]: unknown }) => string;

type AppShellProps = {
  t: Translator;
  uiSettings: unknown;
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
  handleBannerSignIn: unknown;
  openPersonalUnlock: unknown;
  handleResetPersonal: unknown;
  runRemoteSync: unknown;
  listWidth: unknown;
  isResizingDetails: unknown;
  startResizeDetails: unknown;
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
  createVaultError: unknown;
  createItemError: unknown;
  createItemErrorKey: unknown;
  createItemBusy: unknown;
  createVaultBusy: unknown;
  createEditingItemId: unknown;
  revealedFields: unknown;
  altRevealAll: unknown;
  getFieldLabel: unknown;
  addCustomField: unknown;
  removeField: unknown;
  buildPayload: unknown;
  applyPayload: unknown;
  submitCreate: unknown;
  detailsPanel: unknown;
  query: unknown;
  detailLoading: unknown;
  itemDetailError: unknown;
  selectedItem: unknown;
  detailSections: unknown;
  historyEntries: unknown;
  historyLoading: unknown;
  historyError: unknown;
  hasPasswordField: unknown;
  selectedItemConflict: unknown;
  isRevealed: unknown;
  toggleReveal: unknown;
  copyField: unknown;
  copyEnv: unknown;
  copyJson: unknown;
  copyRaw: unknown;
  copyHistoryPassword: unknown;
  fetchHistoryPayload: unknown;
  openExternal: unknown;
  openEditItem: unknown;
  deleteItem: unknown;
  selectedItemDeleted: unknown;
  restoreItem: unknown;
  purgeItem: unknown;
  selectedVaultName: unknown;
  resolveConflict: unknown;
};

const props = defineProps<AppShellProps>();
const t = props.t;

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
const createItemVaultId = modelRef<unknown>("createItemVaultId");
const createItemType = modelRef<unknown>("createItemType");
const createItemTitle = modelRef<unknown>("createItemTitle");
const createItemFolder = modelRef<unknown>("createItemFolder");
const kvFilter = modelRef<unknown>("kvFilter");
const advancedOpen = modelRef<unknown>("advancedOpen");
const createVaultName = modelRef<unknown>("createVaultName");
const createVaultKind = modelRef<unknown>("createVaultKind");
const createVaultCachePolicy = modelRef<unknown>("createVaultCachePolicy");
const createVaultDefault = modelRef<unknown>("createVaultDefault");
const showFolderSuggestions = modelRef<unknown>("showFolderSuggestions");
const query = modelRef<unknown>("query");

const uiSettings = modelRef<unknown>("uiSettings");
</script>

<template>
  <div
    class="flex h-full bg-[var(--bg-primary)]"
  >
    <SidebarPanel
      :style="{ width: uiSettings.sidebarCollapsed ? '0px' : uiSettings.sidebarWidth + 'px' }"
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
      :toggle-storage-dropdown="toggleStorageDropdown"
      :close-storage-dropdown="closeStorageDropdown"
      :open-add-storage-wizard="openAddStorageWizard"
      :open-storage-settings="openStorageSettings"
      :open-create-local-vault="openCreateLocalVault"
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

    <ItemListPanel
      ref="listPanel"
      class="shrink-0"
      :sidebar-collapsed="uiSettings.sidebarCollapsed"
      :categories="categories"
      :selected-category="selectedCategory"
      :filtered-items="filteredItems"
      :list-loading="listLoading"
      :total-list-height="totalListHeight"
      :list-offset="listOffset"
      :visible-items="visibleItems"
      :selected-item-id="selectedItemId"
      :vault-context-label="vaultContextLabel"
      :is-shared-vault="isSharedVault"
      :on-list-scroll="onListScroll"
      :select-item="selectItemById"
      :open-create-item="() => openCreateModal('item')"
      :on-empty-trash="emptyTrash"
      :show-offline-banner="showOfflineBanner"
      :show-session-expired-banner="showSessionExpiredBanner"
      :show-personal-locked-banner="showPersonalLockedBanner"
      :show-sync-error-banner="showSyncErrorBanner"
      :sync-error-message="syncErrorMessage"
      :on-sign-in="handleBannerSignIn"
      :on-unlock-personal="openPersonalUnlock"
      :on-reset-personal="handleResetPersonal"
      :last-sync-time="null"
      :retry-sync="() => runRemoteSync()"
      @expandSidebar="uiSettings.sidebarCollapsed = false"
      :style="{ width: listWidth + 'px', minWidth: listWidth + 'px' }"
    />

    <PanelResizeHandle
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
      :vaults="vaults"
      :flat-folder-paths="flatFolderPaths"
      :create-item-fields="createItemFields"
      :filtered-kv-fields="filteredKvFields"
      :main-fields="mainFields"
      :advanced-fields="advancedFields"
      :custom-fields="customFields"
      :type-options="typeOptions"
      :create-vault-error="createVaultError"
      :create-item-error="createItemError"
      :create-item-error-key="createItemErrorKey"
      :create-item-busy="createItemBusy"
      :create-vault-busy="createVaultBusy"
      :create-editing-item-id="createEditingItemId"
      :revealed-fields="revealedFields"
      :alt-reveal-all="altRevealAll"
      :t="t"
      :get-field-label="getFieldLabel"
      :add-custom-field="addCustomField"
      :remove-field="removeField"
      :build-payload="buildPayload"
      :apply-payload="applyPayload"
      :submit-create="submitCreate"
      :style="{ minWidth: uiSettings.detailsWidth + 'px' }"
    />

    <ItemDetailsPanel
      v-else
      ref="detailsPanel"
      v-model:query="query"
      :detail-loading="detailLoading"
      :error-message="itemDetailError"
      :selected-item="selectedItem"
      :detail-sections="detailSections"
      :history-entries="historyEntries"
      :history-loading="historyLoading"
      :history-error="historyError"
      :has-password-field="hasPasswordField"
      :is-conflict="selectedItemConflict"
      :is-revealed="isRevealed"
      :alt-reveal-all="altRevealAll"
      :toggle-reveal="toggleReveal"
      :copy-field="copyField"
      :copy-env="copyEnv"
      :copy-json="copyJson"
      :copy-raw="copyRaw"
      :copy-history-password="copyHistoryPassword"
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
      :style="{ minWidth: uiSettings.detailsWidth + 'px' }"
    />
  </div>
</template>
