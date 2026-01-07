<script setup lang="ts">
import { computed } from "vue";
import type { Ref } from "vue";
import FatalErrorOverlay from "./FatalErrorOverlay.vue";
import AppStatusOverlay from "./AppStatusOverlay.vue";
import SetupWizardModal from "./SetupWizardModal.vue";
import UnlockModal from "./UnlockModal.vue";
import CommandPaletteModal from "./CommandPaletteModal.vue";
import SettingsModal from "./settings/SettingsModal.vue";
import ToastMessage from "./ToastMessage.vue";
import CreateModal from "./CreateModal.vue";
import SyncStatusToast from "./SyncStatusToast.vue";
import FolderContextMenu from "./FolderContextMenu.vue";
import RenameFolderModal from "./RenameFolderModal.vue";
import DeleteStorageModal from "./DeleteStorageModal.vue";
import ConfirmModal from "./ConfirmModal.vue";
import AuthMethodModal from "./AuthMethodModal.vue";
import PasswordLoginModal from "./PasswordLoginModal.vue";

type Translator = (key: string, params?: { [key: string]: unknown }) => string;

type AppModalsProps = {
  t: Translator;
  fatalError: unknown;
  runBootstrap: unknown;
  appStatus: unknown;
  showSetupModal: unknown;
  setupStep: unknown;
  setupFlow: unknown;
  setupPassword: unknown;
  setupConfirm: unknown;
  connectServerUrl: unknown;
  setupError: unknown;
  setupBusy: unknown;
  connectVerification: unknown;
  connectStatus: unknown;
  connectError: unknown;
  connectOldFp: unknown;
  connectNewFp: unknown;
  connectBusy: unknown;
  connectLoginId: unknown;
  logoUrl: unknown;
  normalizeServerUrl: unknown;
  startLocalSetup: unknown;
  startConnect: unknown;
  backToWelcome: unknown;
  createMasterPassword: unknown;
  showAuthMethodSelection: unknown;
  trustFingerprint: unknown;
  openExternal: unknown;
  copyToClipboard: unknown;
  showUnlock: unknown;
  password: unknown;
  unlockBusy: unknown;
  settings: unknown;
  keystoreStatus: unknown;
  autoUnlockError: unknown;
  error: unknown;
  doUnlock: unknown;
  unlockWithBiometrics: unknown;
  personalUnlockOpen: unknown;
  personalUnlockPassword: unknown;
  personalUnlockBusy: unknown;
  personalUnlockError: unknown;
  unlockPersonalVaults: unknown;
  paletteOpen: unknown;
  paletteQuery: unknown;
  paletteIndex: unknown;
  paletteItems: unknown;
  settingsOpen: unknown;
  settingsInitialTab: unknown;
  rememberEnabled: unknown;
  locale: unknown;
  updateSettings: unknown;
  testBiometrics: unknown;
  rebindBiometrics: unknown;
  storages: unknown;
  showLocalSection: unknown;
  hasLocalVaults: unknown;
  getStorageInfo: unknown;
  handleSignOut: unknown;
  handleSignIn: unknown;
  handleRemoveServer: unknown;
  handleClearData: unknown;
  handleFactoryReset: unknown;
  handleStorageReveal: unknown;
  openAddStorageWizard: unknown;
  openCreateLocalVault: unknown;
  handleSyncNow: unknown;
  handleResetSyncCursor: unknown;
  toast: unknown;
  toastActionLabel: unknown;
  toastAction: unknown;
  createMode: unknown;
  createModalOpen: unknown;
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
  vaults: unknown;
  flatFolderPaths: unknown;
  createItemFields: unknown;
  filteredKvFields: unknown;
  mainFields: unknown;
  advancedFields: unknown;
  customFields: unknown;
  typeOptions: unknown;
  typeGroups: unknown;
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
  syncBusy: unknown;
  syncError: unknown;
  folderMenuOpen: unknown;
  folderMenuPosition: unknown;
  closeFolderMenu: unknown;
  openRenameFolderModal: unknown;
  copyFolderPath: unknown;
  renameFolderModalOpen: unknown;
  renameFolderNewName: unknown;
  renameFolderOldPath: unknown;
  renameFolderNewPath: unknown;
  affectedItemsCount: unknown;
  renameFolderBusy: unknown;
  renameFolderError: unknown;
  submitRenameFolder: unknown;
  deleteStorageOpen: unknown;
  deleteStorageInfo: unknown;
  deleteStorageBusy: unknown;
  confirmDeleteStorage: unknown;
  confirmDisconnectStorage: unknown;
  confirmOpen: unknown;
  confirmTitle: unknown;
  confirmMessage: unknown;
  confirmConfirmLabel: unknown;
  confirmCancelLabel: unknown;
  confirmBusy: unknown;
  confirmInputExpected: unknown;
  confirmInputLabel: unknown;
  confirmInputPlaceholder: unknown;
  handleConfirm: unknown;
  authMethodOpen: unknown;
  availableMethods: unknown;
  handleSelectPassword: unknown;
  handleSelectOidc: unknown;
  passwordLoginOpen: unknown;
  passwordLoginBusy: unknown;
  passwordLoginError: unknown;
  handlePasswordAuth: unknown;
};

const props = defineProps<AppModalsProps>();
const t = props.t;

const modelRef = <T>(key: keyof AppModalsProps) =>
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

const valueRef = <T>(key: keyof AppModalsProps) =>
  computed<T>(() => {
    const value = props[key] as unknown;
    if (value && typeof value === "object" && "value" in (value as { value?: unknown })) {
      return (value as Ref<T>).value;
    }
    return value as T;
  });

const setupStep = modelRef<unknown>("setupStep");
const setupFlow = modelRef<unknown>("setupFlow");
const setupPassword = modelRef<unknown>("setupPassword");
const setupConfirm = modelRef<unknown>("setupConfirm");
const connectServerUrl = modelRef<unknown>("connectServerUrl");
const password = modelRef<unknown>("password");
const personalUnlockPassword = modelRef<unknown>("personalUnlockPassword");
const paletteOpen = modelRef<unknown>("paletteOpen");
const paletteQuery = modelRef<unknown>("paletteQuery");
const paletteIndex = modelRef<unknown>("paletteIndex");
const settingsOpen = modelRef<unknown>("settingsOpen");
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
const renameFolderModalOpen = modelRef<unknown>("renameFolderModalOpen");
const renameFolderNewName = modelRef<unknown>("renameFolderNewName");
const deleteStorageOpen = modelRef<unknown>("deleteStorageOpen");
const confirmOpen = modelRef<unknown>("confirmOpen");
const authMethodOpen = modelRef<unknown>("authMethodOpen");
const passwordLoginOpen = modelRef<unknown>("passwordLoginOpen");

const availableMethods = valueRef<unknown>("availableMethods");
const passwordLoginBusy = valueRef<unknown>("passwordLoginBusy");
const passwordLoginError = valueRef<unknown>("passwordLoginError");
const confirmInputExpected = valueRef<unknown>("confirmInputExpected");
const confirmInputLabel = valueRef<unknown>("confirmInputLabel");
const confirmInputPlaceholder = valueRef<unknown>("confirmInputPlaceholder");
</script>

<template>
  <FatalErrorOverlay
    :message="fatalError"
    :t="t"
    :on-retry="runBootstrap"
  />

  <AppStatusOverlay
    :show="!appStatus && !fatalError"
    :fatal-error="fatalError"
    :t="t"
    :on-retry="runBootstrap"
  />

  <SetupWizardModal
    :open="showSetupModal"
    v-model:step="setupStep"
    v-model:flow="setupFlow"
    v-model:setup-password="setupPassword"
    v-model:setup-confirm="setupConfirm"
    v-model:connect-server-url="connectServerUrl"
    :setup-error="setupError"
    :setup-busy="setupBusy"
    :connect-verification="connectVerification"
    :connect-status="connectStatus"
    :connect-error="connectError"
    :connect-old-fp="connectOldFp"
    :connect-new-fp="connectNewFp"
    :connect-busy="connectBusy"
    :connect-login-id="connectLoginId"
    :logo-url="logoUrl"
    :t="t"
    :normalize-server-url="normalizeServerUrl"
    :start-local-setup="startLocalSetup"
    :start-connect="startConnect"
    :back-to-welcome="backToWelcome"
    :create-master-password="createMasterPassword"
    :begin-server-connect="showAuthMethodSelection"
    :trust-fingerprint="trustFingerprint"
    :open-external="openExternal"
    :copy-to-clipboard="copyToClipboard"
  />

  <UnlockModal
    :open="showUnlock"
    v-model:password="password"
    :unlock-busy="unlockBusy"
    :settings="settings"
    :keystore-status="keystoreStatus"
    :auto-unlock-error="autoUnlockError"
    :error="error"
    :t="t"
    :on-unlock="doUnlock"
    :on-unlock-with-biometrics="unlockWithBiometrics"
  />

  <UnlockModal
    :open="personalUnlockOpen"
    v-model:password="personalUnlockPassword"
    :unlock-busy="personalUnlockBusy"
    :settings="settings"
    :keystore-status="keystoreStatus"
    auto-unlock-error=""
    :error="personalUnlockError"
    :title="t('unlock.personalTitle')"
    :subtitle="t('unlock.personalSubtitle')"
    :placeholder="t('unlock.personalPlaceholder')"
    :allow-biometrics="false"
    :t="t"
    :on-unlock="unlockPersonalVaults"
    :on-unlock-with-biometrics="() => {}"
  />

  <CommandPaletteModal
    v-model:open="paletteOpen"
    v-model:query="paletteQuery"
    v-model:index="paletteIndex"
    :items="paletteItems"
    :t="t"
  />

  <SettingsModal
    v-model:open="settingsOpen"
    :initial-tab="settingsInitialTab"
    :settings="settings"
    :remember-enabled="rememberEnabled"
    :error="error"
    :locale="locale"
    :t="t"
    :update-settings="updateSettings"
    :keystore-status="keystoreStatus"
    :on-test-biometrics="testBiometrics"
    :on-rebind-biometrics="rebindBiometrics"
    :storages="storages"
    :show-local-section="showLocalSection"
    :has-local-vaults="hasLocalVaults"
    :get-storage-info="getStorageInfo"
    :on-sign-out="handleSignOut"
    :on-sign-in="handleSignIn"
    :on-remove-server="handleRemoveServer"
    :on-clear-data="handleClearData"
    :on-factory-reset="handleFactoryReset"
    :on-reveal-storage="handleStorageReveal"
    :on-add-server="openAddStorageWizard"
    :on-create-local-vault="openCreateLocalVault"
    :on-sync-now="handleSyncNow"
    :on-reset-sync-cursor="handleResetSyncCursor"
  />

  <ToastMessage
    :message="toast"
    :action-label="toastActionLabel"
    :on-action="toastAction || undefined"
  />

  <CreateModal
    v-if="createMode === 'vault' && createModalOpen"
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
    :vaults="vaults"
    :flat-folder-paths="flatFolderPaths"
    :create-item-fields="createItemFields"
    :filtered-kv-fields="filteredKvFields"
    :main-fields="mainFields"
    :advanced-fields="advancedFields"
    :custom-fields="customFields"
    :type-options="typeOptions"
    :type-groups="typeGroups"
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
  />

  <SyncStatusToast
    :busy="syncBusy"
    :error="syncError"
    :t="t"
  />

  <FolderContextMenu
    :open="folderMenuOpen"
    :position="folderMenuPosition"
    :t="t"
    @close="closeFolderMenu"
    @rename="openRenameFolderModal"
    @copy="copyFolderPath"
  />

  <RenameFolderModal
    v-model:open="renameFolderModalOpen"
    v-model:newName="renameFolderNewName"
    :old-path="renameFolderOldPath"
    :new-path="renameFolderNewPath"
    :affected-count="affectedItemsCount"
    :busy="renameFolderBusy"
    :error="renameFolderError"
    :t="t"
    @submit="submitRenameFolder"
  />

  <DeleteStorageModal
    v-model:open="deleteStorageOpen"
    :storage="deleteStorageInfo"
    :busy="deleteStorageBusy"
    :t="t"
    @delete="confirmDeleteStorage"
    @disconnect="confirmDisconnectStorage"
  />

  <ConfirmModal
    v-model:open="confirmOpen"
    :title="confirmTitle"
    :message="confirmMessage"
    :confirm-label="confirmConfirmLabel"
    :cancel-label="confirmCancelLabel"
    :busy="confirmBusy"
    :danger="true"
    :confirm-input-expected="confirmInputExpected"
    :confirm-input-label="confirmInputLabel"
    :confirm-input-placeholder="confirmInputPlaceholder"
    :t="t"
    @confirm="handleConfirm"
  />

  <AuthMethodModal
    v-model:open="authMethodOpen"
    :server-url="connectServerUrl"
    :available-methods="availableMethods"
    :t="t"
    @select-password="handleSelectPassword"
    @select-oidc="handleSelectOidc"
  />

  <PasswordLoginModal
    v-model:open="passwordLoginOpen"
    :server-url="connectServerUrl"
    :busy="passwordLoginBusy"
    :error="passwordLoginError"
    :t="t"
    @submit="handlePasswordAuth"
  />
</template>
