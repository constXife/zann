<script setup lang="ts">
import { onErrorCaptured, toRef } from "vue";
import CreateAdvancedFields from "./CreateAdvancedFields.vue";
import CreateKvTable from "./CreateKvTable.vue";
import CreateMainFields from "./CreateMainFields.vue";
import CreateModalHeader from "./CreateModalHeader.vue";
import CreatePanelHeader from "./CreatePanelHeader.vue";
import CreateRawEditorModal from "./CreateRawEditorModal.vue";
import CreateVaultForm from "./CreateVaultForm.vue";
import SmartPathInput from "./SmartPathInput.vue";
import { useCreateForm } from "../composables/useCreateForm";
import type { EncryptedPayload, VaultSummary } from "../types";
import type { FieldInput, Translator } from "../types/createForm";

const createModalOpen = defineModel<boolean>("open", { required: true });
const createItemVaultId = defineModel<string | null>("createItemVaultId", { required: true });
const createItemType = defineModel<string>("createItemType", { required: true });
const createItemTitle = defineModel<string>("createItemTitle", { required: true });
const createItemFolder = defineModel<string>("createItemFolder", { required: true });
const kvFilter = defineModel<string>("kvFilter", { required: true });
const advancedOpen = defineModel<boolean>("advancedOpen", { required: true });
const createVaultName = defineModel<string>("createVaultName", { required: true });
const createVaultKind = defineModel<string>("createVaultKind", { required: true });
const createVaultCachePolicy = defineModel<string>("createVaultCachePolicy", { required: true });
const createVaultDefault = defineModel<boolean>("createVaultDefault", { required: true });
const showFolderSuggestions = defineModel<boolean>("showFolderSuggestions", { required: true });

const props = defineProps<{
  createMode: "vault" | "item" | null;
  variant?: "modal" | "panel";
  vaults: VaultSummary[];
  flatFolderPaths: string[];
  createItemFields: FieldInput[];
  filteredKvFields: FieldInput[];
  mainFields: FieldInput[];
  advancedFields: FieldInput[];
  customFields: FieldInput[];
  typeOptions: string[];
  typeGroups: { id: string; label: string; types: string[] }[];
  createVaultError: string;
  createItemError: string;
  createItemErrorKey: string;
  createItemBusy: boolean;
  createVaultBusy: boolean;
  createEditingItemId: string | null;
  revealedFields: Set<string>;
  altRevealAll: boolean;
  t: Translator;
  getFieldLabel: (key: string) => string;
  addCustomField: (isSecret: boolean) => void;
  removeField: (id: string) => void;
  buildPayload: (typeId: string) => EncryptedPayload;
  applyPayload: (payload: EncryptedPayload, typeId: string) => void;
  submitCreate: () => void;
}>();

const t = props.t;
const createEditingItemId = toRef(props, "createEditingItemId");

onErrorCaptured((err, instance, info) => {
  console.error("[CreateModal] captured error", {
    err,
    info,
    instance,
  });
  return false;
});

const {
  applyPastePayload,
  applyRawEditor,
  canRemoveKvRow,
  closeModal,
  closeCopyMenu,
  closeTypeMenu,
  copyMenuOpen,
  copyNotice,
  copyEnv,
  copyJson,
  copyRaw,
  currentPathInput,
  currentTypeIcon,
  currentTypeLabel,
  dismissPastePrompt,
  filteredPathSuggestions,
  generatorIncludeDigits,
  generatorIncludeSymbols,
  generatorIncludeLower,
  generatorIncludeUpper,
  generatorAvoidAmbiguous,
  generatorLength,
  generatorMemorable,
  generatorOpenId,
  generateSecret,
  getTypeLabel,
  handlePaste,
  handlePathKeydown,
  handlePathPaste,
  isPanel,
  jsonPlaceholderText,
  closeRawEditor,
  nameInput,
  openRawEditor,
  pastePromptMessage,
  pastePromptOpen,
  applySuggestion,
  pathTokens,
  rawEditOpen,
  rawJsonErrorKey,
  rawJsonText,
  scheduleHideFolderSuggestions,
  selectedVaultName,
  selectType,
  toggleCopyMenu,
  toggleTypeMenu,
  tokenDeleteArmed,
  typeMenuOpen,
  typeMeta,
  vaultShake,
} = useCreateForm({
  variant: props.variant,
  createModalOpen,
  createItemVaultId,
  createItemType,
  createItemTitle,
  createItemFolder,
  createItemFields: props.createItemFields,
  createEditingItemId,
  flatFolderPaths: props.flatFolderPaths,
  showFolderSuggestions,
  vaults: props.vaults,
  typeOptions: props.typeOptions,
  typeGroups: props.typeGroups,
  revealedFields: props.revealedFields,
  t,
  buildPayload: props.buildPayload,
  applyPayload: props.applyPayload,
  submitCreate: props.submitCreate,
});
</script>
<template>
  <component
      :is="isPanel ? 'section' : 'div'"
      v-if="createModalOpen"
      :class="isPanel
      ? 'flex flex-1 min-w-0 flex-col overflow-y-auto border-l border-[var(--border-color)] bg-[var(--bg-secondary)]'
      : 'fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl'"
      @click.self="!isPanel && closeModal()"
      @paste="handlePaste"
  >
    <CreatePanelHeader
      v-if="isPanel && createMode === 'item'"
      :vault-name="selectedVaultName()"
      :path-tokens="pathTokens"
      :busy="createItemBusy"
      :is-editing="Boolean(props.createEditingItemId)"
      :type-menu-open="typeMenuOpen"
      :type-options="typeOptions"
      :type-groups="typeGroups"
      :type-meta="typeMeta"
      :current-type-label="currentTypeLabel"
      :current-type-icon="currentTypeIcon"
      :get-type-label="getTypeLabel"
      :t="t"
      :on-cancel="closeModal"
      :on-submit="submitCreate"
      :on-toggle-type-menu="toggleTypeMenu"
      :on-select-type="selectType"
      :on-close-type-menu="closeTypeMenu"
    />

    <div
        :class="isPanel
        ? 'w-full max-w-2xl mx-auto px-6 py-6'
        : 'w-full max-w-2xl rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl relative'"
    >
      <div
          :class="isPanel
          ? 'rounded-2xl border border-[var(--border-color)] bg-[var(--bg-tertiary)] p-6 shadow-sm'
          : ''"
      >
        <div v-if="isPanel && createMode === 'item'" class="space-y-6">
          <label class="block space-y-2 text-xs text-[var(--text-tertiary)]">
            <span class="font-semibold uppercase tracking-wide">{{ t("create.itemPath") }}</span>
            <SmartPathInput
                v-model="currentPathInput"
                dense
                :vault-name="selectedVaultName()"
                :path-tokens="pathTokens"
                :token-delete-armed="tokenDeleteArmed"
                :vault-shake="vaultShake"
                :placeholder="t('create.itemFolderPlaceholder')"
                :suggestions="filteredPathSuggestions"
                :has-error="props.createItemErrorKey === 'vault_required'"
                input-test-id="create-path"
                @focus="showFolderSuggestions = true"
                @blur="scheduleHideFolderSuggestions"
                @keydown="handlePathKeydown"
                @paste="handlePathPaste"
                @apply-suggestion="applySuggestion"
            />
            <span
              v-if="props.createItemErrorKey === 'vault_required'"
              class="text-[11px] text-category-security"
            >
              {{ createItemError }}
            </span>
          </label>

          <input
            v-model="nameInput"
            type="text"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="mt-6 w-full -ml-2 rounded-lg border-none bg-transparent px-2 py-1 text-3xl font-bold tracking-tight text-[var(--text-primary)] placeholder-[var(--text-secondary)] transition-colors hover:bg-zinc-800/50 focus:bg-zinc-900/80 focus:outline-none"
            :class="props.createItemErrorKey === 'name_required' ? 'bg-category-security/10 ring-2 ring-category-security/40' : ''"
            :placeholder="t('create.itemTitlePlaceholderPanel')"
            data-testid="create-name"
          />
          <span
            v-if="props.createItemErrorKey === 'name_required'"
            class="text-xs text-category-security"
          >
            {{ createItemError }}
          </span>
        </div>

    <CreateModalHeader
      v-else
      :create-mode="createMode"
      :is-editing="Boolean(props.createEditingItemId)"
      :type-menu-open="typeMenuOpen"
      :copy-menu-open="copyMenuOpen"
      :type-options="typeOptions"
      :type-groups="typeGroups"
      :type-meta="typeMeta"
          :current-type-label="currentTypeLabel"
          :current-type-icon="currentTypeIcon"
          :get-type-label="getTypeLabel"
          :t="t"
          :on-toggle-type-menu="toggleTypeMenu"
          :on-select-type="selectType"
          :on-close-type-menu="closeTypeMenu"
          :on-toggle-copy-menu="toggleCopyMenu"
          :on-close-copy-menu="closeCopyMenu"
          :on-copy-json="copyJson"
          :on-copy-env="copyEnv"
          :on-copy-raw="copyRaw"
          :on-open-raw-editor="openRawEditor"
          :on-close="closeModal"
        />
        <div
            v-if="copyNotice"
            class="absolute bottom-6 right-6 rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] px-3 py-1.5 text-xs text-[var(--text-primary)] shadow-lg"
        >
          {{ copyNotice }}
        </div>

        <div
            v-if="pastePromptOpen"
            class="mt-3 flex items-center justify-between gap-3 rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] px-3 py-2 text-sm"
        >
          <span class="text-[var(--text-primary)]">{{ pastePromptMessage }}</span>
          <div class="flex items-center gap-2">
            <button
                type="button"
                class="rounded-md px-3 py-1 text-xs font-semibold text-[var(--accent)] hover:bg-[var(--bg-hover)]"
                @click="applyPastePayload"
            >
              {{ t("create.pasteReplace") }}
            </button>
            <button
                type="button"
                class="rounded-md px-3 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
                @click="dismissPastePrompt"
            >
              {{ t("common.cancel") }}
            </button>
          </div>
        </div>

        <CreateVaultForm
          v-if="createMode === 'vault'"
          v-model:create-vault-name="createVaultName"
          v-model:create-vault-kind="createVaultKind"
          v-model:create-vault-cache-policy="createVaultCachePolicy"
          v-model:create-vault-default="createVaultDefault"
          :t="t"
        />

        <div
            v-else
            :class="isPanel ? 'mt-4 space-y-4' : 'mt-4 space-y-4 max-h-[60vh] overflow-y-auto'"
        >
          <label v-if="!isPanel" class="block space-y-1 text-sm">
          <span class="font-medium uppercase tracking-wide text-xs text-[var(--text-secondary)]">
            {{ t("create.itemLocation") }}
          </span>
            <p class="text-xs text-[var(--text-tertiary)]">
              {{ t("create.itemPathHint") }}
            </p>
            <SmartPathInput
                v-model="currentPathInput"
                :vault-name="selectedVaultName()"
                :path-tokens="pathTokens"
                :token-delete-armed="tokenDeleteArmed"
                :vault-shake="vaultShake"
                :placeholder="t('create.itemTitlePlaceholder')"
                :suggestions="filteredPathSuggestions"
                :has-error="['name_required', 'vault_required'].includes(props.createItemErrorKey)"
                input-test-id="create-path"
                @focus="showFolderSuggestions = true"
                @blur="scheduleHideFolderSuggestions"
                @keydown="handlePathKeydown"
                @paste="handlePathPaste"
                @apply-suggestion="applySuggestion"
            />
            <span
              v-if="['name_required', 'vault_required'].includes(props.createItemErrorKey)"
              class="text-xs text-category-security"
            >
              {{ createItemError }}
            </span>
          </label>

          <div class="flex flex-wrap items-center justify-between gap-3">
          <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">
            {{ t("create.itemData") }}
          </span>
          </div>

          <template v-if="createItemType === 'kv'">
            <div :class="props.createItemErrorKey === 'fields_required' ? 'rounded-lg ring-2 ring-category-security/40' : ''">
            <CreateKvTable
                :fields="createItemFields"
                :can-remove="canRemoveKvRow"
                :revealed-fields="revealedFields"
                :alt-reveal-all="props.altRevealAll"
                :t="t"
                :add-custom-field="() => addCustomField(false)"
                :remove-field="removeField"
                :generate-secret="generateSecret"
                  v-model:generator-open-id="generatorOpenId"
                  v-model:generator-length="generatorLength"
                  v-model:generator-include-upper="generatorIncludeUpper"
                  v-model:generator-include-lower="generatorIncludeLower"
                  v-model:generator-include-digits="generatorIncludeDigits"
                  v-model:generator-include-symbols="generatorIncludeSymbols"
                  v-model:generator-avoid-ambiguous="generatorAvoidAmbiguous"
                  v-model:generator-memorable="generatorMemorable"
              />
            </div>
            <span
              v-if="props.createItemErrorKey === 'fields_required'"
              class="text-xs text-category-security"
            >
              {{ createItemError }}
            </span>
          </template>

          <template v-else>
            <div
              class="space-y-4"
              :class="props.createItemErrorKey === 'fields_required' ? 'rounded-lg ring-2 ring-category-security/40' : ''"
            >
              <CreateMainFields
                  :fields="mainFields"
                  :revealed-fields="revealedFields"
                  :alt-reveal-all="props.altRevealAll"
                  :get-field-label="getFieldLabel"
                  :t="t"
                  :generate-secret="generateSecret"
                  v-model:generator-open-id="generatorOpenId"
                  v-model:generator-length="generatorLength"
                  v-model:generator-include-upper="generatorIncludeUpper"
                  v-model:generator-include-lower="generatorIncludeLower"
                  v-model:generator-include-digits="generatorIncludeDigits"
                  v-model:generator-include-symbols="generatorIncludeSymbols"
                  v-model:generator-avoid-ambiguous="generatorAvoidAmbiguous"
                  v-model:generator-memorable="generatorMemorable"
              />

              <CreateAdvancedFields
                  v-model:advanced-open="advancedOpen"
                  :advanced-fields="advancedFields"
                  :custom-fields="customFields"
                  :revealed-fields="revealedFields"
                  :alt-reveal-all="props.altRevealAll"
                  :get-field-label="getFieldLabel"
                  :t="t"
                  :add-custom-field="addCustomField"
                  :remove-field="removeField"
                  :generate-secret="generateSecret"
                  v-model:generator-open-id="generatorOpenId"
                  v-model:generator-length="generatorLength"
                  v-model:generator-include-upper="generatorIncludeUpper"
                  v-model:generator-include-lower="generatorIncludeLower"
                  v-model:generator-include-digits="generatorIncludeDigits"
                  v-model:generator-include-symbols="generatorIncludeSymbols"
                  v-model:generator-avoid-ambiguous="generatorAvoidAmbiguous"
                  v-model:generator-memorable="generatorMemorable"
              />
            </div>
            <span
              v-if="props.createItemErrorKey === 'fields_required'"
              class="text-xs text-category-security"
            >
              {{ createItemError }}
            </span>

          </template>
        </div>

        <p
          v-if="
            createVaultError ||
            (createItemError &&
              !['vault_required', 'name_required', 'fields_required'].includes(props.createItemErrorKey))
          "
          class="mt-3 text-sm text-category-security"
        >
          {{ createVaultError || createItemError }}
        </p>

        <div v-if="!isPanel" class="mt-6 flex justify-end gap-2">
          <button
              type="button"
              class="rounded-lg px-4 py-2 text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
              @click="closeModal"
          >
            {{ t("common.close") }}
          </button>
          <button
              type="button"
              class="flex items-center gap-2 rounded-lg bg-gray-800 dark:bg-gray-600 px-4 py-2 text-sm font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
              :disabled="createItemBusy || createVaultBusy"
              @click="submitCreate"
          >
            <svg
                v-if="createItemBusy || createVaultBusy"
                class="h-4 w-4 animate-spin"
                viewBox="0 0 24 24"
                fill="none"
            >
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
            </svg>
            <span>{{ props.createEditingItemId ? t("common.save") : t("common.create") }}</span>
          </button>
        </div>
      </div>

      <CreateRawEditorModal
        v-model:open="rawEditOpen"
        v-model:raw-json-text="rawJsonText"
        :json-placeholder-text="jsonPlaceholderText"
        :error-key="rawJsonErrorKey"
        :t="t"
        :on-save="applyRawEditor"
        :on-close="closeRawEditor"
        :on-validation="(key) => (rawJsonErrorKey = key)"
      />
    </div>
  </component>
</template>
