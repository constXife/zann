<script setup lang="ts">
import { computed, nextTick, onErrorCaptured, onMounted, ref, toRef, watch } from "vue";
import Button from "./ui/Button.vue";
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
import type { CachePolicy, VaultKind } from "../constants/enums";
import { allowTokenBeforeInput, allowTokenKeydown, handleTokenPaste } from "../utils/inputSanitizer";

const createModalOpen = defineModel<boolean>("open", { required: true });
const createItemVaultId = defineModel<string | null>("createItemVaultId", { required: true });
const createItemType = defineModel<string>("createItemType", { required: true });
const createItemTitle = defineModel<string>("createItemTitle", { required: true });
const createItemFolder = defineModel<string>("createItemFolder", { required: true });
const kvFilter = defineModel<string>("kvFilter", { required: true });
const advancedOpen = defineModel<boolean>("advancedOpen", { required: true });
const createVaultName = defineModel<string>("createVaultName", { required: true });
const createVaultKind = defineModel<VaultKind>("createVaultKind", { required: true });
const createVaultCachePolicy = defineModel<CachePolicy>("createVaultCachePolicy", { required: true });
const createVaultDefault = defineModel<boolean>("createVaultDefault", { required: true });
const showFolderSuggestions = defineModel<boolean>("showFolderSuggestions", { required: true });

const props = defineProps<{
  createMode: "vault" | "item" | null;
  variant?: "modal" | "panel";
  isOffline?: boolean;
  vaults: VaultSummary[];
  flatFolderPaths: string[];
  createItemFields: FieldInput[];
  filteredKvFields: FieldInput[];
  mainFields: FieldInput[];
  advancedFields: FieldInput[];
  customFields: FieldInput[];
  typeOptions: string[];
  typeGroups: { id: string; label: string; types: string[] }[];
  showAllTypesOption?: boolean;
  enableAllTypes?: () => void;
  openTypeMenuOnOpen?: boolean;
  consumeOpenTypeMenu?: () => void;
  openConfirm?: (options: {
    title: string;
    message: string;
    confirmLabel: string;
    cancelLabel?: string;
    onConfirm: () => Promise<void> | void;
  }) => void;
  createVaultError: string;
  createItemError: string;
  createItemErrorKey: string;
  createItemBusy: boolean;
  createItemValid: boolean;
  createVaultBusy: boolean;
  createVaultValid: boolean;
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
const submitDisabled = computed(() => {
  if (props.createMode === "vault") {
    return !props.createVaultValid;
  }
  if (props.createMode === "item") {
    return !props.createItemValid;
  }
  return true;
});
const submitDisabledReason = computed(() => {
  if (!submitDisabled.value) return "";
  if (props.createMode === "vault") {
    return t("errors.name_required");
  }
  if (props.createMode === "item") {
    if (!createItemVaultId.value) return t("errors.vault_required");
    if (!createItemTitle.value.trim()) return t("errors.name_required");
    if (props.createItemError) return props.createItemError;
  }
  return t("errors.name_required");
});
const submitTitle = computed(() => submitDisabledReason.value || "");

const nameInputEl = ref<HTMLInputElement | null>(null);
const pathInputRef = ref<{ focusInput?: () => void } | null>(null);
const kvTableRef = ref<{ focusFirstKey?: () => void } | null>(null);
const focusDefaultField = async () => {
  if (!createModalOpen.value || props.createMode !== "item") {
    return;
  }
  await nextTick();
  if (createItemType.value === "kv" && createItemTitle.value.trim()) {
    kvTableRef.value?.focusFirstKey?.();
    return;
  }
  nameInputEl.value?.focus();
  nameInputEl.value?.select();
};

watch(
  () => createModalOpen.value,
  (open) => {
    if (open) {
      void focusDefaultField();
    }
  },
);

onMounted(() => {
  void focusDefaultField();
});

watch(
  () => props.createMode,
  (mode) => {
    if (mode === "item" && createModalOpen.value) {
      void focusDefaultField();
    }
  },
);

watch(
  () => props.createItemErrorKey,
  (key) => {
    if (key === "fields_required") {
      kvTableRef.value?.focusFirstKey?.();
    }
  },
);

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
  applyPathInsert,
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
  shouldConfirmTypeChange: () => {
    const hasData = props.createItemFields.some((field) => {
      if (field.isCustom) {
        return field.key.trim().length > 0 || field.value.trim().length > 0;
      }
      return field.value.trim().length > 0;
    });
    return hasData;
  },
  confirmTypeChange: (nextTypeId, onConfirm) => {
    if (props.openConfirm) {
      props.openConfirm({
        title: t("create.changeTypeTitle"),
        message: t("create.changeTypeBody"),
        confirmLabel: t("create.changeTypeConfirm"),
        cancelLabel: t("common.cancel"),
        onConfirm,
      });
      return true;
    }
    if (window.confirm(t("create.changeTypeBody"))) {
      onConfirm();
    }
    return true;
  },
});

// Removed auto-open of type dropdown on create.
</script>
<template>
  <component
      :is="isPanel ? 'section' : 'div'"
      v-if="createModalOpen"
      :class="isPanel
      ? 'flex min-w-0 shrink-0 flex-col overflow-y-auto border-l border-[var(--border-color)] bg-[var(--bg-secondary)]'
      : 'fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl'"
      @click.self="!isPanel && closeModal()"
      @paste="handlePaste"
  >
    <CreatePanelHeader
      v-if="isPanel && createMode === 'item'"
      :vault-name="selectedVaultName()"
      :item-title="nameInput"
      :folder-label="createItemFolder"
      :busy="createItemBusy"
      :submit-disabled="submitDisabled"
      :submit-title="submitTitle"
      :is-editing="Boolean(props.createEditingItemId)"
      :is-offline="props.isOffline"
      :type-menu-open="typeMenuOpen"
      :type-options="typeOptions"
      :type-groups="typeGroups"
      :show-all-types-option="Boolean(props.showAllTypesOption)"
      :on-show-all-types="props.enableAllTypes"
      :type-meta="typeMeta"
      :current-type-label="currentTypeLabel"
      :current-type-icon="currentTypeIcon"
      :current-type-id="createItemType"
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
        ? 'w-full max-w-[640px] mx-auto px-6 py-6'
        : 'w-full max-w-[640px] rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl relative'"
    >
      <div
          :class="isPanel
          ? 'rounded-2xl border border-[var(--border-color)] bg-[var(--bg-tertiary)] p-6 shadow-sm'
          : ''"
      >
    <CreateModalHeader
      v-if="!isPanel"
      :create-mode="createMode"
      :is-editing="Boolean(props.createEditingItemId)"
      :type-menu-open="typeMenuOpen"
      :copy-menu-open="copyMenuOpen"
      :type-options="typeOptions"
      :type-groups="typeGroups"
      :show-all-types-option="Boolean(props.showAllTypesOption)"
      :on-show-all-types="props.enableAllTypes"
      :type-meta="typeMeta"
      :current-type-label="currentTypeLabel"
      :current-type-icon="currentTypeIcon"
      :current-type-id="createItemType"
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
            <Button
                variant="link"
                size="xs"
                @click="applyPastePayload"
            >
              {{ t("create.pasteReplace") }}
            </Button>
            <Button
                variant="secondary"
                size="xs"
                @click="dismissPastePrompt"
            >
              {{ t("common.cancel") }}
            </Button>
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
          <label
            class="block space-y-2 text-xs text-[var(--text-tertiary)]"
            :class="isPanel ? '' : 'text-[var(--text-secondary)]'"
          >
            <span
              class="font-semibold uppercase tracking-wide"
              :class="isPanel ? '' : 'text-xs'"
            >
              {{ t("create.itemTitle") }}
            </span>
            <input
              v-model="nameInput"
              ref="nameInputEl"
              type="text"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              class="w-full rounded-lg bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
              :class="['name_required', 'name_invalid_chars', 'name_too_long', 'item_exists'].includes(props.createItemErrorKey) ? 'bg-category-security/10 ring-2 ring-category-security/40' : ''"
              :placeholder="isPanel ? t('create.itemTitlePlaceholderPanel') : t('create.itemTitlePlaceholder')"
              data-testid="create-name"
              @beforeinput="allowTokenBeforeInput"
              @keydown="allowTokenKeydown"
              @paste="handleTokenPaste"
            />
            <span class="text-[11px] text-[var(--text-tertiary)]">
              {{ t("create.itemTitleHelp") }}
            </span>
            <span
              v-if="['name_required', 'name_invalid_chars', 'name_too_long', 'item_exists'].includes(props.createItemErrorKey)"
              class="text-xs text-category-security"
            >
              {{ createItemError }}
            </span>
          </label>

          <label class="block space-y-1 text-sm">
            <span
              class="font-medium uppercase tracking-wide text-xs text-[var(--text-secondary)]"
              :class="isPanel ? 'text-[var(--text-tertiary)] font-semibold' : ''"
            >
              {{ isPanel ? t("create.itemPath") : t("create.itemLocation") }}
            </span>
            <p v-if="!isPanel" class="text-xs text-[var(--text-tertiary)]">
              {{ t("create.itemPathHint") }}
            </p>
            <SmartPathInput
                v-model="currentPathInput"
                ref="pathInputRef"
                :dense="isPanel"
                :vault-name="selectedVaultName()"
                :path-tokens="pathTokens"
                :token-delete-armed="tokenDeleteArmed"
                :vault-shake="vaultShake"
                :placeholder="t('create.itemFolderPlaceholder')"
                :suggestions="filteredPathSuggestions"
                :has-error="(isPanel
                  ? ['vault_required', 'path_invalid', 'path_segment_invalid', 'path_segment_invalid_chars', 'path_segments_limit', 'path_too_long']
                  : ['name_required', 'name_invalid_chars', 'name_too_long', 'item_exists', 'vault_required', 'path_invalid', 'path_segment_invalid', 'path_segment_invalid_chars', 'path_segments_limit', 'path_too_long']
                ).includes(props.createItemErrorKey)"
                input-test-id="create-path"
                @focus="showFolderSuggestions = true"
                @blur="scheduleHideFolderSuggestions"
                @keydown="handlePathKeydown"
                @paste="handlePathPaste"
                @insert-path="applyPathInsert"
                @apply-suggestion="applySuggestion"
            />
            <p class="text-xs text-[var(--text-tertiary)]">
              {{ t("create.itemPathBackspaceHint") }}
            </p>
            <span
              v-if="(isPanel
                ? ['vault_required', 'path_invalid', 'path_segment_invalid', 'path_segment_invalid_chars', 'path_segments_limit', 'path_too_long']
                : ['name_required', 'name_invalid_chars', 'name_too_long', 'item_exists', 'vault_required', 'path_invalid', 'path_segment_invalid', 'path_segment_invalid_chars', 'path_segments_limit', 'path_too_long']
              ).includes(props.createItemErrorKey)"
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
          <p
            v-if="createItemType === 'kv'"
            class="text-xs text-[var(--text-tertiary)]"
          >
            {{ t("create.kvHint") }}
          </p>

          <template v-if="createItemType === 'kv'">
            <div :class="['fields_required', 'field_key_invalid', 'field_key_duplicate'].includes(props.createItemErrorKey) ? 'rounded-lg ring-2 ring-category-security/40' : ''">
            <CreateKvTable
                ref="kvTableRef"
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
              v-if="['fields_required', 'field_key_invalid', 'field_key_duplicate'].includes(props.createItemErrorKey)"
              class="text-xs text-category-security"
            >
              {{ createItemError }}
            </span>
          </template>

          <template v-else>
            <div
              class="space-y-4"
              :class="['fields_required', 'field_key_invalid', 'field_key_duplicate'].includes(props.createItemErrorKey) ? 'rounded-lg ring-2 ring-category-security/40' : ''"
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
              v-if="['fields_required', 'field_key_invalid', 'field_key_duplicate'].includes(props.createItemErrorKey)"
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
              !['vault_required', 'name_required', 'name_invalid_chars', 'name_too_long', 'item_exists', 'path_invalid', 'path_segment_invalid', 'path_segment_invalid_chars', 'path_segments_limit', 'path_too_long', 'fields_required', 'field_key_invalid', 'field_key_duplicate'].includes(props.createItemErrorKey))
          "
          class="mt-3 text-sm text-category-security"
          data-testid="create-error"
        >
          {{ createVaultError || createItemError }}
        </p>

        <div v-if="!isPanel" class="mt-6 flex justify-end gap-2">
          <Button
              variant="secondary"
              size="sm"
              @click="closeModal"
          >
            {{ t("common.close") }}
          </Button>
          <Button
              size="sm"
              :loading="createItemBusy || createVaultBusy"
              :disabled="submitDisabled"
              :title="submitTitle"
              data-testid="create-submit"
              @click="submitCreate"
          >
            {{
              props.createEditingItemId
                ? t("common.save")
                : props.isOffline
                  ? t("create.createOffline")
                  : t("common.create")
            }}
          </Button>
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
