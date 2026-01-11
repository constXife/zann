import { computed, nextTick, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, EncryptedPayload, FieldKind, FieldValue, ItemDetail, VaultSummary } from "../types";
import { getFieldSchema, getSchemaFieldDefs, resolveSchemaLabel, type FieldType } from "../data/secretSchemas";

type Translator = (key: string) => string;

type FieldInput = {
  id: string;
  key: string;
  value: string;
  fieldType: FieldType;
  isCustom: boolean;
  isSecret: boolean;
};

type UseCreateModalOptions = {
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
  selectedItemId: Ref<string | null>;
  vaults: Ref<VaultSummary[]>;
  selectedItem: Ref<ItemDetail | null>;
  selectedCategory: Ref<string | null>;
  lastCreateItemType: Ref<string>;
  loadItems: () => Promise<void>;
  loadVaults: () => Promise<void>;
  runRemoteSync: (storageId: string | null) => Promise<void>;
  localStorageId: string;
  t: Translator;
  onOptimisticHistory?: (payload: EncryptedPayload) => number | null;
  onOptimisticHistoryRollback?: (version: number) => void;
};

export const useCreateModal = (options: UseCreateModalOptions) => {
  const createModalOpen = ref(false);
  const createMode = ref<"vault" | "item" | null>(null);
  const createItemType = ref("login");
  const createItemFields = ref<FieldInput[]>([]);
  const createItemTitle = ref("");
  const createItemFolder = ref("");
  const createItemVaultId = ref<string | null>(null);
  const createEditingItemId = ref<string | null>(null);
  const createItemError = ref("");
  const createItemErrorKey = ref("");
  const createItemBusy = ref(false);
  const advancedOpen = ref(false);
  const kvFilter = ref("");
  const createVaultName = ref("");
  const createVaultKind = ref("personal");
  const createVaultCachePolicy = ref("full");
  const createVaultDefault = ref(false);
  const createVaultError = ref("");
  const createVaultBusy = ref(false);
  const typeOptions = ref<string[]>([]);
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
    "file_secret",
    "server_credentials",
  ];

  const currentSchema = computed(() => getFieldSchema(createItemType.value));

  let fieldIdCounter = 0;
  const nextFieldId = () => {
    if (globalThis.crypto?.randomUUID) {
      return globalThis.crypto.randomUUID();
    }
    fieldIdCounter += 1;
    return `f-${fieldIdCounter}`;
  };

  const mainFieldKeys = computed(() => new Set(currentSchema.value.main.map((d) => d.key)));
  const advancedFieldKeys = computed(() => new Set(currentSchema.value.advanced.map((d) => d.key)));

  const mainFields = computed(() =>
    createItemFields.value.filter((f) => !f.isCustom && mainFieldKeys.value.has(f.key))
  );
  const advancedFields = computed(() =>
    createItemFields.value.filter((f) => !f.isCustom && advancedFieldKeys.value.has(f.key))
  );
  const customFields = computed(() =>
    createItemFields.value.filter((f) => f.isCustom)
  );
  const filteredKvFields = computed(() => {
    if (!kvFilter.value.trim()) return createItemFields.value;
    const q = kvFilter.value.toLowerCase();
    return createItemFields.value.filter((f) => f.key.toLowerCase().includes(q));
  });

  const getFieldLabel = (key: string): string => {
    return resolveSchemaLabel(options.t, createItemType.value, key);
  };

  const flattenPayload = (payload: EncryptedPayload, typeId: string) => {
    const schemaDefs = getSchemaFieldDefs(typeId);
    const schemaKeys = new Set(schemaDefs.map((def) => def.key));
    const fields = payload.fields ?? {};
    const rows: FieldInput[] = [];

    schemaDefs.forEach((def) => {
      const entry = fields[def.key];
      if (!entry) return;
      const fieldType: FieldType =
        entry.kind === "password"
          ? "secret"
          : entry.kind === "otp"
            ? "otp"
            : entry.kind === "url"
              ? "url"
              : entry.kind === "note"
                ? "note"
                : "text";
      rows.push({
        id: nextFieldId(),
        key: def.key,
        value: entry.value,
        fieldType: def.type ?? fieldType,
        isCustom: false,
        isSecret: entry.kind === "password" || entry.kind === "otp" || entry.meta?.masked === true,
      });
    });

    const customKeys = Object.keys(fields).filter((key) => !schemaKeys.has(key));
    if (typeId !== "kv") {
      customKeys.sort((a, b) => a.localeCompare(b));
    }
    customKeys.forEach((key) => {
      const entry = fields[key];
      if (!entry) return;
      const fieldType: FieldType =
        entry.kind === "password"
          ? "secret"
          : entry.kind === "otp"
            ? "otp"
            : entry.kind === "url"
              ? "url"
              : entry.kind === "note"
                ? "note"
                : "text";
      rows.push({
        id: nextFieldId(),
        key,
        value: entry.value,
        fieldType,
        isCustom: true,
        isSecret: entry.kind === "password" || entry.kind === "otp" || entry.meta?.masked === true,
      });
    });

    return rows;
  };

  const typeGroups = computed(() => {
    const available = new Set(typeOptions.value.length ? typeOptions.value : defaultTypeOrder);
    const groups = [
      {
        id: "infra",
        label: options.t("create.typeGroupInfra"),
        types: ["ssh_key", "database", "cloud_iam", "file_secret", "server_credentials"].filter(
          (typeId) => available.has(typeId),
        ),
      },
      {
        id: "core",
        label: options.t("create.typeGroupGeneral"),
        types: ["login", "card", "note", "identity", "api", "kv"].filter((typeId) =>
          available.has(typeId),
        ),
      },
    ];
    return groups.filter((group) => group.types.length > 0);
  });

  const addCustomField = (isSecret: boolean) => {
    createItemFields.value = [
      ...createItemFields.value,
      {
        id: nextFieldId(),
        key: "",
        value: "",
        fieldType: isSecret ? "secret" : "text",
        isCustom: true,
        isSecret,
      },
    ];
  };

  const removeField = (id: string) => {
    createItemFields.value = createItemFields.value.filter((field) => field.id !== id);
  };

  const loadTypeOptions = async () => {
    if (typeOptions.value.length > 0) {
      return;
    }
    try {
      const response = await invoke<ApiResponse<string[]>>("types_list");
      if (response.ok && response.data) {
        typeOptions.value = response.data;
      }
    } catch {
      // noop
    }
  };

  const resetFieldsForType = async (typeId: string, prevFields?: FieldInput[]) => {
    const prior = prevFields ?? createItemFields.value;
    const prev = prior.reduce<Record<string, FieldInput>>((acc, field) => {
      acc[field.key] = field;
      return acc;
    }, {});
    const rows: FieldInput[] = [];
    const allSchemaDefs = getSchemaFieldDefs(typeId);
    const schemaKeys = new Set(allSchemaDefs.map((d) => d.key));

    if (typeId === "kv") {
      prior
        .filter((field) => field.key.trim() && field.value.trim())
        .forEach((field) => {
          rows.push({
            id: field.id || nextFieldId(),
            key: field.key,
            value: field.value,
            fieldType: field.fieldType,
            isCustom: true,
            isSecret: field.isSecret || field.fieldType === "secret" || field.fieldType === "otp",
          });
        });
      createItemFields.value = rows.length
        ? rows
        : [
            {
              id: nextFieldId(),
              key: "",
              value: "",
              fieldType: "text",
              isCustom: true,
              isSecret: false,
            },
          ];
      return;
    }

    if (typeId === "file_secret") {
      const notesDef = allSchemaDefs.find((def) => def.key === "notes");
      createItemFields.value = notesDef
        ? [
            {
              id: prev[notesDef.key]?.id ?? nextFieldId(),
              key: notesDef.key,
              value: prev[notesDef.key]?.value ?? "",
              fieldType: notesDef.type,
              isCustom: false,
              isSecret: false,
            },
          ]
        : [];
      return;
    }

    allSchemaDefs.forEach((def) => {
      const existing = prev[def.key];
      rows.push({
        id: existing?.id ?? nextFieldId(),
        key: def.key,
        value: existing?.value ?? "",
        fieldType: def.type,
        isCustom: false,
        isSecret: def.type === "secret" || def.type === "otp",
      });
    });

    const leftover = prior.filter(
      (field) => (field.isCustom || !schemaKeys.has(field.key)) && field.value.trim(),
    );
    const notesField = rows.find((field) => field.key === "notes");
    if (notesField && leftover.length > 0) {
      const appended = leftover
        .map((field) => `${field.key}: ${field.value}`)
        .join("\n");
      notesField.value = notesField.value
        ? `${notesField.value}\n${appended}`
        : appended;
    } else {
      leftover.forEach((field) => {
        rows.push({
          ...field,
          id: field.id || nextFieldId(),
          isCustom: true,
        });
      });
    }

    createItemFields.value = rows;
  };

  const resetCreateItemState = () => {
    createItemType.value = "login";
    createItemFields.value = [];
    createItemTitle.value = "";
    createItemFolder.value = "";
    createItemVaultId.value = options.selectedVaultId.value ?? null;
    createEditingItemId.value = null;
    createItemError.value = "";
    createItemErrorKey.value = "";
    createItemBusy.value = false;
    advancedOpen.value = false;
    kvFilter.value = "";
  };

  const resetCreateVaultState = () => {
    createVaultName.value = "";
    createVaultKind.value =
      options.selectedStorageId.value === options.localStorageId ? "personal" : "shared";
    createVaultCachePolicy.value = "full";
    createVaultDefault.value = false;
    createVaultError.value = "";
    createVaultBusy.value = false;
  };

  const openCreateModal = async (mode: "vault" | "item") => {
    createMode.value = mode;
    createItemError.value = "";
    createItemErrorKey.value = "";
    createVaultError.value = "";
    createEditingItemId.value = null;
    if (mode === "vault") {
      createVaultName.value = "";
      createVaultKind.value =
        options.selectedStorageId.value === options.localStorageId ? "personal" : "shared";
      createVaultCachePolicy.value = "full";
      createVaultDefault.value = options.vaults.value.length === 0;
    } else {
      await loadTypeOptions();
      const categoryType = options.selectedCategory.value;
      const preferredType =
        options.selectedItem.value?.type_id ??
        (typeOptions.value.includes(categoryType ?? "") ? categoryType : null) ??
        options.lastCreateItemType.value ??
        "login";
      createItemType.value = typeOptions.value.includes(preferredType)
        ? preferredType
        : typeOptions.value[0] ?? "login";
      createItemTitle.value = "";
      createItemFolder.value = "";
      createItemVaultId.value = options.selectedVaultId.value ?? options.vaults.value[0]?.id ?? null;
      advancedOpen.value = false;
      kvFilter.value = "";
      await resetFieldsForType(createItemType.value);
    }
    createModalOpen.value = true;
  };

  const openEditItem = async (payloadOverride?: EncryptedPayload) => {
    if (!options.selectedItem.value) {
      return;
    }
    createMode.value = "item";
    createItemErrorKey.value = "";
    createEditingItemId.value = options.selectedItem.value.id;
    createItemType.value = options.selectedItem.value.type_id;

    const pathParts = options.selectedItem.value.path.split("/");
    createItemTitle.value = pathParts.pop() ?? "";
    createItemFolder.value = pathParts.join("/");

    createItemVaultId.value = options.selectedItem.value.vault_id;
    advancedOpen.value = false;
    kvFilter.value = "";
    await loadTypeOptions();
    const payloadSource = payloadOverride ?? options.selectedItem.value.payload;
    createItemFields.value = flattenPayload(
      payloadSource,
      options.selectedItem.value.type_id,
    );
    createItemError.value = "";
    createModalOpen.value = true;
  };

  const submitCreateVault = async () => {
    createVaultError.value = "";
    if (!createVaultName.value.trim()) {
      createVaultError.value = options.t("errors.name_required");
      return;
    }
    createVaultBusy.value = true;
    try {
      const kind =
        options.selectedStorageId.value === options.localStorageId ? createVaultKind.value : "shared";
      const response = await invoke<ApiResponse<VaultSummary>>("vault_create", {
        req: {
          storage_id: options.selectedStorageId.value,
          name: createVaultName.value,
          kind,
          cache_policy: createVaultCachePolicy.value,
          is_default: createVaultDefault.value,
        },
      });
      if (!response.ok || !response.data) {
        const key = response.error?.kind ?? "generic";
        const message = response.error?.message;
        if (key === "remote_error" && message) {
          throw new Error(message);
        }
        throw new Error(options.t(`errors.${key}`));
      }
      await options.loadVaults();
      options.selectedVaultId.value = response.data.id;
      createModalOpen.value = false;
    } catch (err) {
      createVaultError.value = String(err);
    } finally {
      createVaultBusy.value = false;
    }
  };

  const buildFieldValue = (field: FieldInput): FieldValue => {
    const kind: FieldKind =
      field.fieldType === "otp"
        ? "otp"
        : field.fieldType === "url"
          ? "url"
          : field.fieldType === "note"
            ? "note"
            : field.isSecret || field.fieldType === "secret"
              ? "password"
              : "text";
    return {
      kind,
      value: field.value,
      meta: field.isSecret ? { masked: true } : undefined,
    };
  };

  const buildPayload = (typeId: string): EncryptedPayload => {
    const fields: Record<string, FieldValue> = {};
    createItemFields.value
      .filter((field) => field.key.trim() && field.value.trim())
      .forEach((field) => {
        const key = field.key.trim();
        fields[key] = buildFieldValue(field);
      });
    return {
      v: 1,
      typeId,
      fields,
    };
  };

  const applyPayload = (payload: EncryptedPayload, typeId: string) => {
    createItemFields.value = flattenPayload(payload, typeId);
  };

  const hasFieldValues = () =>
    createItemFields.value.some((field) => field.key.trim() && field.value.trim());

  const hasPasswordChange = (prev: EncryptedPayload, next: EncryptedPayload) => {
    const prevFields = prev.fields ?? {};
    const nextFields = next.fields ?? {};
    return Object.keys(prevFields).some((key) => {
      const prevField = prevFields[key];
      if (!prevField || prevField.kind !== "password") {
        return false;
      }
      const nextField = nextFields[key];
      if (!nextField || nextField.kind !== "password") {
        return true;
      }
      return prevField.value !== nextField.value;
    });
  };

  watch(createItemVaultId, (value) => {
    if (value && createItemErrorKey.value === "vault_required") {
      createItemErrorKey.value = "";
      createItemError.value = "";
    }
  });

  watch(createItemTitle, (value) => {
    if (value.trim() && createItemErrorKey.value === "name_required") {
      createItemErrorKey.value = "";
      createItemError.value = "";
    }
  });

  watch(
    createItemFields,
    () => {
      if (hasFieldValues() && createItemErrorKey.value === "fields_required") {
        createItemErrorKey.value = "";
        createItemError.value = "";
      }
    },
    { deep: true },
  );

  const submitCreateItem = async () => {
    createItemError.value = "";
    createItemErrorKey.value = "";
    if (!createItemVaultId.value) {
      createItemError.value = options.t("errors.vault_required");
      createItemErrorKey.value = "vault_required";
      return;
    }
    const title = createItemTitle.value.trim();
    if (!title) {
      createItemError.value = options.t("errors.name_required");
      createItemErrorKey.value = "name_required";
      return;
    }
    const folder = createItemFolder.value.trim();
    const path = folder ? `${folder}/${title}` : title;

    const hasValue = createItemFields.value.some(
      (field) => field.key.trim() && field.value.trim(),
    );
    if (!hasValue) {
      createItemError.value = options.t("errors.fields_required");
      createItemErrorKey.value = "fields_required";
      return;
    }
    const payload = buildPayload(createItemType.value);
    createItemBusy.value = true;
    let optimisticVersion: number | null = null;
    if (
      createEditingItemId.value &&
      options.selectedItem.value?.payload &&
      hasPasswordChange(options.selectedItem.value.payload, payload)
    ) {
      optimisticVersion = options.onOptimisticHistory?.(options.selectedItem.value.payload) ?? null;
    }
    try {
      const response = createEditingItemId.value
        ? await invoke<ApiResponse<string>>("items_update", {
            req: {
              storage_id: options.selectedStorageId.value,
              item_id: createEditingItemId.value,
              path,
              type_id: createItemType.value,
              payload,
            },
          })
        : await invoke<ApiResponse<string>>("items_put", {
            req: {
              storage_id: options.selectedStorageId.value,
              vault_id: createItemVaultId.value,
              path,
              type_id: createItemType.value,
              payload,
            },
          });
      if (!response.ok || !response.data) {
        const key = response.error?.kind ?? "generic";
        const message = response.error?.message;
        if (key === "remote_error" && message) {
          throw new Error(message);
        }
        throw new Error(options.t(`errors.${key}`));
      }
      createModalOpen.value = false;
      createItemTitle.value = "";
      createItemFolder.value = "";
      createEditingItemId.value = null;
      await options.loadItems();
      if (options.selectedItemId.value === response.data) {
        options.selectedItemId.value = null;
        await nextTick();
      }
      options.selectedItemId.value = response.data;
      if (options.selectedStorageId.value !== options.localStorageId) {
        await options.runRemoteSync(options.selectedStorageId.value);
      }
    } catch (err) {
      if (optimisticVersion !== null) {
        options.onOptimisticHistoryRollback?.(optimisticVersion);
      }
      createItemError.value = String(err);
    } finally {
      createItemBusy.value = false;
    }
  };

  const submitCreate = async () => {
    if (createMode.value === "vault") {
      await submitCreateVault();
    } else {
      await submitCreateItem();
    }
  };

  watch(createItemType, async (value) => {
    if (!createModalOpen.value || createMode.value !== "item") {
      return;
    }
    if (createEditingItemId.value) {
      return;
    }
    const prev = [...createItemFields.value];
    await resetFieldsForType(value, prev);
    options.lastCreateItemType.value = value;
  });

  watch(createModalOpen, (open) => {
    if (!open) {
      resetCreateItemState();
      resetCreateVaultState();
      createMode.value = null;
    }
  });

  watch(
    () => options.selectedVaultId.value,
    (vaultId) => {
      if (!createModalOpen.value || createMode.value !== "item") {
        return;
      }
      if (createEditingItemId.value) {
        return;
      }
      createItemVaultId.value = vaultId ?? null;
    },
  );

  return {
    createModalOpen,
    createMode,
    createItemType,
    createItemFields,
    createItemTitle,
    createItemFolder,
    createItemVaultId,
    createEditingItemId,
    createItemError,
    createItemErrorKey,
    createItemBusy,
    advancedOpen,
    kvFilter,
    createVaultName,
    createVaultKind,
    createVaultCachePolicy,
    createVaultDefault,
    createVaultError,
    createVaultBusy,
    typeOptions,
    typeGroups,
    currentSchema,
    mainFields,
    advancedFields,
    customFields,
    filteredKvFields,
    getFieldLabel,
    addCustomField,
    removeField,
    buildPayload,
    applyPayload,
    loadTypeOptions,
    resetFieldsForType,
    openCreateModal,
    openEditItem,
    submitCreate,
  };
};
