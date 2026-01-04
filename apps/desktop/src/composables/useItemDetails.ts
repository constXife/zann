import { computed, onBeforeUnmount, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type {
  ApiResponse,
  DetailSection,
  EncryptedPayload,
  FieldRow,
  ItemDetail,
  ItemHistoryDetail,
  ItemHistorySummary,
  Settings,
} from "../types";
import { getSchemaFieldDefs, getSchemaKeys } from "../data/secretSchemas";

type Translator = (key: string) => string;

type UseItemDetailsOptions = {
  selectedStorageId: Ref<string>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
  settings: Ref<Settings | null>;
  t: Translator;
  onError?: (message: string) => void;
};

export const useItemDetails = (options: UseItemDetailsOptions) => {
  const selectedItem = ref<ItemDetail | null>(null);
  const detailLoading = ref(false);
  const historyEntries = ref<ItemHistorySummary[]>([]);
  const historyLoading = ref(false);
  const historyError = ref("");
  const historyPayloads = ref(new Map<number, ItemHistoryDetail["payload"]>());
  const pendingHistoryEntries = ref<ItemHistorySummary[]>([]);
  const revealedFields = ref(new Set<string>());
  const revealTimer = ref<number | null>(null);
  const historyToken = ref(0);

  const loadItemDetail = async (itemId: string) => {
    if (!options.initialized.value || !options.unlocked.value) {
      return;
    }
    console.info("[details] load_item_start", { itemId });
    detailLoading.value = true;
    try {
      const response = await invoke<ApiResponse<ItemDetail>>("items_get", {
        req: { storage_id: options.selectedStorageId.value, item_id: itemId },
      });
      if (!response.ok || !response.data) {
        const key = response.error?.kind ?? "generic";
        const message = response.error?.message;
        throw new Error(message ?? options.t(`errors.${key}`));
      }
      selectedItem.value = response.data;
      historyEntries.value = [];
      historyPayloads.value = new Map();
      pendingHistoryEntries.value = [];
      historyError.value = "";
      await loadItemHistory(response.data);
      console.info("[details] load_item_ok", {
        itemId,
        name: response.data.name,
        vaultId: response.data.vault_id,
      });
    } catch (err) {
      options.onError?.(String(err));
      console.warn("[details] load_item_err", { itemId, error: String(err) });
    } finally {
      detailLoading.value = false;
    }
  };

  const loadItemHistory = async (item: ItemDetail) => {
    const current = historyToken.value + 1;
    historyToken.value = current;
    historyLoading.value = true;
    try {
      const response = await invoke<ApiResponse<ItemHistorySummary[]>>(
        "items_history_list",
        {
          req: {
            storage_id: options.selectedStorageId.value,
            vault_id: item.vault_id,
            item_id: item.id,
            limit: 5,
          },
        },
      );
      if (historyToken.value !== current) {
        return;
      }
      if (!response.ok || !response.data) {
        const key = response.error?.kind ?? "generic";
        const message = response.error?.message;
        throw new Error(message ?? options.t(`errors.${key}`));
      }
      const serverEntries = response.data;
      const reconciledPending = pendingHistoryEntries.value.filter((entry) => {
        const entryTs = Date.parse(entry.created_at);
        return !serverEntries.some((serverEntry) => {
          const serverTs = Date.parse(serverEntry.created_at);
          return Number.isFinite(entryTs) && Number.isFinite(serverTs) && serverTs >= entryTs;
        });
      });
      pendingHistoryEntries.value = reconciledPending;
      const pendingVersions = new Set(reconciledPending.map((entry) => entry.version));
      for (const key of historyPayloads.value.keys()) {
        if (key < 0 && !pendingVersions.has(key)) {
          historyPayloads.value.delete(key);
        }
      }
      historyEntries.value = [...reconciledPending, ...serverEntries];
    } catch (err) {
      if (historyToken.value !== current) {
        return;
      }
      historyEntries.value = [...pendingHistoryEntries.value];
      historyError.value = String(err);
    } finally {
      if (historyToken.value === current) {
        historyLoading.value = false;
      }
    }
  };

  const fetchHistoryPayload = async (version: number) => {
    if (!selectedItem.value) {
      return null;
    }
    const cached = historyPayloads.value.get(version);
    if (cached) {
      return cached;
    }
    const response = await invoke<ApiResponse<ItemHistoryDetail>>("items_history_get", {
      req: {
        storage_id: options.selectedStorageId.value,
        vault_id: selectedItem.value.vault_id,
        item_id: selectedItem.value.id,
        version,
      },
    });
    if (!response.ok || !response.data) {
      const key = response.error?.kind ?? "generic";
      const message = response.error?.message;
      if (key === "history_unavailable_shared") {
        throw new Error(options.t(`errors.${key}`));
      }
      throw new Error(message ?? options.t(`errors.${key}`));
    }
    historyPayloads.value.set(version, response.data.payload);
    return response.data.payload;
  };

  const isRevealed = (path: string) => revealedFields.value.has(path);

  const scheduleAutoHideReveal = () => {
    if (!options.settings.value || options.settings.value.auto_hide_reveal_seconds <= 0) {
      return;
    }
    if (revealTimer.value) {
      window.clearTimeout(revealTimer.value);
    }
    revealTimer.value = window.setTimeout(() => {
      revealedFields.value = new Set();
      revealTimer.value = null;
    }, options.settings.value.auto_hide_reveal_seconds * 1000);
  };

  const toggleReveal = (path: string) => {
    const next = new Set(revealedFields.value);
    if (next.has(path)) {
      next.delete(path);
    } else {
      next.add(path);
    }
    revealedFields.value = next;
    scheduleAutoHideReveal();
  };

  const revealAll = () => {
    const next = new Set<string>();
    detailSections.value.forEach((section) => {
      section.fields.forEach((field) => {
        if (field.masked) {
          next.add(field.path);
        }
      });
    });
    revealedFields.value = next;
    scheduleAutoHideReveal();
  };

  const revealToggle = () => {
    if (revealedFields.value.size > 0) {
      revealedFields.value = new Set();
    } else {
      revealAll();
    }
  };

  const clearRevealTimer = () => {
    if (revealTimer.value) {
      window.clearTimeout(revealTimer.value);
      revealTimer.value = null;
    }
  };

  const detailSections = computed<DetailSection[]>(() => {
    if (!selectedItem.value?.payload) {
      return [];
    }
    const payload = selectedItem.value.payload;
    const typeId = selectedItem.value.type_id;
    const schemaDefs = getSchemaFieldDefs(typeId);
    const schemaKeys = new Set(getSchemaKeys(typeId));
    const fields: FieldRow[] = [];
    const payloadFields = payload.fields ?? {};

    schemaDefs.forEach((def) => {
      const item = payloadFields[def.key];
      if (!item) return;
      const masked = item.meta?.masked ?? (item.kind === "password" || item.kind === "otp");
      const copyable = item.meta?.copyable ?? true;
      const revealable = item.meta?.masked ?? masked;
      fields.push({
        key: def.label ?? def.key,
        value: item.value,
        path: def.key,
        kind: item.kind,
        masked,
        copyable,
        revealable,
      });
    });

    const customKeys = Object.keys(payloadFields)
      .filter((key) => !schemaKeys.has(key))
      .sort((a, b) => a.localeCompare(b));
    customKeys.forEach((key) => {
      const item = payloadFields[key];
      if (!item) return;
      const masked = item.meta?.masked ?? (item.kind === "password" || item.kind === "otp");
      const copyable = item.meta?.copyable ?? true;
      const revealable = item.meta?.masked ?? masked;
      fields.push({
        key,
        value: item.value,
        path: key,
        kind: item.kind,
        masked,
        copyable,
        revealable,
      });
    });
    return fields.length
      ? [
          {
            title: "",
            fields,
          },
        ]
      : [];
  });

  const findPrimarySecret = (sections: DetailSection[]) => {
    const fields = sections.flatMap((section) => section.fields);
    return fields.find((field) => field.masked) ?? fields[0] ?? null;
  };

  onBeforeUnmount(clearRevealTimer);

  const addOptimisticHistory = (payload: EncryptedPayload) => {
    const version = -Date.now();
    const entry: ItemHistorySummary = {
      version,
      checksum: "local",
      change_type: "update",
      changed_by_name: null,
      changed_by_email: "local",
      created_at: new Date().toISOString(),
      pending: true,
    };
    pendingHistoryEntries.value = [entry, ...pendingHistoryEntries.value];
    historyEntries.value = [entry, ...historyEntries.value];
    historyPayloads.value.set(version, payload);
    historyError.value = "";
    historyLoading.value = false;
    return version;
  };

  const removeOptimisticHistory = (version: number) => {
    if (version >= 0) {
      return;
    }
    pendingHistoryEntries.value = pendingHistoryEntries.value.filter((entry) => entry.version !== version);
    historyEntries.value = historyEntries.value.filter((entry) => entry.version !== version);
    historyPayloads.value.delete(version);
  };

  return {
    selectedItem,
    detailLoading,
    detailSections,
    historyEntries,
    historyLoading,
    historyError,
    fetchHistoryPayload,
    revealedFields,
    loadItemDetail,
    isRevealed,
    toggleReveal,
    revealAll,
    revealToggle,
    clearRevealTimer,
    isCopyableByProfile: () => true,
    isRevealableByProfile: () => true,
    findPrimarySecret,
    addOptimisticHistory,
    removeOptimisticHistory,
  };
};
