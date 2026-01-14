import type { ComputedRef, Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type {
  ApiResponse,
  EncryptedPayload,
  FieldRow,
  ItemHistorySummary,
  ItemDetail,
  ItemSummary,
} from "../../../types";
import { createErrorWithCause } from "../../errors";

type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  confirmInputExpected?: string;
  confirmInputLabel?: string;
  confirmInputPlaceholder?: string;
  onConfirm: () => Promise<void> | void;
};

type AppItemActionsOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  selectedStorageId: Ref<string>;
  selectedVaultName: ComputedRef<string>;
  isSharedVault: ComputedRef<boolean>;
  selectedCategory: Ref<string | null>;
  selectedItemId: Ref<string | null>;
  selectedItem: Ref<ItemDetail | null>;
  items: Ref<ItemSummary[]>;
  detailSections: Ref<{ fields: FieldRow[] }[]>;
  fetchHistoryPayload: (version: number) => Promise<EncryptedPayload | null>;
  loadItemDetail: (itemId: string) => Promise<void>;
  loadItems: () => Promise<void>;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  scheduleRemoteSync: (storageId: string | null) => void;
  copyToClipboard: (value: string) => Promise<void>;
  findPrimarySecret: (sections: { fields: FieldRow[] }[]) => FieldRow | null;
  openConfirm: (options: ConfirmOptions) => void;
  showToast: (message: string, options?: { duration?: number }) => void;
  setError: (message: string) => void;
  isDeletedItem: (item: ItemSummary) => boolean;
  localStorageId: string;
};

export function useAppItemActions({
  t,
  selectedStorageId,
  selectedVaultName,
  isSharedVault,
  selectedCategory,
  selectedItemId,
  selectedItem,
  items,
  detailSections,
  fetchHistoryPayload,
  loadItemDetail,
  loadItems,
  runRemoteSync,
  scheduleRemoteSync,
  copyToClipboard,
  findPrimarySecret,
  openConfirm,
  showToast,
  setError,
  isDeletedItem,
  localStorageId,
}: AppItemActionsOptions) {
  const copyField = async (field: FieldRow) => {
    await copyToClipboard(field.value);
  };

  const buildFieldsRecord = () => {
    const record: Record<string, string> = {};
    detailSections.value
      .flatMap((section) => section.fields)
      .forEach((field) => {
        record[field.path] = field.value;
      });
    return record;
  };

  const copyEnv = async () => {
    if (!selectedItem.value) {
      return;
    }
    const lines = detailSections.value
      .flatMap((section) => section.fields)
      .map((field) => `${field.path}=${field.value}`);
    const payload = lines.length ? `${lines.join("\n")}\n` : "";
    await copyToClipboard(payload);
  };

  const copyJson = async () => {
    if (!selectedItem.value) {
      return;
    }
    const payload = JSON.stringify(buildFieldsRecord(), null, 2);
    await copyToClipboard(payload);
  };

  const copyRaw = async () => {
    if (!selectedItem.value) {
      return;
    }
    const payload = JSON.stringify(selectedItem.value.payload, null, 2);
    await copyToClipboard(payload);
  };

  const extractHistoryPassword = (payload: EncryptedPayload) => {
    const fields = payload.fields ?? {};
    const entry = Object.values(fields).find((field) => field.kind === "password");
    return entry?.value ?? null;
  };

  const copyHistoryPassword = async (version: number) => {
    if (!selectedItem.value) {
      return;
    }
    try {
      const payload = await fetchHistoryPayload(version);
      if (!payload) {
        showToast(t("items.historyVersionMissing"));
        return;
      }
      const password = extractHistoryPassword(payload);
      await copyToClipboard(password ?? JSON.stringify(payload, null, 2));
      showToast(t("items.historyCopySuccess"));
    } catch (err) {
      showToast(t("items.historyCopyFailed"));
      console.warn("[history] copy_failed", { error: String(err) });
    }
  };

  const restoreHistoryVersion = (entry: ItemHistorySummary) => {
    if (!selectedItem.value) {
      return;
    }
    openConfirm({
      title: t("items.restorePreviousTitle"),
      message: t("items.restorePreviousMessage"),
      confirmLabel: t("items.restorePreviousConfirm"),
      cancelLabel: t("common.cancel"),
      onConfirm: async () => {
        try {
          const response = await invoke<ApiResponse<null>>("items_history_restore", {
            req: {
              storage_id: selectedStorageId.value,
              vault_id: selectedItem.value?.vault_id,
              item_id: selectedItem.value?.id,
              version: entry.version,
            },
          });
          if (!response.ok) {
            const key = response.error?.kind ?? "generic";
            const detail = response.error?.message
              ? `${t(`errors.${key}`)}: ${response.error.message}`
              : t(`errors.${key}`);
            throw createErrorWithCause(detail, response.error);
          }
          await runRemoteSync(selectedStorageId.value);
          await loadItemDetail(selectedItem.value!.id);
          showToast(t("items.restorePreviousDone"));
        } catch (err) {
          setError(String(err));
          showToast(String(err), { duration: 1800 });
        }
      },
    });
  };

  const copyPrimarySecret = async () => {
    if (!selectedItem.value) {
      return;
    }
    const primary = findPrimarySecret(detailSections.value);
    if (primary) {
      await copyToClipboard(primary.value);
    }
  };

  const openTrash = () => {
    selectedCategory.value = "trash";
    selectedItemId.value = null;
  };

  const doDeleteItem = async (itemId: string, storageId: string) => {
    try {
      const response = await invoke<ApiResponse<null>>("items_delete", {
        req: {
          storage_id: storageId,
          item_id: itemId,
        },
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      if (selectedItemId.value === itemId) {
        selectedItemId.value = null;
      }
      await loadItems();
      if (storageId !== localStorageId) {
        scheduleRemoteSync(storageId);
      }
      showToast(t("common.deleted"));
    } catch (err) {
      setError(String(err));
      showToast(String(err), { duration: 1800 });
    }
  };

  const deleteItem = async () => {
    if (!selectedItemId.value) {
      return;
    }
    const itemId = selectedItemId.value;
    const storageId = selectedStorageId.value;
    const confirmMessage = isSharedVault.value
      ? t("items.moveToTrashSharedConfirm", { vault: selectedVaultName.value })
      : t("items.moveToTrashConfirm");
    openConfirm({
      title: t("items.moveToTrash"),
      message: confirmMessage,
      confirmLabel: t("items.moveToTrash"),
      onConfirm: () => doDeleteItem(itemId, storageId),
    });
  };

  const restoreItemById = async (
    storageId: string,
    itemId: string,
    options?: { selectAfter?: boolean },
  ) => {
    const response = await invoke<ApiResponse<null>>("items_restore", {
      req: {
        storage_id: storageId,
        item_id: itemId,
      },
    });
    if (!response.ok) {
      const key = response.error?.kind ?? "generic";
      throw createErrorWithCause(t(`errors.${key}`), response.error);
    }
    if (options?.selectAfter) {
      selectedItemId.value = itemId;
    } else if (selectedCategory.value === "trash") {
      selectedItemId.value = null;
    }
    await loadItems();
    if (storageId !== localStorageId) {
      scheduleRemoteSync(storageId);
    }
    showToast(t("items.restore"));
  };

  const restoreItem = async () => {
    if (!selectedItemId.value) {
      return;
    }
    try {
      await restoreItemById(selectedStorageId.value, selectedItemId.value);
    } catch (err) {
      setError(String(err));
      showToast(String(err), { duration: 1800 });
    }
  };

  const doPurgeItem = async (itemId: string, storageId: string) => {
    try {
      const response = await invoke<ApiResponse<null>>("items_purge", {
        req: {
          storage_id: storageId,
          item_id: itemId,
        },
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      if (selectedItemId.value === itemId) {
        selectedItemId.value = null;
      }
      await loadItems();
      showToast(t("items.deleteForever"));
    } catch (err) {
      setError(String(err));
      showToast(String(err), { duration: 1800 });
    }
  };

  const purgeItem = async () => {
    if (!selectedItemId.value) {
      return;
    }
    const itemId = selectedItemId.value;
    const storageId = selectedStorageId.value;
    const itemName = selectedItem.value?.name ?? "";
    const confirmMessage = isSharedVault.value
      ? t("items.deleteForeverSharedConfirm", { vault: selectedVaultName.value })
      : t("items.deleteForeverConfirm");
    openConfirm({
      title: t("items.deleteForever"),
      message: confirmMessage,
      confirmLabel: t("items.deleteForever"),
      confirmInputExpected: itemName,
      confirmInputLabel: itemName
        ? t("items.deleteForeverTypeNameLabel", { name: itemName })
        : "",
      confirmInputPlaceholder: itemName
        ? t("items.deleteForeverTypeNamePlaceholder")
        : "",
      onConfirm: () => doPurgeItem(itemId, storageId),
    });
  };

  const doEmptyTrash = async (storageId: string) => {
    try {
      const response = await invoke<ApiResponse<number>>("items_empty_trash", {
        req: {
          storage_id: storageId,
        },
      });
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw createErrorWithCause(t(`errors.${key}`), response.error);
      }
      selectedItemId.value = null;
      await loadItems();
      showToast(t("items.emptyTrash"));
    } catch (err) {
      setError(String(err));
      showToast(String(err), { duration: 1800 });
    }
  };

  const emptyTrash = async () => {
    const trashCount = items.value.filter((item) => isDeletedItem(item)).length;
    if (trashCount === 0) {
      return;
    }
    const storageId = selectedStorageId.value;
    const confirmMessage = isSharedVault.value
      ? t("items.emptyTrashSharedConfirm", {
          count: trashCount,
          vault: selectedVaultName.value,
        })
      : t("items.emptyTrashConfirm", { count: trashCount });
    openConfirm({
      title: t("items.emptyTrash"),
      message: confirmMessage,
      confirmLabel: t("items.emptyTrash"),
      onConfirm: () => doEmptyTrash(storageId),
    });
  };

  return {
    copyField,
    copyEnv,
    copyJson,
    copyRaw,
    copyHistoryPassword,
    restoreHistoryVersion,
    copyPrimarySecret,
    openTrash,
    deleteItem,
    restoreItem,
    purgeItem,
    emptyTrash,
  };
}
