import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { ApiResponse, ItemCounts, ItemsListResponse, ItemSummary } from "../types";
import { createErrorWithCause } from "./errors";

type Translator = (key: string) => string;

type UseItemsOptions = {
  selectedStorageId: Ref<string>;
  selectedVaultId: Ref<string | null>;
  initialized: Ref<boolean>;
  unlocked: Ref<boolean>;
  listLoading: Ref<boolean>;
  listLoadingMore?: Ref<boolean>;
  listError: Ref<string>;
  t: Translator;
  onAfterLoad?: () => void;
};

export const useItems = (options: UseItemsOptions) => {
  const items = ref<ItemSummary[]>([]);
  const nextCursor = ref<string | null>(null);
  const hasMore = ref(false);
  const totalCount = ref<number | null>(null);
  const itemCounts = ref<ItemCounts | null>(null);
  const defaultLimit = 200;

  const resetPageState = () => {
    nextCursor.value = null;
    hasMore.value = false;
    totalCount.value = null;
    itemCounts.value = null;
  };

  const setLoadingMore = (value: boolean) => {
    if (options.listLoadingMore) {
      options.listLoadingMore.value = value;
    } else {
      options.listLoading.value = value;
    }
  };

  const fetchPage = async (cursor?: string | null, append = false) => {
    const response = await invoke<ApiResponse<ItemsListResponse>>("items_list", {
      req: {
        storage_id: options.selectedStorageId.value,
        vault_id: options.selectedVaultId.value,
        include_deleted: true,
        limit: defaultLimit,
        cursor: cursor ?? null,
      },
    });
    if (!response.ok || !response.data) {
      const key = response.error?.kind ?? "generic";
      throw createErrorWithCause(options.t(`errors.${key}`), response.error);
    }
    items.value = append ? [...items.value, ...response.data.items] : response.data.items;
    nextCursor.value = response.data.next_cursor ?? null;
    totalCount.value = response.data.total_count;
    itemCounts.value = response.data.counts ?? null;
    hasMore.value = !!nextCursor.value;
    options.listError.value = "";
  };

  const loadItems = async (loadOptions?: { silent?: boolean }) => {
    const shouldToggleLoading = !loadOptions?.silent;
    if (!options.selectedVaultId.value || !options.initialized.value || !options.unlocked.value) {
      items.value = [];
      resetPageState();
      options.listError.value = "";
      if (shouldToggleLoading) {
        options.listLoading.value = false;
      }
      return;
    }
    if (shouldToggleLoading) {
      options.listLoading.value = true;
    }
    try {
      await fetchPage(null, false);
      options.onAfterLoad?.();
    } catch (err) {
      options.listError.value = String(err);
    } finally {
      if (shouldToggleLoading) {
        options.listLoading.value = false;
      }
    }
  };

  const loadMoreItems = async () => {
    if (!nextCursor.value || !options.selectedVaultId.value) {
      return;
    }
    if (options.listLoading.value || options.listLoadingMore?.value) {
      return;
    }
    setLoadingMore(true);
    try {
      await fetchPage(nextCursor.value, true);
    } catch (err) {
      options.listError.value = String(err);
    } finally {
      setLoadingMore(false);
    }
  };

  return {
    items,
    loadItems,
    loadMoreItems,
    hasMore,
    totalCount,
    itemCounts,
  };
};
