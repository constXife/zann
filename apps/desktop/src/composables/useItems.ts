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
  onFatalError: (message: string) => void;
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

  const setLoading = (value: boolean) => {
    options.listLoading.value = value;
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
    if (append) {
      items.value = [...items.value, ...response.data.items];
    } else {
      items.value = response.data.items;
    }
    nextCursor.value = response.data.next_cursor ?? null;
    totalCount.value = response.data.total_count;
    itemCounts.value = response.data.counts ?? null;
    hasMore.value = !!nextCursor.value;
  };

  const loadItems = async () => {
    if (!options.selectedVaultId.value || !options.initialized.value || !options.unlocked.value) {
      items.value = [];
      nextCursor.value = null;
      hasMore.value = false;
      totalCount.value = null;
      itemCounts.value = null;
      return;
    }
    setLoading(true);
    try {
      await fetchPage(null, false);
      options.onAfterLoad?.();
    } catch (err) {
      options.onFatalError(String(err));
    } finally {
      setLoading(false);
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
      options.onFatalError(String(err));
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
