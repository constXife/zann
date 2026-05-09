import { computed, onBeforeUnmount, ref, watch } from "vue";
import type { ComputedRef, Ref } from "vue";
import type { ItemCounts, ItemSummary } from "../../../types";

type AppItemFiltersOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  items: Ref<ItemSummary[]>;
  itemCounts?: Ref<ItemCounts | null> | ComputedRef<ItemCounts | null>;
  isSharedVault: ComputedRef<boolean>;
  selectedFolder: Ref<string | null>;
  selectedCategory?: Ref<string | null>;
};

export function useAppItemFilters({
  t,
  items,
  itemCounts,
  isSharedVault,
  selectedFolder,
  selectedCategory: selectedCategoryRef,
}: AppItemFiltersOptions) {
  const selectedCategory = selectedCategoryRef ?? ref<string | null>(null);
  const query = ref("");
  const debouncedQuery = ref("");
  const DEBOUNCE_MS = 250;
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  const infraTypes = new Set([
    "ssh_key",
    "database",
    "cloud_iam",
    "file_secret",
    "server_credentials",
  ]);

  const isDeletedItem = (item: ItemSummary) => !!item.deleted_at;

  const categoryCounts = computed(() => {
    const counts: Record<string, number> = {
      all: 0,
      login: 0,
      note: 0,
      card: 0,
      identity: 0,
      api: 0,
      kv: 0,
      infra: 0,
      trash: 0,
    };
    if (itemCounts?.value) {
      const byType = itemCounts.value.by_type ?? {};
      counts.all = itemCounts.value.all ?? 0;
      counts.trash = itemCounts.value.trash ?? 0;
      counts.login = byType.login ?? 0;
      counts.note = byType.note ?? 0;
      counts.card = byType.card ?? 0;
      counts.identity = byType.identity ?? 0;
      counts.api = byType.api ?? 0;
      counts.kv = byType.kv ?? 0;
      counts.infra = 0;
      infraTypes.forEach((typeId) => {
        counts.infra += byType[typeId] ?? 0;
      });
      return counts;
    }
    items.value.forEach((item) => {
      if (isDeletedItem(item)) {
        counts.trash++;
        return;
      }
      counts.all++;
      if (counts[item.type_id] !== undefined) {
        counts[item.type_id]++;
      }
      if (infraTypes.has(item.type_id)) {
        counts.infra++;
      }
    });
    return counts;
  });

  const categories = computed(() => [
    { id: "all", icon: "grid", label: t("nav.allItems") },
    { id: "login", icon: "key", label: t("nav.logins") },
    { id: "note", icon: "doc", label: t("nav.notes") },
    { id: "card", icon: "card", label: t("nav.cards") },
    { id: "identity", icon: "person", label: t("nav.identity") },
    { id: "api", icon: "network", label: t("nav.api") },
    { id: "kv", icon: "list", label: t("nav.kv") },
    { id: "infra", icon: "network", label: t("nav.infrastructure") },
    {
      id: "trash",
      icon: "trash",
      label: isSharedVault.value ? t("items.trashShared") : t("nav.trash"),
    },
  ]);

  const selectCategory = (categoryId: string) => {
    selectedCategory.value = categoryId;
  };

  watch(
    query,
    (value) => {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(() => {
        debouncedQuery.value = value;
      }, DEBOUNCE_MS);
    },
    { immediate: true },
  );

  onBeforeUnmount(() => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
  });

  const filteredItems = computed(() => {
    let result = items.value;
    if (selectedCategory.value === "trash") {
      result = result.filter((item) => isDeletedItem(item));
    } else {
      result = result.filter((item) => !isDeletedItem(item));
    }

    if (
      selectedCategory.value &&
      selectedCategory.value !== "all" &&
      selectedCategory.value !== "trash"
    ) {
      if (selectedCategory.value === "infra") {
        result = result.filter((item) => infraTypes.has(item.type_id));
      } else {
        result = result.filter((item) => item.type_id === selectedCategory.value);
      }
    }

    if (selectedFolder.value !== null) {
      if (selectedFolder.value === "") {
        result = result.filter((item) => !item.path.includes("/"));
      } else {
        result = result.filter((item) => {
          const parts = item.path.split("/");
          parts.pop();
          const folder = parts.join("/");
          return (
            folder === selectedFolder.value ||
            folder.startsWith(selectedFolder.value + "/")
          );
        });
      }
    }

    if (debouncedQuery.value.trim()) {
      const needle = debouncedQuery.value.toLowerCase();
      result = result.filter((item) =>
        [item.name, item.path, item.type_id].some((value) =>
          value.toLowerCase().includes(needle),
        ),
      );
    }

    return result;
  });

  return {
    selectedCategory,
    query,
    categoryCounts,
    categories,
    selectCategory,
    filteredItems,
    isDeletedItem,
  };
}
