import { computed, onBeforeUnmount, ref, watch } from "vue";
import type { ComputedRef, Ref } from "vue";
import type { ItemCounts, ItemSummary } from "../../../types";
import { categoryForType, categoryTypes, type ItemCategoryId } from "../../../utils/itemCategories";

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
  const selectedSubtype = ref<string | null>(null);
  const query = ref("");
  const debouncedQuery = ref("");
  const categoryIds: ItemCategoryId[] = [
    "all",
    "login",
    "card",
    "note",
    "infra",
    "trash",
  ];
  const DEBOUNCE_MS = 250;
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const isDeletedItem = (item: ItemSummary) => !!item.deleted_at;

  const categoryCounts = computed(() => {
    const counts = categoryIds.reduce<Record<ItemCategoryId, number>>((acc, id) => {
      acc[id] = 0;
      return acc;
    }, {} as Record<ItemCategoryId, number>);

    if (itemCounts?.value) {
      const byType = itemCounts.value.by_type ?? {};
      counts.all = itemCounts.value.all ?? 0;
      counts.trash = itemCounts.value.trash ?? 0;
      categoryIds.forEach((categoryId) => {
        if (categoryId === "all" || categoryId === "trash") {
          return;
        }
        counts[categoryId] = categoryTypes(categoryId).reduce(
          (sum, typeId) => sum + (byType[typeId] ?? 0),
          0,
        );
      });
      return counts;
    }

    items.value.forEach((item) => {
      if (isDeletedItem(item)) {
        counts.trash++;
        return;
      }
      counts.all++;
      const category = categoryForType(item.type_id);
      if (category) {
        counts[category]++;
      }
    });
    return counts;
  });

  const categories = computed(() => [
    { id: "all", icon: "grid", label: t("nav.allItems") },
    { id: "login", icon: "key", label: t("nav.logins") },
    { id: "card", icon: "card", label: t("nav.cards") },
    { id: "note", icon: "doc", label: t("nav.notes") },
    { id: "infra", icon: "network", label: t("nav.infrastructure") },
    {
      id: "trash",
      icon: "trash",
      label: isSharedVault.value ? t("items.trashShared") : t("nav.trash"),
    },
  ]);

  const selectCategory = (categoryId: string) => {
    selectedCategory.value = categoryId === "kv" ? "infra" : categoryId;
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
      const matchTypes = new Set(categoryTypes(selectedCategory.value as ItemCategoryId));
      if (matchTypes.size) {
        result = result.filter((item) => matchTypes.has(item.type_id));
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
    selectedSubtype,
    query,
    categoryCounts,
    categories,
    selectCategory,
    filteredItems,
    isDeletedItem,
  };
}
