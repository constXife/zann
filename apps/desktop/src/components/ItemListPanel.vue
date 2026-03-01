<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import type { ItemSummary } from "../types";
import { SyncStatus } from "../constants/enums";
import Button from "./ui/Button.vue";
import TypePickerMenu from "./TypePickerMenu.vue";
import { typeMeta } from "../data/secretSchemas";

type Category = { id: string; icon: string; label: string };

const { t } = useI18n();

const props = defineProps<{
  sidebarCollapsed: boolean;
  categories: Category[];
  selectedCategory: string | null;
  filteredItems: ItemSummary[];
  listLoading: boolean;
  listError: string;
  totalListHeight: number;
  listOffset: number;
  visibleItems: ItemSummary[];
  selectedItemId: string | null;
  vaultContextLabel: string;
  isSharedVault: boolean;
  isLocalStorage: boolean;
  syncBusy: boolean;
  onListScroll: () => void;
  selectItem: (itemId: string) => void;
  openCreateItem: (typeId?: string) => void;
  createTypeOptions: string[];
  createTypeGroups: { id: string; label: string; types: string[] }[];
  prepareCreateTypes?: () => Promise<void>;
  onEmptyTrash: () => void;
  retryLoadItems: () => void;
  listBlocked: boolean;
  listBlockedMessage: string;
}>();

const emit = defineEmits<{ (e: "expandSidebar"): void }>();

const listContainer = ref<HTMLDivElement | null>(null);
const isMac = ref(false);
const createMenuOpen = ref(false);

defineExpose({ listContainer });

const platformHint = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`.toLowerCase();
isMac.value = platformHint.includes("mac");

const selectedCategoryLabel = computed(() => {
  if (props.selectedCategory && props.selectedCategory !== "all") {
    return props.categories.find((cat) => cat.id === props.selectedCategory)?.label ?? "All";
  }
  return "All";
});

const collapsedPaddingClass = computed(() => {
  if (!props.sidebarCollapsed) return "";
  return isMac.value ? "pl-[130px]" : "pl-[48px]";
});
const collapsedToggleOffsetClass = computed(() => (isMac.value ? "left-[84px]" : "left-[12px]"));

const showEmptyTrash = computed(
  () => props.selectedCategory === "trash" && props.filteredItems.length > 0,
);

const getTypeLabel = (typeId: string) => {
  const key = `types.${typeId}`;
  const label = t(key);
  return label !== key ? label : typeId;
};

const createMenuTypes = computed(() => {
  if (props.createTypeGroups?.length) {
    return props.createTypeGroups.flatMap((group) => group.types);
  }
  return props.createTypeOptions ?? [];
});

const shouldOpenCreateMenu = computed(() => {
  if (!props.selectedCategory || props.selectedCategory === "all" || props.selectedCategory === "trash") {
    return true;
  }
  return createMenuTypes.value.length > 1;
});

const formatDeletedAt = (value?: string | null) => {
  if (!value) {
    return t("time.justNow");
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
};

const formatUpdatedAt = (value?: string | null) => {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleDateString();
};

const getFolderPath = (path: string) =>
  path.includes("/") ? path.split("/").slice(0, -1).join("/") : "";

const handleSelectItem = (itemId: string) => {
  console.info("[item_list] select_item", { itemId });
  if (props.listBlocked) {
    return;
  }
  props.selectItem(itemId);
};

const actionDisabledClass = computed(() =>
  props.listBlocked ? "opacity-50 cursor-not-allowed" : "",
);

const closeCreateMenu = () => {
  createMenuOpen.value = false;
};

const handleCreateClick = async () => {
  if (props.listBlocked) {
    return;
  }
  if (!shouldOpenCreateMenu.value) {
    props.openCreateItem(createMenuTypes.value[0]);
    return;
  }
  if (!createMenuTypes.value.length && props.prepareCreateTypes) {
    await props.prepareCreateTypes();
  }
  if (!createMenuTypes.value.length) {
    props.openCreateItem();
    return;
  }
  createMenuOpen.value = true;
};

const handleSelectCreateType = (typeId: string) => {
  createMenuOpen.value = false;
  props.openCreateItem(typeId);
};
</script>

<template>
  <section
    class="relative flex flex-col bg-[var(--bg-secondary)]"
    :title="listBlocked ? listBlockedMessage : ''"
  >
    <Button
      v-if="sidebarCollapsed"
      variant="ghost"
      size="icon-sm"
      class="absolute top-[8px] z-[60]"
      :class="collapsedToggleOffsetClass"
      :title="t('sidebar.expand')"
      data-tauri-drag-region="false"
      @click="emit('expandSidebar')"
    >
      <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 4H5a1 1 0 00-1 1v14a1 1 0 001 1h4m0-16v16m0-16h10a1 1 0 011 1v14a1 1 0 01-1 1H9" />
      </svg>
    </Button>

    <div
      class="flex items-center justify-between px-4 pt-3 pb-2"
      :class="collapsedPaddingClass"
      data-tauri-drag-region
    >
      <div class="flex items-center gap-3">
        <div>
          <div class="flex items-center gap-2 text-sm font-semibold leading-none">
            <span>{{ selectedCategoryLabel }}</span>
            <span
              v-if="isSharedVault"
              class="rounded-full bg-category-security/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-category-security"
            >
              {{ t("nav.shared") }}
            </span>
          </div>
          <div class="text-xs text-[var(--text-secondary)] leading-none mt-1">{{ filteredItems.length }} items</div>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <div
          v-if="syncBusy"
          class="hidden items-center gap-2 text-[11px] text-[var(--text-tertiary)] sm:flex"
        >
          <span class="h-2.5 w-2.5 animate-spin rounded-full border border-[var(--border-color)] border-t-[var(--text-secondary)]"></span>
          <span>{{ t("status.syncing") }}</span>
        </div>
        <Button
          v-if="showEmptyTrash"
          variant="outline"
          size="xs"
          :class="actionDisabledClass"
          :disabled="listBlocked"
          data-tauri-drag-region="false"
          @click="onEmptyTrash"
        >
          {{ t("items.emptyTrash") }}
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          :class="actionDisabledClass"
          :disabled="listBlocked"
          data-tauri-drag-region="false"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12" />
          </svg>
        </Button>
        <div class="relative">
          <Button
            variant="ghost"
            size="icon-sm"
            :class="[
              actionDisabledClass,
              createMenuOpen ? 'bg-[var(--bg-hover)] text-[var(--text-primary)]' : '',
            ]"
            :disabled="listBlocked"
            data-tauri-drag-region="false"
            data-testid="item-create"
            :aria-expanded="createMenuOpen"
            @click="handleCreateClick"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v16m8-8H4" />
            </svg>
          </Button>
          <TypePickerMenu
            :open="createMenuOpen"
            align="right"
            menu-width-class="w-48"
            :show-group-labels="false"
            :type-options="createTypeOptions"
            :type-groups="createTypeGroups"
            :type-meta="typeMeta"
            :get-type-label="getTypeLabel"
            :on-select-type="handleSelectCreateType"
            :on-close="closeCreateMenu"
          />
        </div>
      </div>
    </div>

    <div
      v-if="!listLoading && listError"
      class="mx-4 mt-2 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs text-red-700 dark:text-red-300"
    >
      <div class="flex items-start justify-between gap-2">
        <div class="min-w-0">
          <div class="font-semibold">{{ t("items.listLoadFailed") }}</div>
          <div class="mt-1 text-[11px] text-red-600/80 dark:text-red-300/80 break-words">
            {{ listError }}
          </div>
        </div>
        <button
          type="button"
          class="shrink-0 rounded-md bg-red-500/20 px-2 py-1 text-[11px] font-semibold text-red-700 dark:text-red-300 hover:bg-red-500/30 transition-colors"
          @click="retryLoadItems"
        >
          {{ t("common.retry") }}
        </button>
      </div>
    </div>

    <div
      v-if="listBlocked"
      class="mx-4 mt-2 rounded-lg border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300"
    >
      {{ listBlockedMessage }}
    </div>

    <div
      ref="listContainer"
      class="flex-1 overflow-auto"
      :class="listBlocked ? 'pointer-events-none opacity-60' : ''"
      @scroll="onListScroll"
    >
      <div v-if="listLoading" class="space-y-1 p-2">
        <div
          v-for="n in 6"
          :key="n"
          class="h-14 rounded-lg bg-[var(--bg-hover)] animate-pulse"
        ></div>
      </div>
      <div v-if="!listLoading" :style="{ height: `${totalListHeight}px` }">
        <div :style="{ transform: `translateY(${listOffset}px)` }">
          <button
            v-for="item in visibleItems"
            :key="item.id"
            type="button"
            class="w-full px-4 py-2.5 text-left transition h-[72px]"
            :class="
              item.id === selectedItemId
                ? 'bg-[var(--bg-active)]'
                : 'hover:bg-[var(--bg-hover)]'
            "
            @click="handleSelectItem(item.id)"
          >
            <div class="flex items-center gap-3">
              <div
                class="flex h-9 w-9 items-center justify-center rounded-full text-white text-xs font-medium"
                :class="`bg-category-${item.type_id}`"
              >
                {{ item.name.charAt(0).toUpperCase() }}
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 min-w-0">
                  <div class="font-medium truncate">
                    {{ item.name }}
                  </div>
                  <span
                    v-if="!isLocalStorage && item.sync_status === SyncStatus.Conflict"
                    class="shrink-0 rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-600 dark:text-red-400"
                  >
                    {{ t("status.conflict") }}
                  </span>
                  <span
                    v-else-if="!isLocalStorage && item.sync_status && item.sync_status !== SyncStatus.Synced"
                    class="shrink-0 inline-flex items-center justify-center rounded-full bg-amber-500/15 p-1 text-amber-700 dark:text-amber-400"
                    :title="t('status.pending')"
                    data-testid="item-sync-pending"
                  >
                    <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 15a4 4 0 0 1 .5-8 5 5 0 0 1 9.6 1.5A3.5 3.5 0 0 1 17.5 15H7z" />
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v6m0 0l-2-2m2 2l2-2" />
                    </svg>
                  </span>
                </div>
                <div class="text-xs text-[var(--text-secondary)] flex items-center min-w-0">
                  <template v-if="selectedCategory !== 'trash'">
                    <span class="shrink-0 text-[var(--text-tertiary)]">
                      {{ getTypeLabel(item.type_id) }}
                    </span>
                    <span v-if="getFolderPath(item.path)" class="shrink min-w-0 truncate">
                      <span class="mx-1 text-[var(--text-tertiary)]">·</span>
                      <span>{{ getFolderPath(item.path) }}</span>
                    </span>
                    <span class="shrink-0">
                      <span class="mx-1 text-[var(--text-tertiary)]">·</span>
                      <span>{{ t("items.updatedAtLabel", { value: formatUpdatedAt(item.updated_at) }) }}</span>
                    </span>
                  </template>
                  <template v-else>
                    {{ t("items.deletedAt") }}: {{ formatDeletedAt(item.deleted_at) }}
                    <span v-if="isSharedVault" class="ml-1">
                      · {{ t("items.deletedBy") }}:
                      {{ item.deleted_by || t("items.deletedByUnknown") }}
                    </span>
                  </template>
                </div>
              </div>
            </div>
          </button>
        </div>
      </div>
      <div
        v-if="!listLoading && !listError && !filteredItems.length"
        class="mx-4 my-3 text-xs text-[var(--text-tertiary)]"
      ></div>
    </div>
  </section>
</template>
