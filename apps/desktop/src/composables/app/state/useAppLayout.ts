import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { ComputedRef, Ref } from "vue";
import type { UiSettings } from "../../useUiSettings";
import type { ItemSummary } from "../../../types";

type ListPanelRef = {
  listContainer?: { value: HTMLElement | null } | null;
} | null;

type DetailsPanelRef = {
  focusSearch?: () => void;
} | null;

type AppLayoutOptions = {
  uiSettings: Ref<UiSettings>;
  showMain: ComputedRef<boolean>;
  filteredItems: ComputedRef<ItemSummary[]>;
  selectedItemId: Ref<string | null>;
};

export function useAppLayout({
  uiSettings,
  showMain,
  filteredItems,
  selectedItemId,
}: AppLayoutOptions) {
  const listPanel = ref<ListPanelRef>(null);
  const detailsPanel = ref<DetailsPanelRef>(null);
  const listContainerEl = computed(
    () => listPanel.value?.listContainer?.value ?? null,
  );

  const scrollTop = ref(0);
  const viewportHeight = ref(0);
  const rowHeight = 72;
  const overscan = 6;

  const isResizingDetails = ref(false);
  const SIDEBAR_FIXED = 240;
  const LIST_MIN = 320;
  const LIST_MAX = 560;
  const LIST_DEFAULT = 400;
  const DETAILS_MIN_PX = 560;
  const RESIZE_HANDLE_WIDTH = 5;
  const detailsRatio = ref(0);
  const listWidth = ref(320);

  const currentSidebarWidth = () =>
    uiSettings.value.sidebarCollapsed ? 0 : SIDEBAR_FIXED;

  const availableWidth = () =>
    Math.max(0, window.innerWidth - currentSidebarWidth() - RESIZE_HANDLE_WIDTH);

  const minDetailsWidth = () => {
    const available = availableWidth();
    return Math.max(DETAILS_MIN_PX, available - LIST_MAX);
  };

  const maxDetailsWidth = () => {
    const available = availableWidth();
    return Math.max(0, available - LIST_MIN);
  };

  const clampDetailsWidth = (value: number) => {
    const min = minDetailsWidth();
    const max = maxDetailsWidth();
    if (max <= 0) return 0;
    if (max < min) return Math.max(0, Math.min(value, max));
    return Math.min(max, Math.max(min, value));
  };

  const updateListWidth = () => {
    const sidebarWidth = currentSidebarWidth();
    const availableForList = Math.max(
      0,
      window.innerWidth - sidebarWidth - uiSettings.value.detailsWidth - RESIZE_HANDLE_WIDTH,
    );
    listWidth.value = Math.max(LIST_MIN, availableForList);
  };

  const updatePanelRatios = () => {
    const available = availableWidth();
    if (available <= 0) return;
    detailsRatio.value = uiSettings.value.detailsWidth / available;
  };

  const applyPanelWidthsFromRatio = () => {
    if (window.innerWidth <= 0) return;
    const desired =
      detailsRatio.value > 0
        ? Math.round(availableWidth() * detailsRatio.value)
        : Math.max(DETAILS_MIN_PX, availableWidth() - LIST_DEFAULT);
    uiSettings.value.sidebarWidth = SIDEBAR_FIXED;
    uiSettings.value.detailsWidth = clampDetailsWidth(desired);
    updatePanelRatios();
    updateListWidth();
  };

  const startResizeDetails = (e: MouseEvent) => {
    isResizingDetails.value = true;
    document.addEventListener("mousemove", onResizeDetails);
    document.addEventListener("mouseup", stopResizeDetails);
    e.preventDefault();
  };

  const onResizeDetails = (e: MouseEvent) => {
    if (!isResizingDetails.value) return;
    const desired = window.innerWidth - e.clientX;
    uiSettings.value.detailsWidth = clampDetailsWidth(desired);
    updatePanelRatios();
    updateListWidth();
  };

  const stopResizeDetails = () => {
    isResizingDetails.value = false;
    document.removeEventListener("mousemove", onResizeDetails);
    document.removeEventListener("mouseup", stopResizeDetails);
  };

  const visibleRange = computed(() => {
    const total = filteredItems.value.length;
    if (total === 0) {
      return { start: 0, end: 0 };
    }
    const start = Math.max(0, Math.floor(scrollTop.value / rowHeight) - overscan);
    const end = Math.min(
      total,
      Math.ceil((scrollTop.value + viewportHeight.value) / rowHeight) + overscan,
    );
    return { start, end };
  });

  const visibleItems = computed(() => {
    const { start, end } = visibleRange.value;
    return filteredItems.value.slice(start, end);
  });

  const totalListHeight = computed(() => filteredItems.value.length * rowHeight);

  const listOffset = computed(() => visibleRange.value.start * rowHeight);

  const onListScroll = () => {
    if (!listContainerEl.value) {
      return;
    }
    scrollTop.value = listContainerEl.value.scrollTop;
    viewportHeight.value = listContainerEl.value.clientHeight;
  };

  const scrollToIndex = (index: number) => {
    const container = listContainerEl.value;
    if (!container) {
      return;
    }
    const top = index * rowHeight;
    const bottom = top + rowHeight;
    const viewTop = container.scrollTop;
    const viewBottom = viewTop + container.clientHeight;
    if (top < viewTop) {
      container.scrollTop = top;
    } else if (bottom > viewBottom) {
      container.scrollTop = bottom - container.clientHeight;
    }
  };

  const moveSelection = (delta: number) => {
    const list = filteredItems.value;
    if (list.length === 0) {
      return;
    }
    const currentIndex = list.findIndex(
      (item) => item.id === selectedItemId.value,
    );
    const nextIndex =
      currentIndex === -1
        ? 0
        : Math.min(list.length - 1, Math.max(0, currentIndex + delta));
    selectedItemId.value = list[nextIndex].id;
    scrollToIndex(nextIndex);
  };

  onMounted(() => {
    updatePanelRatios();
    applyPanelWidthsFromRatio();
    window.addEventListener("resize", applyPanelWidthsFromRatio);
    if (listContainerEl.value) {
      viewportHeight.value = listContainerEl.value.clientHeight;
    }
  });

  onBeforeUnmount(() => {
    window.removeEventListener("resize", applyPanelWidthsFromRatio);
  });

  watch(showMain, (value) => {
    if (!value || !listContainerEl.value) {
      return;
    }
    viewportHeight.value = listContainerEl.value.clientHeight;
    updateListWidth();
  });

  watch(
    () => uiSettings.value.sidebarCollapsed,
    () => {
      applyPanelWidthsFromRatio();
    },
  );

  return {
    listPanel,
    detailsPanel,
    listContainerEl,
    listWidth,
    isResizingDetails,
    startResizeDetails,
    onListScroll,
    visibleItems,
    totalListHeight,
    listOffset,
    moveSelection,
  };
}
