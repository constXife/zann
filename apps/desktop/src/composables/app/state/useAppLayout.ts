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
  const SIDEBAR_FIXED = 280;
  const LIST_MIN = 220;
  const LIST_BASE = SIDEBAR_FIXED;
  const LIST_MAX = 420;
  const DETAILS_MIN_PX = 420;
  const DETAILS_MIN_RATIO = 0.5;
  const DETAILS_MAX_RATIO = 0.75;
  const DETAILS_MAX_PX = 880;
  const detailsRatio = ref(0);
  const listWidth = ref(320);

  const currentSidebarWidth = () =>
    uiSettings.value.sidebarCollapsed ? 0 : SIDEBAR_FIXED;

  const minDetailsWidth = () => {
    const desired = Math.max(
      DETAILS_MIN_PX,
      Math.floor(window.innerWidth * DETAILS_MIN_RATIO),
    );
    const maxAllowed = Math.max(
      0,
      window.innerWidth - currentSidebarWidth() - LIST_MIN,
    );
    return Math.min(desired, maxAllowed);
  };

  const maxDetailsWidth = () => {
    const maxAllowed = Math.max(
      0,
      window.innerWidth - currentSidebarWidth() - LIST_MIN,
    );
    return Math.min(
      Math.floor(window.innerWidth * DETAILS_MAX_RATIO),
      DETAILS_MAX_PX,
      maxAllowed,
    );
  };

  const updateListWidth = () => {
    const sidebarWidth = currentSidebarWidth();
    const availableForList = Math.max(
      0,
      window.innerWidth - sidebarWidth - minDetailsWidth(),
    );
    const baseWidth = Math.min(LIST_BASE, availableForList);
    const extraSpace = Math.max(0, availableForList - baseWidth);
    const extra = Math.min(160, Math.floor(extraSpace * 0.35));
    const nextWidth = Math.min(LIST_MAX, baseWidth + extra, availableForList);
    listWidth.value = Math.max(0, nextWidth);
  };

  const updatePanelRatios = () => {
    if (window.innerWidth <= 0) return;
    detailsRatio.value = uiSettings.value.detailsWidth / window.innerWidth;
  };

  const applyPanelWidthsFromRatio = () => {
    if (window.innerWidth <= 0) return;
    const minDetails = minDetailsWidth();
    const maxDetails = maxDetailsWidth();
    const nextDetails = Math.min(
      maxDetails,
      Math.max(minDetails, Math.round(window.innerWidth * detailsRatio.value)),
    );
    uiSettings.value.sidebarWidth = SIDEBAR_FIXED;
    uiSettings.value.detailsWidth = nextDetails;
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
    const minDetails = minDetailsWidth();
    const maxDetails = maxDetailsWidth();
    const newWidth = Math.min(
      maxDetails,
      Math.max(minDetails, window.innerWidth - e.clientX),
    );
    uiSettings.value.detailsWidth = newWidth;
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
      updateListWidth();
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
