<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import { useI18n } from "vue-i18n";
import type { ItemHistorySummary } from "../types";

const { t } = useI18n();

const props = defineProps<{
  historyEntries: ItemHistorySummary[];
  historyLoading: boolean;
  historyError: string;
  timeTravelIndex: number;
  timeTravelHasDraft: boolean;
  restoreHistoryVersion: (entry: ItemHistorySummary) => void;
  setTimeTravelIndex: (index: number) => void;
}>();

const formatUpdatedAt = (value?: string | null) => {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
};

const timeTravelEntry = computed(() => props.historyEntries[props.timeTravelIndex] ?? null);
const timeTravelTitle = computed(() =>
  timeTravelEntry.value ? formatUpdatedAt(timeTravelEntry.value.created_at) : "",
);
const timeTravelTotal = computed(() => props.historyEntries.length);

const timeTravelPosition = computed(() => {
  if (!timeTravelTotal.value) {
    return 0;
  }
  return timeTravelSliderIndex.value + 1;
});

const timeTravelPercent = computed(() => {
  if (timeTravelSliderMax.value === 0) {
    return 0;
  }
  return Math.round((timeTravelSliderIndex.value / timeTravelSliderMax.value) * 100);
});

const timeTravelTimeline = computed(() => {
  const entries = props.historyEntries.map((entry, historyIndex) => ({
    entry,
    historyIndex,
    ts: Date.parse(entry.created_at),
  }));
  return entries
    .slice()
    .sort((a, b) => {
      const aOk = Number.isFinite(a.ts);
      const bOk = Number.isFinite(b.ts);
      if (aOk && bOk) {
        return a.ts - b.ts;
      }
      if (aOk) return -1;
      if (bOk) return 1;
      return a.historyIndex - b.historyIndex;
    })
    .map((entry, timelineIndex) => ({
      ...entry,
      timelineIndex,
    }));
});

const timeTravelSliderMax = computed(() =>
  Math.max(0, timeTravelTimeline.value.length - 1),
);

const timeTravelSliderIndex = computed(() => {
  const match = timeTravelTimeline.value.find(
    (entry) => entry.historyIndex === props.timeTravelIndex,
  );
  return match?.timelineIndex ?? 0;
});

const timeTravelSegments = computed(() => {
  const total = timeTravelTotal.value;
  if (!total) {
    return [];
  }
  const max = Math.max(0, timeTravelSliderMax.value);
  const widthPercent = total > 0 ? 100 / total : 100;
  return timeTravelTimeline.value.map((entry) => {
    const percent = max > 0 ? (entry.timelineIndex / max) * 100 : 0;
    const left = Math.min(100 - widthPercent, Math.max(0, percent - widthPercent / 2));
    return {
      ...entry,
      percent,
      left,
      width: widthPercent,
    };
  });
});

const timeTravelSnapPulse = ref(false);
let timeTravelSnapTimer: number | null = null;

const triggerTimeTravelSnap = () => {
  timeTravelSnapPulse.value = true;
  if (timeTravelSnapTimer) {
    window.clearTimeout(timeTravelSnapTimer);
  }
  timeTravelSnapTimer = window.setTimeout(() => {
    timeTravelSnapPulse.value = false;
    timeTravelSnapTimer = null;
  }, 160);
};

const setTimeTravelByTimelineIndex = (timelineIndex: number) => {
  const entry = timeTravelTimeline.value[timelineIndex];
  if (!entry) {
    return;
  }
  props.setTimeTravelIndex(entry.historyIndex);
  triggerTimeTravelSnap();
};

onBeforeUnmount(() => {
  if (timeTravelSnapTimer) {
    window.clearTimeout(timeTravelSnapTimer);
    timeTravelSnapTimer = null;
  }
});
</script>

<template>
  <div
    id="history-panel"
    data-testid="history-panel"
    class="sticky top-0 z-10 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)]/90 px-3 py-2 text-xs text-[var(--text-primary)] backdrop-blur"
  >
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-semibold">{{ t("items.historyTimeTravelTitle") }}</span>
        <span class="text-[var(--text-tertiary)]">· {{ timeTravelTitle }}</span>
        <span
          v-if="timeTravelEntry?.pending"
          class="rounded-full bg-[var(--bg-hover)] px-2 py-0.5 text-[10px] font-semibold text-[var(--text-tertiary)]"
        >
          {{ t("items.historyPending") }}
        </span>
      </div>
      <div class="flex items-center gap-2 text-[var(--text-tertiary)]">
        <span>{{ t("items.historyPosition", { current: timeTravelPosition, total: timeTravelTotal }) }}</span>
        <span>{{ timeTravelPercent }}%</span>
      </div>
    </div>
    <div class="mt-2">
      <div class="flex items-center justify-between gap-2 text-[10px] text-[var(--text-tertiary)]">
        <button
          type="button"
          class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
          :disabled="!timeTravelEntry || timeTravelEntry.pending"
          @click="timeTravelEntry && props.restoreHistoryVersion(timeTravelEntry)"
          data-testid="history-restore"
        >
          {{ t("items.historyRestore") }}
        </button>
        <div class="flex items-center gap-1">
          <button
            type="button"
            class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
            :disabled="timeTravelSliderIndex <= 0"
            @click="setTimeTravelByTimelineIndex(timeTravelSliderIndex - 1)"
          >
            ◀
          </button>
          <button
            type="button"
            class="rounded px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] disabled:opacity-50"
            :disabled="timeTravelSliderIndex >= timeTravelSliderMax"
            @click="setTimeTravelByTimelineIndex(timeTravelSliderIndex + 1)"
          >
            ▶
          </button>
        </div>
      </div>
      <div
        class="relative mt-2"
        :class="timeTravelSnapPulse ? 'time-travel-snap' : ''"
      >
        <div class="absolute inset-0 pointer-events-none">
          <span
            v-for="entry in timeTravelSegments"
            :key="entry.entry.version"
            class="absolute top-1/2 h-2 -translate-y-1/2 rounded-full bg-[var(--bg-tertiary)]/70"
            :style="{ left: `${entry.left}%`, width: `${entry.width}%` }"
          ></span>
        </div>
        <input
          class="time-travel-range w-full"
          data-testid="history-slider"
          type="range"
          min="0"
          :max="timeTravelSliderMax"
          step="1"
          :value="timeTravelSliderIndex"
          @input="setTimeTravelByTimelineIndex(Number(($event.target as HTMLInputElement).value))"
        />
      </div>
      <div class="mt-1 flex items-center justify-between text-[10px] text-[var(--text-tertiary)]">
        <span v-if="timeTravelTimeline.length">
          {{ formatUpdatedAt(timeTravelTimeline[0].entry.created_at) }}
        </span>
        <span v-if="timeTravelTimeline.length">
          {{ formatUpdatedAt(timeTravelTimeline[timeTravelTimeline.length - 1].entry.created_at) }}
        </span>
      </div>
    </div>
    <div v-if="props.historyLoading" class="mt-2 text-[var(--text-tertiary)]">
      {{ t("items.historyVersionLoading") }}
    </div>
    <div v-else-if="props.historyError" class="mt-2 text-red-400">
      {{ props.historyError }}
    </div>
    <div v-else-if="props.timeTravelHasDraft" class="mt-2 text-[var(--text-tertiary)]">
      {{ t("items.historyDraftNotice") }}
    </div>
  </div>
</template>

<style scoped>
.time-travel-range {
  -webkit-appearance: none;
  appearance: none;
  height: 10px;
  background: linear-gradient(90deg, rgba(99, 102, 241, 0.2), rgba(16, 185, 129, 0.2));
  border-radius: 999px;
  cursor: pointer;
}

.time-travel-range:focus {
  outline: none;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
}

.time-travel-range::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 20px;
  height: 20px;
  border-radius: 999px;
  background: var(--accent);
  border: 2px solid rgba(255, 255, 255, 0.6);
  box-shadow: 0 6px 18px rgba(15, 23, 42, 0.35);
  transition: transform 120ms ease;
}

.time-travel-range::-moz-range-thumb {
  width: 20px;
  height: 20px;
  border-radius: 999px;
  background: var(--accent);
  border: 2px solid rgba(255, 255, 255, 0.6);
  box-shadow: 0 6px 18px rgba(15, 23, 42, 0.35);
  transition: transform 120ms ease;
}

.time-travel-range::-webkit-slider-runnable-track {
  height: 10px;
  border-radius: 999px;
}

.time-travel-range::-moz-range-track {
  height: 10px;
  border-radius: 999px;
}

.time-travel-snap .time-travel-range::-webkit-slider-thumb {
  transform: scale(1.08);
}

.time-travel-snap .time-travel-range::-moz-range-thumb {
  transform: scale(1.08);
}
</style>
