<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import type { FieldRow, FieldValue } from "../types";

const { t } = useI18n();

type DiffStatus = "modified" | "added" | "removed" | "same";
type DiffSegment = { text: string; changed: boolean };

function computeCharDiff(
  oldStr: string,
  newStr: string,
): { oldSegments: DiffSegment[]; newSegments: DiffSegment[] } {
  const m = oldStr.length;
  const n = newStr.length;

  // Build LCS table
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array(n + 1).fill(0),
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (oldStr[i - 1] === newStr[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack to find LCS indices
  const oldInLcs = new Set<number>();
  const newInLcs = new Set<number>();
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (oldStr[i - 1] === newStr[j - 1]) {
      oldInLcs.add(i - 1);
      newInLcs.add(j - 1);
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  // Build segments for old string
  const oldSegments: DiffSegment[] = [];
  let currentText = "";
  let currentChanged = !oldInLcs.has(0);
  for (let idx = 0; idx < m; idx++) {
    const isChanged = !oldInLcs.has(idx);
    if (isChanged === currentChanged) {
      currentText += oldStr[idx];
    } else {
      if (currentText) {
        oldSegments.push({ text: currentText, changed: currentChanged });
      }
      currentText = oldStr[idx];
      currentChanged = isChanged;
    }
  }
  if (currentText) {
    oldSegments.push({ text: currentText, changed: currentChanged });
  }

  // Build segments for new string
  const newSegments: DiffSegment[] = [];
  currentText = "";
  currentChanged = !newInLcs.has(0);
  for (let idx = 0; idx < n; idx++) {
    const isChanged = !newInLcs.has(idx);
    if (isChanged === currentChanged) {
      currentText += newStr[idx];
    } else {
      if (currentText) {
        newSegments.push({ text: currentText, changed: currentChanged });
      }
      currentText = newStr[idx];
      currentChanged = isChanged;
    }
  }
  if (currentText) {
    newSegments.push({ text: currentText, changed: currentChanged });
  }

  return { oldSegments, newSegments };
}

const charDiffCache = new Map<string, { oldSegments: DiffSegment[]; newSegments: DiffSegment[] }>();

function getCharDiff(diff: DiffField): { oldSegments: DiffSegment[]; newSegments: DiffSegment[] } {
  if (diff.status !== "modified" || !diff.baseField || !diff.currentField) {
    return { oldSegments: [], newSegments: [] };
  }

  const cacheKey = `${diff.key}:${diff.baseField.value}:${diff.currentField.value}`;
  const cached = charDiffCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const result = computeCharDiff(
    String(diff.baseField.value),
    String(diff.currentField.value),
  );
  charDiffCache.set(cacheKey, result);
  return result;
}

type DiffField = {
  key: string;
  status: DiffStatus;
  baseField: FieldRow | null;
  currentField: FieldRow | null;
};

const props = defineProps<{
  currentFields: FieldRow[];
  baseFields: Record<string, FieldValue>;
  showMaskedValue: (path: string) => boolean;
  handleCopy: (field: FieldRow) => void;
  copiedField: string | null;
  applyTimeTravelField: (fieldKey: string) => void;
  formatFieldLabel: (key: string) => string;
}>();

const allDiffFields = computed<DiffField[]>(() => {
  const result: DiffField[] = [];
  const processedKeys = new Set<string>();

  for (const field of props.currentFields) {
    processedKeys.add(field.key);
    const base = props.baseFields[field.key];

    let status: DiffStatus;
    if (!base) {
      status = "added";
    } else if (base.kind === field.kind && base.value === field.value) {
      status = "same";
    } else {
      status = "modified";
    }

    result.push({
      key: field.key,
      status,
      baseField: base ? fieldValueToRow(field.key, base) : null,
      currentField: field,
    });
  }

  const baseKeys = Object.keys(props.baseFields).filter(
    (k) => !processedKeys.has(k),
  );
  baseKeys.sort((a, b) => a.localeCompare(b));

  for (const key of baseKeys) {
    const base = props.baseFields[key];
    result.push({
      key,
      status: "removed",
      baseField: fieldValueToRow(key, base),
      currentField: null,
    });
  }

  return result;
});

function fieldValueToRow(key: string, fv: FieldValue): FieldRow {
  const masked =
    fv.meta?.masked ?? (fv.kind === "password" || fv.kind === "otp");
  return {
    key,
    value: fv.value,
    path: `history-base:${key}`,
    kind: fv.kind,
    masked,
    copyable: fv.meta?.copyable ?? true,
    revealable: fv.meta?.masked ?? masked,
  };
}

const leftBgClass = (status: DiffStatus) => {
  if (status === "removed") return "bg-red-500/15";
  if (status === "modified") return "bg-amber-500/10";
  return "";
};

const rightBgClass = (status: DiffStatus) => {
  if (status === "added") return "bg-emerald-500/15";
  if (status === "modified") return "bg-amber-500/10";
  return "";
};
</script>

<template>
  <div class="grid grid-cols-2 gap-4">
    <!-- Left: Base version (Before) -->
    <div class="space-y-1">
      <div
        class="text-xs font-semibold text-[var(--text-tertiary)] mb-3 uppercase tracking-wide"
      >
        {{ t("items.historyBefore") }}
      </div>
      <div
        v-for="diff in allDiffFields"
        :key="`left-${diff.key}`"
        class="border-b border-white/5 py-2 last:border-b-0 rounded-md px-2 -mx-2"
        :class="leftBgClass(diff.status)"
      >
        <div class="text-[10px] font-mono font-semibold uppercase tracking-wide text-[var(--text-tertiary)] mb-1">
          {{ formatFieldLabel(diff.key) }}
          <span
            v-if="diff.status === 'removed'"
            class="ml-1.5 rounded-full bg-red-500/20 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-red-200"
          >
            {{ t("items.historyDeletedTag") }}
          </span>
        </div>
        <div
          v-if="diff.baseField"
          class="flex items-start justify-between gap-2"
        >
          <div class="min-w-0 flex-1">
            <button
              type="button"
              class="min-w-0 w-full text-left font-mono text-sm text-[var(--text-primary)] px-1 py-0.5 transition-colors focus:outline-none"
              :class="diff.baseField.copyable ? 'hover:bg-[var(--bg-hover)] cursor-pointer rounded-md' : ''"
              @click="handleCopy(diff.baseField!)"
            >
              <span
                v-if="diff.baseField.masked && showMaskedValue(diff.baseField.path)"
                class="tracking-widest text-base leading-none text-[var(--text-primary)]"
              >
                ••••••••••••
              </span>
              <template v-else-if="diff.status === 'modified'">
                <span
                  v-for="(seg, segIdx) in getCharDiff(diff).oldSegments"
                  :key="segIdx"
                  class="break-words text-[var(--text-primary)] whitespace-pre-wrap"
                  :class="seg.changed ? 'font-bold' : ''"
                >{{ seg.text }}</span>
              </template>
              <span
                v-else
                class="break-words text-[var(--text-primary)] whitespace-pre-wrap"
              >
                {{ diff.baseField.value }}
              </span>
            </button>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <button
              v-if="diff.baseField.copyable"
              type="button"
              class="rounded px-1.5 py-0.5 text-[10px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="handleCopy(diff.baseField!)"
            >
              <span v-if="copiedField === diff.baseField.path" class="text-emerald-400">
                ✓
              </span>
              <span v-else>📋</span>
            </button>
            <button
              v-if="diff.status === 'removed'"
              type="button"
              class="rounded px-1.5 py-0.5 text-[10px] font-semibold text-red-200 hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="applyTimeTravelField(diff.key)"
            >
              ↩ {{ t("items.historyApplyField") }}
            </button>
          </div>
        </div>
        <div v-else class="text-xs text-[var(--text-tertiary)] italic px-1 py-0.5">
          —
        </div>
      </div>
    </div>

    <!-- Right: Current version (After) -->
    <div class="space-y-1">
      <div
        class="text-xs font-semibold text-[var(--text-tertiary)] mb-3 uppercase tracking-wide"
      >
        {{ t("items.historyAfter") }}
      </div>
      <div
        v-for="diff in allDiffFields"
        :key="`right-${diff.key}`"
        class="border-b border-white/5 py-2 last:border-b-0 rounded-md px-2 -mx-2"
        :class="rightBgClass(diff.status)"
      >
        <div class="text-[10px] font-mono font-semibold uppercase tracking-wide text-[var(--text-tertiary)] mb-1">
          {{ formatFieldLabel(diff.key) }}
          <span
            v-if="diff.status === 'added'"
            class="ml-1.5 rounded-full bg-emerald-500/20 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-emerald-200"
          >
            {{ t("items.historyAddedTag") }}
          </span>
          <span
            v-else-if="diff.status === 'modified'"
            class="ml-1.5 rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-amber-200"
          >
            {{ t("items.historyModifiedTag") }}
          </span>
        </div>
        <div
          v-if="diff.currentField"
          class="flex items-start justify-between gap-2"
        >
          <div class="min-w-0 flex-1">
            <button
              type="button"
              class="min-w-0 w-full text-left font-mono text-sm text-[var(--text-primary)] px-1 py-0.5 transition-colors focus:outline-none"
              :class="diff.currentField.copyable ? 'hover:bg-[var(--bg-hover)] cursor-pointer rounded-md' : ''"
              @click="handleCopy(diff.currentField!)"
            >
              <span
                v-if="diff.currentField.masked && showMaskedValue(diff.currentField.path)"
                class="tracking-widest text-base leading-none text-[var(--text-primary)]"
              >
                ••••••••••••
              </span>
              <template v-else-if="diff.status === 'modified'">
                <span
                  v-for="(seg, segIdx) in getCharDiff(diff).newSegments"
                  :key="segIdx"
                  class="break-words text-[var(--text-primary)] whitespace-pre-wrap"
                  :class="seg.changed ? 'font-bold' : ''"
                >{{ seg.text }}</span>
              </template>
              <span
                v-else
                class="break-words text-[var(--text-primary)] whitespace-pre-wrap"
              >
                {{ diff.currentField.value }}
              </span>
            </button>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <button
              v-if="diff.currentField.copyable"
              type="button"
              class="rounded px-1.5 py-0.5 text-[10px] font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="handleCopy(diff.currentField!)"
            >
              <span v-if="copiedField === diff.currentField.path" class="text-emerald-400">
                ✓
              </span>
              <span v-else>📋</span>
            </button>
            <button
              v-if="diff.status === 'modified'"
              type="button"
              class="rounded px-1.5 py-0.5 text-[10px] font-semibold text-amber-200 hover:bg-[var(--bg-active)] active:bg-[var(--bg-active)]"
              @click.stop="applyTimeTravelField(diff.key)"
            >
              ↩ {{ t("items.historyApplyField") }}
            </button>
          </div>
        </div>
        <div v-else class="text-xs text-[var(--text-tertiary)] italic px-1 py-0.5">
          —
        </div>
      </div>
    </div>
  </div>
</template>
