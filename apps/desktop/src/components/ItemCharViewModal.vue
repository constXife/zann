<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";

const props = defineProps<{
  open: boolean;
  label: string;
  value: string;
}>();

const emit = defineEmits<{ (e: "close"): void }>();
const { t } = useI18n();

const chunkChars = (line: string, size = 4) => {
  const chars = Array.from(line);
  const groups: string[][] = [];
  for (let i = 0; i < chars.length; i += size) {
    groups.push(chars.slice(i, i + size));
  }
  return groups;
};

const isDigit = (char: string) => /[0-9]/.test(char);
const isLetter = (char: string) => /[a-zA-Z]/.test(char);
const isSymbol = (char: string) => !isDigit(char) && !isLetter(char);

const natoMap: Record<string, string> = {
  A: "Alpha",
  B: "Bravo",
  C: "Charlie",
  D: "Delta",
  E: "Echo",
  F: "Foxtrot",
  G: "Golf",
  H: "Hotel",
  I: "India",
  J: "Juliett",
  K: "Kilo",
  L: "Lima",
  M: "Mike",
  N: "November",
  O: "Oscar",
  P: "Papa",
  Q: "Quebec",
  R: "Romeo",
  S: "Sierra",
  T: "Tango",
  U: "Uniform",
  V: "Victor",
  W: "Whiskey",
  X: "X-ray",
  Y: "Yankee",
  Z: "Zulu",
};

const getNato = (char: string) => {
  const upper = char.toUpperCase();
  return natoMap[upper] ?? "";
};

const getAmbiguityLabel = (char: string) => {
  const labels: Record<string, string> = {
    "0": "Zero",
    "1": "One",
    O: "O (letter)",
    o: "o (letter)",
    I: "I (letter)",
    i: "i (letter)",
    l: "l (small)",
  };
  return labels[char] ?? "";
};

const getSymbolLabel = (char: string) => {
  const labels: Record<string, string> = {
    "#": "Hash",
    "@": "At",
    "!": "Bang",
    "$": "Dollar",
    "%": "Percent",
    "&": "Amp",
    "*": "Star",
    "-": "Dash",
    "_": "Underscore",
    ".": "Dot",
    "+": "Plus",
    "/": "Slash",
    "\\": "Backslash",
  };
  return labels[char] ?? "Symbol";
};

const getCharClass = (char: string) => {
  if (isDigit(char)) {
    return "border-blue-500/50 text-blue-100 bg-blue-500/10";
  }
  if (isSymbol(char)) {
    return "border-orange-500/50 text-orange-100 bg-orange-500/10";
  }
  return "border-zinc-700 text-[var(--text-primary)] bg-zinc-800/50";
};

const lines = computed(() => props.value.split("\n"));
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-md"
    @click.self="emit('close')"
  >
    <div class="inline-block w-fit max-w-[92vw] rounded-2xl border border-[var(--border-color)] bg-[var(--bg-secondary)] p-12 shadow-2xl text-center">
      <div class="flex items-center justify-between">
        <div class="text-sm font-semibold text-[var(--text-primary)]">
          {{ label }}
        </div>
        <button
          type="button"
          class="rounded px-2 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
          @click="emit('close')"
        >
          {{ t("common.close") }}
        </button>
      </div>
      <div class="mt-6 space-y-6 text-[var(--text-primary)]">
        <div
          v-for="(line, lineIndex) in lines"
          :key="`line-${lineIndex}`"
          class="flex flex-wrap justify-center gap-6"
        >
          <span
            v-if="line.length === 0"
            class="rounded-lg border border-[var(--border-color)] px-6 py-4 text-lg text-[var(--text-tertiary)]"
          >
            ␤
          </span>
          <div
            v-for="(group, groupIndex) in chunkChars(line)"
            :key="`group-${lineIndex}-${groupIndex}`"
            class="flex items-start gap-3"
          >
            <div
              v-for="(char, idx) in group"
              :key="`${lineIndex}-${groupIndex}-${idx}`"
              class="flex flex-col items-center gap-2"
            >
              <div
                class="flex h-24 w-16 items-center justify-center rounded-xl border-2 px-3 py-2 text-xl font-mono"
                :class="getCharClass(char)"
              >
                <span class="leading-none">{{ char }}</span>
              </div>
              <span
                v-if="getAmbiguityLabel(char)"
                class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]"
              >
                {{ getAmbiguityLabel(char) }}
              </span>
              <span
                v-else-if="isSymbol(char)"
                class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]"
              >
                {{ getSymbolLabel(char) }}
              </span>
              <span
                v-else-if="isLetter(char)"
                class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]"
              >
                {{ getNato(char) }}
              </span>
            </div>
            <span v-if="groupIndex < chunkChars(line).length - 1" class="w-6"></span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
