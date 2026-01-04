<script setup lang="ts">
import { nextTick, ref, watch } from "vue";

type Translator = (key: string) => string;

type PaletteItem = {
  id: string;
  label: string;
  subtitle?: string;
  hint?: string;
  enabled?: boolean;
  action?: () => void;
};

const props = defineProps<{
  open: boolean;
  query: string;
  index: number;
  items: PaletteItem[];
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  "update:query": [string];
  "update:index": [number];
}>();

const onQueryInput = (event: Event) => {
  const target = event.target as HTMLInputElement | null;
  emit("update:query", target?.value ?? "");
};

const listEl = ref<HTMLDivElement | null>(null);

watch(
  () => props.index,
  async (value) => {
    await nextTick();
    const list = listEl.value;
    if (!list) return;
    const children = list.querySelectorAll("button");
    const target = children[value];
    if (!target) return;
    target.scrollIntoView({ block: "nearest" });
  },
);
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-start justify-center bg-black/40 dark:bg-black/60 pt-20 backdrop-blur-xl"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-lg rounded-xl bg-[var(--bg-secondary)] shadow-2xl overflow-hidden">
      <div class="p-3 border-b border-[var(--border-color)]">
        <div class="relative">
          <svg class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            :value="query"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] py-2.5 pl-9 pr-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none"
            type="search"
            :placeholder="t('palette.placeholder')"
            @input="onQueryInput"
          />
        </div>
      </div>
      <div
        ref="listEl"
        class="max-h-80 overflow-auto p-2"
      >
        <button
          v-for="(item, itemIndex) in items"
          :key="item.id"
          type="button"
          class="w-full rounded-lg px-3 py-2.5 text-left transition"
          :class="[
            item.enabled === false ? 'opacity-40' : '',
            itemIndex === index ? 'bg-[var(--bg-active)]' : 'hover:bg-[var(--bg-hover)]',
          ]"
          :disabled="item.enabled === false"
          @mouseenter="emit('update:index', itemIndex)"
          @click="item.action"
        >
          <div class="flex items-center justify-between gap-3">
            <div class="font-medium">{{ item.label }}</div>
            <span v-if="item.hint" class="text-xs text-[var(--text-secondary)] bg-[var(--bg-tertiary)] px-1.5 py-0.5 rounded">{{
              item.hint
            }}</span>
          </div>
          <div v-if="item.subtitle" class="text-xs text-[var(--text-secondary)] mt-0.5">
            {{ item.subtitle }}
          </div>
        </button>
      </div>
    </div>
  </div>
</template>
