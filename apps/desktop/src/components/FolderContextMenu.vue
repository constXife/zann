<script setup lang="ts">
type Translator = (key: string) => string;

type MenuPosition = {
  x: number;
  y: number;
};

defineProps<{
  open: boolean;
  position: MenuPosition;
  t: Translator;
}>();

const emit = defineEmits<{
  close: [];
  rename: [];
  copy: [];
}>();
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 z-[100]"
    @click="emit('close')"
  >
    <div
      class="absolute rounded-lg bg-[var(--bg-secondary)] border border-[var(--border-color)] shadow-xl py-1 min-w-[160px]"
      :style="{ left: position.x + 'px', top: position.y + 'px' }"
      @click.stop
    >
      <button
        type="button"
        class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors flex items-center gap-2"
        @click="emit('rename')"
      >
        <svg class="h-4 w-4 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
        </svg>
        {{ t("folder.rename") }}
      </button>
      <button
        type="button"
        class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors flex items-center gap-2"
        @click="emit('copy')"
      >
        <svg class="h-4 w-4 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
        {{ t("folder.copyPath") }}
      </button>
    </div>
  </div>
</template>
