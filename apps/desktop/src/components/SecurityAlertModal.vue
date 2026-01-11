<script setup lang="ts">
const open = defineModel<boolean>("open", { required: true });

const props = defineProps<{
  title: string;
  message: string;
  t: (key: string) => string;
}>();

const close = () => {
  open.value = false;
};
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl"
  >
    <div class="w-full max-w-md rounded-2xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-semibold text-category-security">{{ title }}</h2>
        <button
          type="button"
          class="rounded-lg px-2 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
          @click="close"
        >
          {{ t("common.close") }}
        </button>
      </div>
      <p class="mt-3 text-sm text-[var(--text-secondary)]">
        {{ message }}
      </p>
      <button
        type="button"
        class="mt-5 w-full rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-4 py-3 text-sm font-semibold text-white transition-colors"
        @click="close"
      >
        {{ t("common.close") }}
      </button>
    </div>
  </div>
</template>
