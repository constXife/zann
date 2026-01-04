<script setup lang="ts">
defineProps<{
  message: string;
  actionLabel?: string;
  onAction?: () => void;
}>();
</script>

<template>
  <div
    v-if="message"
    class="fixed bottom-6 right-6 rounded-lg bg-[var(--bg-tertiary)] px-4 py-2.5 text-sm shadow-lg z-[200] flex items-center gap-3"
  >
    <span>{{ message }}</span>
    <button
      v-if="actionLabel && onAction"
      type="button"
      class="text-xs font-semibold text-[var(--accent)] hover:underline"
      @click="onAction"
    >
      {{ actionLabel }}
    </button>
  </div>
</template>
