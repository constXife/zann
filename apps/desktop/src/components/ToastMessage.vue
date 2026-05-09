<script setup lang="ts">
import type { ToastItem } from "../composables/app/state/useAppToast";

defineProps<{
  toasts: ToastItem[];
}>();
</script>

<template>
  <div v-if="toasts.length" class="fixed bottom-6 right-6 z-[200] flex flex-col gap-2">
    <div
      v-for="toast in toasts"
      :key="toast.id"
      class="rounded-lg bg-[var(--bg-tertiary)] px-4 py-2.5 text-sm shadow-lg flex items-center gap-3"
    >
      <span>{{ toast.message }}</span>
      <button
        v-if="toast.actionLabel && toast.action"
        type="button"
        class="text-xs font-semibold text-[var(--accent)] hover:underline"
        @click="toast.action"
      >
        {{ toast.actionLabel }}
      </button>
    </div>
  </div>
</template>
