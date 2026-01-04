<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  variant?: "opacity" | "color";
  hidden?: boolean;
  active?: boolean;
}>();

const baseClass = computed(() => {
  if (props.variant === "opacity") {
    return "w-1 cursor-col-resize transition-opacity duration-200 flex-shrink-0";
  }
  return "w-1 cursor-col-resize bg-transparent hover:bg-[var(--accent)] transition-colors flex-shrink-0";
});

const stateClass = computed(() => {
  if (props.variant === "opacity") {
    return props.hidden ? "opacity-0 pointer-events-none" : "opacity-100 hover:bg-[var(--accent)]";
  }
  return props.active ? "bg-[var(--accent)]" : "";
});
</script>

<template>
  <div
    :class="[baseClass, stateClass]"
    v-bind="$attrs"
  ></div>
</template>
