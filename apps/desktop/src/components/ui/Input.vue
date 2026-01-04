<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cva } from "class-variance-authority";
import { cn } from "../../lib/utils";

const inputVariants = cva(
  "flex h-10 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
);

const props = defineProps<{
  type?: string;
}>();

const attrs = useAttrs();
const classes = computed(() => cn(inputVariants(), attrs.class));
const passthrough = computed(() => {
  const { class: _class, ...rest } = attrs as Record<string, unknown>;
  return rest;
});
</script>

<template>
  <input :type="props.type ?? 'text'" v-bind="passthrough" :class="classes" />
</template>
