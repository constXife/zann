<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  modelValue: string;
  placeholder?: string;
}>();

const emit = defineEmits<{
  "update:modelValue": [string];
  validation: [string];
}>();

const localValue = computed({
  get: () => props.modelValue ?? "",
  set: (value: string) => {
    emit("update:modelValue", value);
  },
});

const validateJson = (text: string) => {
  const trimmed = text.trim();
  if (!trimmed) {
    emit("validation", "");
    return;
  }
  try {
    JSON.parse(trimmed);
    emit("validation", "");
  } catch {
    emit("validation", "create.invalidJson");
  }
};
</script>

<template>
  <textarea
    v-model="localValue"
    class="w-full min-h-[180px] rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
    :placeholder="placeholder"
    @blur="validateJson(localValue)"
  ></textarea>
</template>
