<script setup lang="ts">
import { ref, watch } from "vue";
import GeneratorPopover from "./GeneratorPopover.vue";
import type { FieldInput, Translator } from "../types/createForm";

const generatorOpenId = defineModel<string | null>("generatorOpenId", { required: true });
const generatorLength = defineModel<number>("generatorLength", { required: true });
const generatorIncludeUpper = defineModel<boolean>("generatorIncludeUpper", { required: true });
const generatorIncludeLower = defineModel<boolean>("generatorIncludeLower", { required: true });
const generatorIncludeDigits = defineModel<boolean>("generatorIncludeDigits", { required: true });
const generatorIncludeSymbols = defineModel<boolean>("generatorIncludeSymbols", { required: true });
const generatorAvoidAmbiguous = defineModel<boolean>("generatorAvoidAmbiguous", { required: true });
const generatorMemorable = defineModel<boolean>("generatorMemorable", { required: true });

const props = defineProps<{
  fields: FieldInput[];
  revealedFields: Set<string>;
  altRevealAll: boolean;
  getFieldLabel: (key: string) => string;
  t: Translator;
  generateSecret: () => string;
}>();

const isGeneratorOpen = (id: string) => generatorOpenId.value === id;
const setGeneratorOpen = (id: string, open: boolean) => {
  generatorOpenId.value = open ? id : null;
};

const focusRevealIds = ref(new Set<string>());
const autoRevealIds = ref(new Set<string>());
const autoRevealTimers = new Map<string, number>();

const isRevealed = (id: string) =>
  props.revealedFields.has(id) ||
  focusRevealIds.value.has(id) ||
  autoRevealIds.value.has(id) ||
  generatorOpenId.value === id ||
  props.altRevealAll;

const setFocusReveal = (id: string, active: boolean) => {
  const next = new Set(focusRevealIds.value);
  if (active) {
    next.add(id);
  } else {
    next.delete(id);
  }
  focusRevealIds.value = next;
};

const triggerAutoReveal = (id: string) => {
  const next = new Set(autoRevealIds.value);
  next.add(id);
  autoRevealIds.value = next;
  if (autoRevealTimers.has(id)) {
    window.clearTimeout(autoRevealTimers.get(id));
  }
  const timer = window.setTimeout(() => {
    const updated = new Set(autoRevealIds.value);
    updated.delete(id);
    autoRevealIds.value = updated;
    autoRevealTimers.delete(id);
  }, 2000);
  autoRevealTimers.set(id, timer);
};

watch(
  [
    generatorLength,
    generatorIncludeUpper,
    generatorIncludeLower,
    generatorIncludeDigits,
    generatorIncludeSymbols,
    generatorAvoidAmbiguous,
    generatorMemorable,
  ],
  () => {
    const activeId = generatorOpenId.value;
    if (!activeId) {
      return;
    }
    const field = props.fields.find((item) => item.id === activeId);
    if (!field || (field.fieldType !== "secret" && field.fieldType !== "otp")) {
      return;
    }
    field.value = props.generateSecret();
    triggerAutoReveal(field.id);
  },
);
</script>

<template>
  <div v-if="props.fields.length" class="space-y-3">
    <div
      v-for="field in props.fields"
      :key="field.id"
      class="space-y-1"
    >
      <label class="text-sm font-medium">{{ props.getFieldLabel(field.key) }}</label>
      <textarea
        v-if="field.fieldType === 'note'"
        v-model="field.value"
        rows="3"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck="false"
        class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] resize-y"
      ></textarea>
      <div v-else class="relative">
        <input
          v-model="field.value"
          :type="(field.fieldType === 'secret' || field.fieldType === 'otp') && !isRevealed(field.id) ? 'password' : 'text'"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 pr-9 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
          @focus="setFocusReveal(field.id, true)"
          @blur="setFocusReveal(field.id, false)"
        />
        <GeneratorPopover
          v-if="field.fieldType === 'secret' || field.fieldType === 'otp'"
          :t="props.t"
          :model-value="isGeneratorOpen(field.id)"
          v-model:length="generatorLength"
          v-model:include-upper="generatorIncludeUpper"
          v-model:include-lower="generatorIncludeLower"
          v-model:include-digits="generatorIncludeDigits"
          v-model:include-symbols="generatorIncludeSymbols"
          v-model:avoid-ambiguous="generatorAvoidAmbiguous"
          v-model:memorable="generatorMemorable"
          button-class="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
          @update:modelValue="(open) => setGeneratorOpen(field.id, open)"
          @regenerate="() => { field.value = props.generateSecret(); triggerAutoReveal(field.id); }"
        />
      </div>
    </div>
  </div>
</template>
