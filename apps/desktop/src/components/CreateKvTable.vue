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
  canRemove: boolean;
  revealedFields: Set<string>;
  altRevealAll: boolean;
  t: Translator;
  addCustomField: () => void;
  removeField: (id: string) => void;
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
    if (!field || !field.isSecret) {
      return;
    }
    field.value = props.generateSecret();
    triggerAutoReveal(field.id);
  },
);
</script>

<template>
  <div class="space-y-2">
    <div class="rounded-lg border border-transparent overflow-visible">
      <div
        v-for="(field, idx) in props.fields"
        :key="field.id"
        class="flex items-center gap-2 border-b border-[var(--border-color)] last:border-b-0 bg-[var(--bg-tertiary)] py-2"
      >
        <div class="grid min-w-0 flex-1 grid-cols-2 gap-2">
          <input
            v-model="field.key"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="min-w-0 w-full rounded bg-[var(--bg-secondary)] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
            :placeholder="props.t('create.fieldKeyPlaceholder')"
            :data-testid="`kv-key-${idx}`"
          />
          <input
            v-model="field.value"
            :type="field.isSecret && !isRevealed(field.id) ? 'password' : 'text'"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="min-w-0 w-full rounded bg-[var(--bg-secondary)] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
            :placeholder="props.t('create.fieldValuePlaceholder')"
            @focus="setFocusReveal(field.id, true)"
            @blur="setFocusReveal(field.id, false)"
            :data-testid="`kv-value-${idx}`"
          />
        </div>
        <div class="relative flex items-center justify-center text-[var(--text-secondary)] w-10">
          <GeneratorPopover
            v-if="field.isSecret"
            :t="props.t"
            :model-value="isGeneratorOpen(field.id)"
            v-model:length="generatorLength"
            v-model:include-upper="generatorIncludeUpper"
            v-model:include-lower="generatorIncludeLower"
            v-model:include-digits="generatorIncludeDigits"
            v-model:include-symbols="generatorIncludeSymbols"
            v-model:avoid-ambiguous="generatorAvoidAmbiguous"
            v-model:memorable="generatorMemorable"
            button-class="inline-flex h-8 w-8 items-center justify-center rounded text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            icon-class="text-xs"
            @update:modelValue="(open) => setGeneratorOpen(field.id, open)"
            @regenerate="() => { field.value = props.generateSecret(); triggerAutoReveal(field.id); }"
          />
        </div>
        <div class="flex items-center justify-end gap-1 text-[var(--text-secondary)]">
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            @click="field.isSecret = !field.isSecret"
            :title="field.isSecret ? props.t('create.secretLabel') : props.t('create.publicLabel')"
          >
            <span class="text-sm">{{ field.isSecret ? '🔒' : '🔓' }}</span>
          </button>
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] disabled:opacity-40 disabled:cursor-not-allowed"
            :disabled="idx === 0"
            @click="idx !== 0 && props.removeField(field.id)"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>
      <div v-if="!props.fields.length" class="py-4 text-center text-xs text-[var(--text-secondary)]">
        {{ props.t("create.noFields") }}
      </div>
      <div class="pt-2 pb-4">
        <button
          type="button"
          class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-[var(--border-color)] text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
          @click="props.addCustomField"
          :title="props.t('create.addKeyValue')"
        >
          +
        </button>
      </div>
    </div>
  </div>
</template>
