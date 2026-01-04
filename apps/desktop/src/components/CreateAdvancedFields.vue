<script setup lang="ts">
import { ref, watch } from "vue";
import GeneratorPopover from "./GeneratorPopover.vue";
import type { FieldInput, Translator } from "../types/createForm";

const advancedOpen = defineModel<boolean>("advancedOpen", { required: true });
const generatorOpenId = defineModel<string | null>("generatorOpenId", { required: true });
const generatorLength = defineModel<number>("generatorLength", { required: true });
const generatorIncludeUpper = defineModel<boolean>("generatorIncludeUpper", { required: true });
const generatorIncludeLower = defineModel<boolean>("generatorIncludeLower", { required: true });
const generatorIncludeDigits = defineModel<boolean>("generatorIncludeDigits", { required: true });
const generatorIncludeSymbols = defineModel<boolean>("generatorIncludeSymbols", { required: true });
const generatorAvoidAmbiguous = defineModel<boolean>("generatorAvoidAmbiguous", { required: true });
const generatorMemorable = defineModel<boolean>("generatorMemorable", { required: true });

const props = defineProps<{
  advancedFields: FieldInput[];
  customFields: FieldInput[];
  revealedFields: Set<string>;
  altRevealAll: boolean;
  getFieldLabel: (key: string) => string;
  t: Translator;
  addCustomField: (isSecret: boolean) => void;
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
    const field =
      props.advancedFields.find((item) => item.id === activeId) ??
      props.customFields.find((item) => item.id === activeId);
    if (!field) {
      return;
    }
    const isSecret =
      field.fieldType === "secret" ||
      field.fieldType === "otp" ||
      field.isSecret;
    if (!isSecret) {
      return;
    }
    field.value = props.generateSecret();
    triggerAutoReveal(field.id);
  },
);
</script>

<template>
  <div v-if="props.advancedFields.length || props.customFields.length" class="border-t border-[var(--border-color)] pt-3">
    <button
      type="button"
      class="flex items-center gap-2 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
      @click="advancedOpen = !advancedOpen"
    >
      <svg
        class="h-4 w-4 transition-transform"
        :class="{ 'rotate-90': advancedOpen }"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
      </svg>
      {{ props.t("create.advanced") }}
    </button>

    <div v-if="advancedOpen" class="mt-3 space-y-3">
      <div
        v-for="field in props.advancedFields"
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

      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">{{ props.t("create.customFields") }}</span>
          <button
            type="button"
            class="text-xs text-[var(--accent)] hover:underline"
            @click="props.addCustomField(false)"
          >
            + {{ props.t("create.addField") }}
          </button>
        </div>
        <div
          v-for="field in props.customFields"
          :key="field.id"
          class="flex items-center gap-2 rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] p-2"
        >
          <input
            v-model="field.key"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="flex-1 min-w-0 rounded bg-[var(--bg-secondary)] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
            :placeholder="props.t('create.fieldKeyPlaceholder')"
          />
          <div class="relative flex-1 min-w-0">
            <input
              v-model="field.value"
              :type="field.isSecret && !isRevealed(field.id) ? 'password' : 'text'"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              class="w-full rounded bg-[var(--bg-secondary)] px-2 py-1 pr-7 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
              :placeholder="props.t('create.fieldValuePlaceholder')"
              @focus="setFocusReveal(field.id, true)"
              @blur="setFocusReveal(field.id, false)"
            />
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
              button-class="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
              icon-class="text-[10px]"
              @update:modelValue="(open) => setGeneratorOpen(field.id, open)"
              @regenerate="() => { field.value = props.generateSecret(); triggerAutoReveal(field.id); }"
            />
          </div>
          <button
            type="button"
            class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            @click="field.isSecret = !field.isSecret"
            :title="field.isSecret ? props.t('create.secretLabel') : props.t('create.publicLabel')"
          >
            <span class="text-xs">{{ field.isSecret ? '🔒' : '🔓' }}</span>
          </button>
          <button
            type="button"
            class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            @click="props.removeField(field.id)"
          >
            <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
