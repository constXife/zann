<script setup lang="ts">
import { ref, watch } from "vue";
import GeneratorPopover from "./GeneratorPopover.vue";
import type { FieldInput, Translator } from "../types/createForm";
import { allowTokenBeforeInput, allowTokenKeydown, handleTokenPaste } from "../utils/inputSanitizer";

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
const keyRefs = ref<HTMLInputElement[]>([]);
const manualRevealIds = ref(new Set<string>());
const autoRevealIds = ref(new Set<string>());
const autoRevealTimers = new Map<string, number>();
const menuOpenId = ref<string | null>(null);
const expandedFieldId = ref<string | null>(null);

const isRevealed = (id: string) =>
  props.revealedFields.has(id) ||
  focusRevealIds.value.has(id) ||
  manualRevealIds.value.has(id) ||
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

const toggleReveal = (id: string) => {
  const next = new Set(manualRevealIds.value);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  manualRevealIds.value = next;
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

const setKeyRef = (el: HTMLInputElement | null, idx: number) => {
  if (!el) return;
  keyRefs.value[idx] = el;
};

const focusFirstKey = () => {
  keyRefs.value[0]?.focus();
};

const shouldMultiline = (value: string) =>
  value.includes("\n") || value.length > 80;

const handleValueKeydown = (event: KeyboardEvent, field: FieldInput) => {
  if (event.key !== "Enter") {
    return;
  }
  if (event.shiftKey) {
    event.preventDefault();
    field.value = field.value ? `${field.value}\n` : "\n";
    return;
  }
  event.preventDefault();
  props.addCustomField();
};

const autoResize = (event: Event) => {
  const el = event.target as HTMLTextAreaElement;
  el.style.height = "auto";
  el.style.height = `${el.scrollHeight}px`;
};

const copyValue = async (value: string) => {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }
};

const openExpanded = (id: string) => {
  expandedFieldId.value = id;
};

const closeExpanded = () => {
  expandedFieldId.value = null;
};

const updateExpandedValue = (event: Event) => {
  if (!expandedFieldId.value) return;
  const field = props.fields.find((item) => item.id === expandedFieldId.value);
  if (!field) return;
  field.value = (event.target as HTMLTextAreaElement).value;
};

const toggleMenu = (id: string) => {
  menuOpenId.value = menuOpenId.value === id ? null : id;
};

const closeMenu = () => {
  menuOpenId.value = null;
};

const toggleFieldSecret = (field: FieldInput) => {
  field.isSecret = !field.isSecret;
  closeMenu();
};

const removeRow = (field: FieldInput, idx: number) => {
  if (idx === 0) return;
  props.removeField(field.id);
  closeMenu();
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

defineExpose({ focusFirstKey });
</script>

<template>
  <div class="space-y-2">
    <div class="rounded-lg border border-transparent overflow-visible">
      <div
        v-for="(field, idx) in props.fields"
        :key="field.id"
        class="group flex items-center gap-2 border-b border-[var(--border-color)] last:border-b-0 bg-[var(--bg-tertiary)] py-2"
      >
        <div class="grid min-w-0 flex-1 grid-cols-[minmax(0,40%)_minmax(0,1fr)] gap-2">
          <input
            v-model="field.key"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="min-w-0 w-full rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
            :placeholder="props.t('create.fieldKeyPlaceholder')"
            :data-testid="`kv-key-${idx}`"
            :ref="(el) => setKeyRef(el as HTMLInputElement | null, idx)"
            @beforeinput="allowTokenBeforeInput"
            @keydown="allowTokenKeydown"
            @paste="handleTokenPaste"
          />
          <textarea
            v-if="shouldMultiline(field.value) && (!field.isSecret || isRevealed(field.id))"
            v-model="field.value"
            rows="1"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="min-w-0 w-full rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[var(--accent)] resize-y"
            :placeholder="props.t('create.fieldValuePlaceholder')"
            @input="autoResize"
            @focus="setFocusReveal(field.id, true)"
            @blur="setFocusReveal(field.id, false)"
            :data-testid="`kv-value-${idx}`"
          ></textarea>
          <input
            v-else
            v-model="field.value"
            :type="field.isSecret && !isRevealed(field.id) ? 'password' : 'text'"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="min-w-0 w-full rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
            :placeholder="props.t('create.fieldValuePlaceholder')"
            @focus="setFocusReveal(field.id, true)"
            @blur="setFocusReveal(field.id, false)"
            @keydown="(event) => handleValueKeydown(event, field)"
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
        <div class="relative flex items-center justify-end gap-1 text-[var(--text-secondary)]">
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            :title="isRevealed(field.id) ? props.t('create.hideValue') : props.t('create.revealValue')"
            :disabled="!field.isSecret"
            @click="field.isSecret && toggleReveal(field.id)"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <template v-if="isRevealed(field.id)">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="1.5"
                  d="M3 3l18 18M10.94 10.94a3 3 0 014.12 4.12M9.88 5.09A9 9 0 0121 12c-1.73 3.08-5.12 6-9 6a9.77 9.77 0 01-4.88-1.34M6.1 6.1A9.77 9.77 0 003 12c1.73 3.08 5.12 6 9 6a9.74 9.74 0 004.11-.9"
                />
              </template>
              <template v-else>
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="1.5"
                  d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                />
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="1.5"
                  d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                />
              </template>
            </svg>
          </button>
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            :title="props.t('create.copyValue')"
            @click="copyValue(field.value)"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 7h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z" />
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 7V6a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v9" />
            </svg>
          </button>
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            :title="props.t('create.expandValue')"
            @click="openExpanded(field.id)"
            :class="field.isSecret ? 'opacity-0 group-hover:opacity-100 transition-opacity' : 'opacity-100'"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4" />
            </svg>
          </button>
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            :title="props.t('create.moreActions')"
            @click="toggleMenu(field.id)"
            :class="'opacity-0 group-hover:opacity-100 transition-opacity'"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v.01M12 12v.01M12 18v.01" />
            </svg>
          </button>
          <div
            v-if="menuOpenId === field.id"
            class="absolute right-10 top-full mt-1 w-40 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-50"
          >
            <button
              type="button"
              class="w-full px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
              @click="toggleFieldSecret(field)"
            >
              {{ field.isSecret ? props.t('create.makePublic') : props.t('create.makeSecret') }}
            </button>
            <button
              type="button"
              class="w-full px-3 py-2 text-sm text-left text-category-security hover:bg-[var(--bg-hover)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              :disabled="idx === 0"
              @click="removeRow(field, idx)"
            >
              {{ props.t("create.removeRow") }}
            </button>
          </div>
        </div>
      </div>
      <div v-if="!props.fields.length" class="py-4 text-center text-xs text-[var(--text-secondary)]">
        <div class="font-medium text-[var(--text-primary)]">{{ props.t("create.addFirstRow") }}</div>
        <button
          type="button"
          class="mt-2 inline-flex items-center gap-2 rounded-lg border border-[var(--border-color)] px-3 py-1 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
          @click="props.addCustomField"
        >
          {{ props.t("create.addRow") }}
        </button>
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

    <div
      v-if="expandedFieldId"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      @click.self="closeExpanded"
    >
      <div class="w-full max-w-2xl rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <div class="flex items-center justify-between gap-3">
          <div>
            <div class="text-sm font-semibold text-[var(--text-primary)]">
              {{ props.t("create.expandValue") }}
            </div>
            <div class="text-xs text-[var(--text-secondary)]">
              {{ props.t("create.valueLabel") }}
            </div>
          </div>
          <button
            type="button"
            class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            @click="closeExpanded"
          >
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <textarea
          class="mt-4 w-full rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] resize-y min-h-[200px]"
          :class="expandedFieldId && props.fields.find((item) => item.id === expandedFieldId)?.isSecret && !isRevealed(expandedFieldId) ? 'kv-secret-mask' : ''"
          :value="props.fields.find((item) => item.id === expandedFieldId)?.value ?? ''"
          @input="updateExpandedValue"
        ></textarea>
        <div class="mt-4 flex items-center justify-between">
          <button
            v-if="expandedFieldId && props.fields.find((item) => item.id === expandedFieldId)?.isSecret"
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            @click="toggleReveal(expandedFieldId)"
          >
            {{ isRevealed(expandedFieldId) ? props.t("create.hideValue") : props.t("create.revealValue") }}
          </button>
          <div class="ml-auto flex items-center gap-2">
            <button
              type="button"
              class="rounded-lg px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              @click="expandedFieldId && copyValue(props.fields.find((item) => item.id === expandedFieldId)?.value ?? '')"
            >
              {{ props.t("create.copyValue") }}
            </button>
            <button
              type="button"
              class="rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
              @click="closeExpanded"
            >
              {{ props.t("common.close") }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.kv-secret-mask {
  -webkit-text-security: disc;
  text-security: disc;
}
</style>
