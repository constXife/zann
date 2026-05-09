<script setup lang="ts">
import { ref, watch } from "vue";
import GeneratorPopover from "./GeneratorPopover.vue";
import type { FieldInput, Translator } from "../types/createForm";
import { allowTokenBeforeInput, allowTokenKeydown, handleTokenPaste } from "../utils/inputSanitizer";

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
const manualRevealIds = ref(new Set<string>());
const autoRevealIds = ref(new Set<string>());
const autoRevealTimers = new Map<string, number>();
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

const shouldMultiline = (value: string) =>
  value.includes("\n") || value.length > 80;

const autoResize = (event: Event) => {
  const el = event.target as HTMLTextAreaElement;
  el.style.height = "auto";
  el.style.height = `${el.scrollHeight}px`;
};

const openExpanded = (id: string) => {
  expandedFieldId.value = id;
};

const closeExpanded = () => {
  expandedFieldId.value = null;
};

const updateExpandedValue = (event: Event) => {
  if (!expandedFieldId.value) return;
  const field = props.advancedFields.find((item) => item.id === expandedFieldId.value)
    ?? props.customFields.find((item) => item.id === expandedFieldId.value);
  if (!field) return;
  field.value = (event.target as HTMLTextAreaElement).value;
};

const toggleCustomSecret = (field: FieldInput) => {
  field.isSecret = !field.isSecret;
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
        <label class="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">
          {{ props.getFieldLabel(field.key) }}
        </label>
        <div v-if="field.fieldType === 'note'" class="relative">
          <textarea
            v-model="field.value"
            rows="3"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="w-full rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 pr-12 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] resize-y"
            @input="autoResize"
          ></textarea>
          <div class="absolute right-2 top-2 flex items-center gap-1">
            <button
              type="button"
              class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              :title="props.t('create.expandValue')"
              @click="openExpanded(field.id)"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4" />
              </svg>
            </button>
          </div>
        </div>
        <div v-else class="relative">
          <textarea
            v-if="shouldMultiline(field.value) && (field.fieldType !== 'secret' && field.fieldType !== 'otp' || isRevealed(field.id))"
            v-model="field.value"
            rows="1"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="w-full rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 pr-12 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)] resize-y"
            @input="autoResize"
            @focus="setFocusReveal(field.id, true)"
            @blur="setFocusReveal(field.id, false)"
          ></textarea>
          <input
            v-else
            v-model="field.value"
            :type="(field.fieldType === 'secret' || field.fieldType === 'otp') && !isRevealed(field.id) ? 'password' : 'text'"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            class="w-full rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] px-3 py-2 pr-12 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            @focus="setFocusReveal(field.id, true)"
            @blur="setFocusReveal(field.id, false)"
          />
          <div class="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
            <button
              v-if="field.fieldType === 'secret' || field.fieldType === 'otp'"
              type="button"
              class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              :title="isRevealed(field.id) ? props.t('create.hideValue') : props.t('create.revealValue')"
              @click="toggleReveal(field.id)"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  v-if="isRevealed(field.id)"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="1.5"
                  d="M3 3l18 18M10.94 10.94a3 3 0 014.12 4.12M9.88 5.09A9 9 0 0121 12c-1.73 3.08-5.12 6-9 6a9.77 9.77 0 01-4.88-1.34M6.1 6.1A9.77 9.77 0 003 12c1.73 3.08 5.12 6 9 6a9.74 9.74 0 004.11-.9"
                />
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
              button-class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
              @update:modelValue="(open) => setGeneratorOpen(field.id, open)"
              @regenerate="() => { field.value = props.generateSecret(); triggerAutoReveal(field.id); }"
            />
            <button
              type="button"
              class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              :title="props.t('create.expandValue')"
              @click="openExpanded(field.id)"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4" />
              </svg>
            </button>
          </div>
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
            class="flex-1 min-w-0 rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
            :placeholder="props.t('create.fieldKeyPlaceholder')"
            @beforeinput="allowTokenBeforeInput"
            @keydown="allowTokenKeydown"
            @paste="handleTokenPaste"
          />
          <div class="relative flex-1 min-w-0">
            <textarea
              v-if="shouldMultiline(field.value) && (!field.isSecret || isRevealed(field.id))"
              v-model="field.value"
              rows="1"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              class="w-full rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-2 py-1 pr-10 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--accent)] resize-y"
              :placeholder="props.t('create.fieldValuePlaceholder')"
              @input="autoResize"
              @focus="setFocusReveal(field.id, true)"
              @blur="setFocusReveal(field.id, false)"
            ></textarea>
            <input
              v-else
              v-model="field.value"
              :type="field.isSecret && !isRevealed(field.id) ? 'password' : 'text'"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              class="w-full rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-2 py-1 pr-10 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
              :placeholder="props.t('create.fieldValuePlaceholder')"
              @focus="setFocusReveal(field.id, true)"
              @blur="setFocusReveal(field.id, false)"
            />
            <div class="absolute right-1 top-1/2 -translate-y-1/2 flex items-center gap-1">
              <button
                v-if="field.isSecret"
                type="button"
                class="rounded p-0.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
                :title="isRevealed(field.id) ? props.t('create.hideValue') : props.t('create.revealValue')"
                @click="toggleReveal(field.id)"
              >
                <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    v-if="isRevealed(field.id)"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="1.5"
                    d="M3 3l18 18M10.94 10.94a3 3 0 014.12 4.12M9.88 5.09A9 9 0 0121 12c-1.73 3.08-5.12 6-9 6a9.77 9.77 0 01-4.88-1.34M6.1 6.1A9.77 9.77 0 003 12c1.73 3.08 5.12 6 9 6a9.74 9.74 0 004.11-.9"
                  />
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
                button-class="rounded p-0.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
                icon-class="text-[10px]"
                @update:modelValue="(open) => setGeneratorOpen(field.id, open)"
                @regenerate="() => { field.value = props.generateSecret(); triggerAutoReveal(field.id); }"
              />
              <button
                type="button"
                class="rounded p-0.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
                :title="props.t('create.expandValue')"
                @click="openExpanded(field.id)"
              >
                <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4" />
                </svg>
              </button>
            </div>
          </div>
          <button
            type="button"
            class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
            @click="toggleCustomSecret(field)"
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

    <div
      v-if="expandedFieldId"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      @click.self="closeExpanded"
    >
      <div class="w-full max-w-2xl rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
        <div class="flex items-center justify-between gap-3">
          <div class="text-sm font-semibold text-[var(--text-primary)]">
            {{
              props.getFieldLabel(
                (props.advancedFields.find((item) => item.id === expandedFieldId)
                  ?? props.customFields.find((item) => item.id === expandedFieldId))?.key ?? "",
              )
            }}
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
          :class="expandedFieldId && (props.advancedFields.find((item) => item.id === expandedFieldId)?.fieldType === 'secret' || props.advancedFields.find((item) => item.id === expandedFieldId)?.fieldType === 'otp' || props.customFields.find((item) => item.id === expandedFieldId)?.isSecret) && !isRevealed(expandedFieldId) ? 'kv-secret-mask' : ''"
          :value="(props.advancedFields.find((item) => item.id === expandedFieldId) ?? props.customFields.find((item) => item.id === expandedFieldId))?.value ?? ''"
          @input="updateExpandedValue"
        ></textarea>
        <div class="mt-4 flex items-center justify-between">
          <button
            v-if="expandedFieldId && (props.advancedFields.find((item) => item.id === expandedFieldId)?.fieldType === 'secret' || props.advancedFields.find((item) => item.id === expandedFieldId)?.fieldType === 'otp' || props.customFields.find((item) => item.id === expandedFieldId)?.isSecret)"
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            @click="toggleReveal(expandedFieldId)"
          >
            {{ isRevealed(expandedFieldId) ? props.t("create.hideValue") : props.t("create.revealValue") }}
          </button>
          <button
            type="button"
            class="ml-auto rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
            @click="closeExpanded"
          >
            {{ props.t("common.close") }}
          </button>
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
