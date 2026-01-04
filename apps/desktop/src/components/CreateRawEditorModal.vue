<script setup lang="ts">
import JsonEditor from "./JsonEditor.vue";
import type { Translator } from "../types/createForm";

const open = defineModel<boolean>("open", { required: true });
const rawJsonText = defineModel<string>("rawJsonText", { required: true });

const props = defineProps<{
  jsonPlaceholderText: string;
  errorKey: string;
  t: Translator;
  onSave: () => void;
  onClose: () => void;
  onValidation: (key: string) => void;
}>();
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/50 backdrop-blur-sm z-[70]"
    @click.self="props.onClose"
  >
    <div class="w-full max-w-2xl rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <div class="flex items-center justify-between gap-3">
        <div>
          <h3 class="text-lg font-semibold">{{ props.t("create.editRawJson") }}</h3>
          <p class="mt-1 text-sm text-[var(--text-secondary)]">
            {{ props.t("create.rawJsonHint") }}
          </p>
        </div>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
          @click="props.onClose"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="mt-4 space-y-2">
        <JsonEditor
          v-model="rawJsonText"
          :placeholder="props.jsonPlaceholderText"
          @validation="props.onValidation"
        />
        <p v-if="props.errorKey" class="text-xs text-category-security">
          {{ props.t(props.errorKey) }}
        </p>
      </div>

      <div class="mt-6 flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg px-4 py-2 text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
          @click="props.onClose"
        >
          {{ props.t("common.cancel") }}
        </button>
        <button
          type="button"
          class="rounded-lg bg-gray-800 px-4 py-2 text-sm font-semibold text-white hover:bg-gray-700"
          @click="props.onSave"
        >
          {{ props.t("common.save") }}
        </button>
      </div>
    </div>
  </div>
</template>
