<script setup lang="ts">
import { computed } from "vue";

const modelValue = defineModel<string>({ required: true });

const props = defineProps<{
  vaultName: string;
  pathTokens: string[];
  tokenDeleteArmed: boolean;
  vaultShake: boolean;
  placeholder: string;
  suggestions: string[];
  dense?: boolean;
  hasError?: boolean;
  inputTestId?: string;
}>();

const emit = defineEmits<{
  (e: "focus"): void;
  (e: "blur"): void;
  (e: "keydown", event: KeyboardEvent): void;
  (e: "paste", event: ClipboardEvent): void;
  (e: "apply-suggestion", value: string): void;
}>();

const containerClass = computed(() =>
  props.dense
    ? "min-h-[36px] border border-transparent bg-[var(--bg-secondary)] text-xs focus-within:border-[var(--border-color)]"
    : "min-h-[44px] bg-[var(--bg-tertiary)] text-sm focus-within:ring-2 focus-within:ring-[var(--accent)]",
);

const errorClass = computed(() =>
  props.hasError
    ? "ring-2 ring-category-security/50 border-category-security/60"
    : "",
);

const tokenClass = computed(() =>
  props.dense ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs",
);

const inputClass = computed(() =>
  props.dense
    ? "min-w-[120px] px-1 py-0.5 text-xs"
    : "min-w-[140px] px-1 py-1 text-sm",
);
</script>

<template>
  <div class="relative">
    <div
      class="flex flex-wrap items-center gap-2 rounded-lg"
      :class="[containerClass, errorClass]"
    >
      <span
        class="inline-flex items-center gap-1 rounded-full bg-[var(--bg-secondary)] text-[var(--text-secondary)]"
        :class="[tokenClass, { 'vault-shake': props.vaultShake }]"
      >
        🔒 {{ props.vaultName }}
      </span>
      <span class="text-[var(--text-secondary)] font-semibold">/</span>
      <template v-for="(token, idx) in props.pathTokens" :key="`${token}-${idx}`">
        <span
          class="inline-flex items-center gap-1 rounded-full text-[var(--text-secondary)]"
          :class="[
            tokenClass,
            idx === props.pathTokens.length - 1 && props.tokenDeleteArmed && !props.dense
              ? 'bg-category-security/15 text-category-security'
              : 'bg-[var(--bg-secondary)]',
          ]"
        >
          📂 {{ token }}
        </span>
        <span class="text-[var(--text-secondary)] font-semibold">/</span>
      </template>
      <input
        v-model="modelValue"
        type="text"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck="false"
        class="flex-1 bg-transparent focus:outline-none"
        :class="inputClass"
        :placeholder="props.placeholder"
        :data-testid="props.inputTestId"
        @focus="emit('focus')"
        @blur="emit('blur')"
        @keydown="emit('keydown', $event)"
        @paste="emit('paste', $event)"
      />
    </div>
    <ul
      v-if="props.suggestions.length > 0"
      class="absolute z-50 mt-1 w-full max-h-48 overflow-auto rounded-lg bg-[var(--bg-tertiary)] border border-[var(--border-color)] shadow-lg"
    >
      <li
        v-for="folder in props.suggestions"
        :key="folder"
        class="px-3 py-2 cursor-pointer hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
        :class="props.dense ? 'text-xs' : 'text-sm'"
        @mousedown.prevent="emit('apply-suggestion', folder)"
      >
        <span class="text-[var(--text-secondary)]">📁</span>
        <span class="ml-2">{{ folder }}</span>
      </li>
    </ul>
  </div>
</template>

<style scoped>
@keyframes vault-shake {
  0% { transform: translateX(0); }
  20% { transform: translateX(-3px); }
  40% { transform: translateX(3px); }
  60% { transform: translateX(-2px); }
  80% { transform: translateX(2px); }
  100% { transform: translateX(0); }
}

.vault-shake {
  animation: vault-shake 0.25s ease-in-out;
}
</style>
