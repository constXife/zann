<script setup lang="ts">
type Translator = (key: string, params?: Record<string, unknown>) => string;

const open = defineModel<boolean>({ required: true });
const length = defineModel<number>("length", { required: true });
const includeUpper = defineModel<boolean>("includeUpper", { required: true });
const includeLower = defineModel<boolean>("includeLower", { required: true });
const includeDigits = defineModel<boolean>("includeDigits", { required: true });
const includeSymbols = defineModel<boolean>("includeSymbols", { required: true });
const avoidAmbiguous = defineModel<boolean>("avoidAmbiguous", { required: true });
const memorable = defineModel<boolean>("memorable", { required: true });

const props = defineProps<{
  t: Translator;
  buttonClass?: string;
  iconClass?: string;
  popoverClass?: string;
}>();

const emit = defineEmits<{ (e: "regenerate"): void }>();

const toggleOpen = () => {
  open.value = !open.value;
};

const close = () => {
  open.value = false;
};
</script>

<template>
  <button
    type="button"
    :class="props.buttonClass ?? 'rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]'"
    :title="props.t('create.generateSecret')"
    @click.stop="toggleOpen"
  >
    <span :class="props.iconClass ?? 'text-xs'">
      <slot name="icon">🎲</slot>
    </span>
  </button>
  <div
    v-if="open"
    class="fixed inset-0 z-40"
    @click="close"
  ></div>
  <div
    v-if="open"
    :class="props.popoverClass ?? 'absolute right-0 top-full mt-2 w-64 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] p-3 text-xs shadow-xl z-50'"
    @click.stop
  >
    <div class="flex items-center justify-between">
      <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">
        {{ props.t("create.generatorTitle") }}
      </span>
      <button
        type="button"
        class="rounded p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
        @click="close"
      >
        x
      </button>
    </div>
    <label class="mt-2 flex items-center gap-2 text-xs text-[var(--text-secondary)]">
      <input type="checkbox" v-model="memorable" />
      <span>{{ props.t("create.generatorMemorable") }}</span>
    </label>
    <div class="mt-3 space-y-2">
      <div class="flex items-center justify-between text-xs">
        <span>{{ props.t("create.generatorLength") }}</span>
        <span class="font-semibold">{{ length }}</span>
      </div>
      <input
        v-model.number="length"
        type="range"
        min="4"
        max="128"
        step="1"
        class="w-full"
      />
      <div class="flex flex-wrap gap-2">
        <label class="flex items-center gap-1 text-xs text-[var(--text-secondary)]">
          <input type="checkbox" v-model="includeLower" />
          <span>{{ props.t("create.generatorLower") }}</span>
        </label>
        <label class="flex items-center gap-1 text-xs text-[var(--text-secondary)]">
          <input type="checkbox" v-model="includeUpper" />
          <span>{{ props.t("create.generatorUpper") }}</span>
        </label>
        <label class="flex items-center gap-1 text-xs text-[var(--text-secondary)]">
          <input type="checkbox" v-model="includeDigits" />
          <span>{{ props.t("create.generatorDigits") }}</span>
        </label>
        <label class="flex items-center gap-1 text-xs text-[var(--text-secondary)]">
          <input type="checkbox" v-model="includeSymbols" />
          <span>{{ props.t("create.generatorSymbols") }} !@#</span>
        </label>
        <label class="flex items-center gap-1 text-xs text-[var(--text-secondary)]">
          <input type="checkbox" v-model="avoidAmbiguous" />
          <span>{{ props.t("create.generatorAvoidAmbiguous") }}</span>
        </label>
      </div>
      <button
        type="button"
        class="w-full rounded-md bg-[var(--bg-tertiary)] px-2 py-1 text-xs font-semibold text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
        @click="emit('regenerate')"
      >
        {{ props.t("create.regenerate") }}
      </button>
    </div>
  </div>
</template>
