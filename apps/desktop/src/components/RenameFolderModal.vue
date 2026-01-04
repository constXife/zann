<script setup lang="ts">
type Translator = (key: string) => string;

defineProps<{
  open: boolean;
  oldPath: string;
  newPath: string;
  newName: string;
  busy: boolean;
  error: string;
  affectedCount: number;
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  "update:newName": [string];
  submit: [];
}>();

const onNameInput = (event: Event) => {
  const target = event.target as HTMLInputElement | null;
  emit("update:newName", target?.value ?? "");
};
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[110]"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <div class="flex items-center justify-between gap-3">
        <h3 class="text-lg font-semibold">{{ t("folder.renameTitle") }}</h3>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="mt-4 space-y-4">
        <div class="text-sm">
          <div class="text-[var(--text-secondary)]">{{ t("folder.oldPath") }}</div>
          <div class="mt-1 font-mono text-xs bg-[var(--bg-tertiary)] rounded px-2 py-1">{{ oldPath }}</div>
        </div>

        <label class="block space-y-1 text-sm">
          <span class="font-medium">{{ t("folder.newName") }}</span>
          <input
            :value="newName"
            type="text"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            @input="onNameInput"
          />
        </label>

        <div v-if="newPath" class="text-sm">
          <div class="text-[var(--text-secondary)]">{{ t("folder.newPath") }}</div>
          <div class="mt-1 font-mono text-xs bg-[var(--bg-tertiary)] rounded px-2 py-1">{{ newPath }}</div>
        </div>

        <div class="text-sm text-[var(--text-secondary)]">
          {{ t("folder.affects", { count: affectedCount }) }}
        </div>

        <p v-if="error" class="text-sm text-category-security">{{ error }}</p>
      </div>

      <div class="mt-6 flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)] transition-colors"
          @click="emit('update:open', false)"
        >
          {{ t("common.close") }}
        </button>
        <button
          type="button"
          class="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          :disabled="busy || !newName.trim()"
          @click="emit('submit')"
        >
          <svg v-if="busy" class="inline-block h-4 w-4 animate-spin mr-1" viewBox="0 0 24 24" fill="none">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
          </svg>
          {{ t("folder.rename") }}
        </button>
      </div>
    </div>
  </div>
</template>
