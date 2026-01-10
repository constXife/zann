<script setup lang="ts">
type Translator = (key: string, params?: Record<string, unknown>) => string;

const props = defineProps<{
  open: boolean;
  serverUrl: string;
  availableMethods: string[];
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  selectPassword: [];
  selectOidc: [];
}>();
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl z-[110]"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-md rounded-xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <!-- Header -->
      <div class="flex items-center justify-between gap-3 mb-6">
        <h3 class="text-lg font-semibold">{{ t("auth.selectMethod") }}</h3>
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

      <!-- Server URL -->
      <div class="text-sm text-[var(--text-tertiary)] mb-4">
        {{ serverUrl }}
      </div>

      <!-- Options -->
      <div class="space-y-3">
        <!-- Email & Password -->
        <button
          v-if="availableMethods.includes('password')"
          type="button"
          class="w-full flex items-center gap-4 rounded-lg bg-[var(--bg-tertiary)] p-4 hover:bg-[var(--bg-hover)] transition-colors text-left"
          @click="emit('selectPassword')"
          data-testid="auth-method-password"
        >
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-hover)]">
            <svg class="h-5 w-5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div class="flex-1 min-w-0">
            <div class="font-medium">{{ t("auth.emailPassword") }}</div>
            <div class="text-xs text-[var(--text-tertiary)]">{{ t("auth.emailPasswordDesc") }}</div>
          </div>
          <svg class="h-5 w-5 text-[var(--text-tertiary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
          </svg>
        </button>

        <!-- OIDC / Browser -->
        <button
          v-if="availableMethods.includes('oidc')"
          type="button"
          class="w-full flex items-center gap-4 rounded-lg bg-[var(--bg-tertiary)] p-4 hover:bg-[var(--bg-hover)] transition-colors text-left"
          @click="emit('selectOidc')"
          data-testid="auth-method-oidc"
        >
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-hover)]">
            <svg class="h-5 w-5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
          </div>
          <div class="flex-1 min-w-0">
            <div class="font-medium">{{ t("auth.oidc") }}</div>
            <div class="text-xs text-[var(--text-tertiary)]">{{ t("auth.oidcDesc") }}</div>
          </div>
          <svg class="h-5 w-5 text-[var(--text-tertiary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
          </svg>
        </button>
      </div>
    </div>
  </div>
</template>
