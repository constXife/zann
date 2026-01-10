<script setup lang="ts">
import { computed, ref, watch } from "vue";

type Translator = (key: string, params?: Record<string, unknown>) => string;

const props = defineProps<{
  open: boolean;
  serverUrl: string;
  busy: boolean;
  error: string;
  t: Translator;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
  submit: [
    payload: {
      mode: "login" | "register";
      email: string;
      password: string;
      fullName?: string | null;
    }
  ];
}>();

const mode = ref<"login" | "register">("login");
const email = ref("");
const password = ref("");
const confirm = ref("");
const fullName = ref("");
const localError = ref("");

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      mode.value = "login";
      email.value = "";
      password.value = "";
      confirm.value = "";
      fullName.value = "";
      localError.value = "";
    }
  }
);

const handleSubmit = () => {
  if (!email.value || !password.value) return;
  localError.value = "";
  if (mode.value === "register" && password.value !== confirm.value) {
    localError.value = props.t("auth.passwordMismatch");
    return;
  }
  emit("submit", {
    mode: mode.value,
    email: email.value,
    password: password.value,
    fullName: fullName.value.trim() ? fullName.value.trim() : null,
  });
};

const canSubmit = computed(() => {
  if (!email.value || !password.value) return false;
  if (mode.value === "register") {
    return confirm.value.length > 0 && confirm.value === password.value;
  }
  return true;
});

const toggleMode = () => {
  mode.value = mode.value === "login" ? "register" : "login";
  localError.value = "";
};
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
        <h3 class="text-lg font-semibold">
          {{ mode === "register" ? t("auth.signUp") : t("auth.signIn") }}
        </h3>
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

      <!-- Error -->
      <div
        v-if="localError || error"
        class="mb-4 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-500"
      >
        {{ localError || error }}
      </div>

      <!-- Form -->
      <form @submit.prevent="handleSubmit" class="space-y-4">
        <div v-if="mode === 'register'">
          <label class="block text-sm font-medium mb-1.5">{{ t("auth.fullName") }}</label>
          <input
            v-model="fullName"
            type="text"
            :placeholder="t('auth.fullName')"
            :disabled="busy"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2.5 text-sm placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] disabled:opacity-50"
            autocomplete="name"
            data-testid="auth-full-name"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">{{ t("auth.email") }}</label>
          <input
            v-model="email"
            type="email"
            :placeholder="t('auth.email')"
            :disabled="busy"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2.5 text-sm placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] disabled:opacity-50"
            autocomplete="email"
            data-testid="auth-email"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">{{ t("auth.password") }}</label>
          <input
            v-model="password"
            type="password"
            :placeholder="t('auth.password')"
            :disabled="busy"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2.5 text-sm placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] disabled:opacity-50"
            :autocomplete="mode === 'register' ? 'new-password' : 'current-password'"
            data-testid="auth-password"
          />
        </div>

        <div v-if="mode === 'register'">
          <label class="block text-sm font-medium mb-1.5">{{ t("auth.confirmPassword") }}</label>
          <input
            v-model="confirm"
            type="password"
            :placeholder="t('auth.confirmPassword')"
            :disabled="busy"
            class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2.5 text-sm placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] disabled:opacity-50"
            autocomplete="new-password"
            data-testid="auth-confirm"
          />
        </div>

        <button
          type="submit"
          :disabled="busy || !canSubmit"
          class="w-full rounded-lg bg-[var(--accent)] px-4 py-2.5 text-sm font-medium text-white hover:bg-[var(--accent-hover)] active:bg-[var(--accent-active)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          data-testid="auth-submit"
        >
          {{
            busy
              ? mode === "register"
                ? t("auth.signingUp")
                : t("auth.signingIn")
              : mode === "register"
                ? t("auth.signUp")
                : t("auth.signIn")
          }}
        </button>

        <div class="text-sm text-[var(--text-tertiary)] text-center">
          <span v-if="mode === 'login'">{{ t("auth.noAccount") }}</span>
          <span v-else>{{ t("auth.haveAccount") }}</span>
          <button
            type="button"
            class="ml-1 text-[var(--accent)] hover:underline"
            @click="toggleMode"
            data-testid="auth-toggle"
          >
            {{ mode === "login" ? t("auth.signUp") : t("auth.signIn") }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
