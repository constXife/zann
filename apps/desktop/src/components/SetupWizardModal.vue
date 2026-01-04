<script setup lang="ts">
import { computed } from "vue";

type Translator = (key: string, params?: Record<string, unknown>) => string;

const setupStep = defineModel<"welcome" | "password" | "connect">("step", { required: true });
const setupFlow = defineModel<"local" | "remote">("flow", { required: true });
const setupPassword = defineModel<string>("setupPassword", { required: true });
const setupConfirm = defineModel<string>("setupConfirm", { required: true });
const connectServerUrl = defineModel<string>("connectServerUrl", { required: true });

const props = defineProps<{
  open: boolean;
  logoUrl: string;
  setupError: string;
  setupBusy: boolean;
  connectVerification: string;
  connectStatus: string;
  connectError: string;
  connectOldFp: string;
  connectNewFp: string;
  connectBusy: boolean;
  connectLoginId: string;
  t: Translator;
  normalizeServerUrl: (value: string) => string;
  startLocalSetup: () => void;
  startConnect: () => void;
  backToWelcome: () => void;
  createMasterPassword: () => void;
  beginServerConnect: () => void;
  trustFingerprint: () => void;
  openExternal: (url: string) => void;
  copyToClipboard: (value: string) => void;
}>();

const prefillServerUrl = () => {
  if (!connectServerUrl.value) {
    connectServerUrl.value = "https://";
  }
};

const selectAll = (event: Event) => {
  const target = event.target as HTMLInputElement | null;
  if (!target) {
    return;
  }
  target.focus();
  target.select();
};

const onUrlBlur = () => {
  connectServerUrl.value = props.normalizeServerUrl(connectServerUrl.value);
};

// Progress indicator
const totalSteps = computed(() => (setupFlow.value === "remote" ? 2 : 1));

const currentStep = computed(() => {
  if (setupStep.value === "welcome") return 0;
  if (setupStep.value === "connect") return 1;
  if (setupStep.value === "password") return totalSteps.value;
  return 0;
});

const stepLabel = computed(() => {
  if (setupStep.value === "connect") return props.t("wizard.stepConnect");
  if (setupStep.value === "password") return props.t("wizard.stepSecure");
  return "";
});

// Password strength indicator
type PasswordStrength = "weak" | "medium" | "strong";

const passwordStrength = computed((): PasswordStrength => {
  const pwd = setupPassword.value;
  if (!pwd || pwd.length < 8) return "weak";

  let score = 0;
  if (pwd.length >= 12) score++;
  if (pwd.length >= 16) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^a-zA-Z0-9]/.test(pwd)) score++;

  if (score <= 2) return "weak";
  if (score <= 4) return "medium";
  return "strong";
});

const strengthBarClass = computed(() => ({
  "bg-red-500": passwordStrength.value === "weak",
  "bg-amber-500": passwordStrength.value === "medium",
  "bg-green-500": passwordStrength.value === "strong",
}));

const strengthTextClass = computed(() => ({
  "text-red-500": passwordStrength.value === "weak",
  "text-amber-500": passwordStrength.value === "medium",
  "text-green-500": passwordStrength.value === "strong",
}));

const strengthBarWidth = computed(() => {
  if (passwordStrength.value === "weak") return "33%";
  if (passwordStrength.value === "medium") return "66%";
  return "100%";
});
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-center justify-center bg-black/40 dark:bg-black/60 backdrop-blur-xl"
  >
    <div class="w-full max-w-md rounded-2xl bg-[var(--bg-secondary)] p-6 shadow-2xl">
      <div class="h-5 cursor-grab" data-tauri-drag-region></div>
      <div v-if="setupStep === 'welcome'" class="space-y-6 text-center">
        <img :src="logoUrl" alt="Zann" class="mx-auto h-16 w-16 rounded-2xl" />
        <div>
          <h2 class="text-xl font-semibold">{{ t("wizard.title") }}</h2>
          <p class="mt-1 text-sm text-[var(--text-secondary)]">
            {{ t("wizard.subtitle") }}
          </p>
        </div>
        <div class="space-y-3 text-sm">
          <button
            type="button"
            class="w-full rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-4 py-3 font-semibold text-white transition-colors"
            @click="startConnect"
          >
            {{ t("wizard.connect") }}
          </button>
          <div>
            <button
              type="button"
              class="w-full rounded-lg border border-[var(--border-color)] px-4 py-3 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
              @click="startLocalSetup"
            >
              {{ t("wizard.useOnThisDevice") }}
            </button>
            <p class="mt-2 text-xs text-[var(--text-tertiary)] text-center">
              {{ t("wizard.connectLater") }}
            </p>
          </div>
        </div>
      </div>

      <div v-else-if="setupStep === 'password'" class="space-y-4">
        <div class="flex items-center justify-between" data-tauri-drag-region>
          <div>
            <p class="text-xs text-[var(--text-tertiary)]">
              {{ t("wizard.stepOf", { current: currentStep, total: totalSteps }) }} — {{ stepLabel }}
            </p>
            <h2 class="text-lg font-semibold">{{ t("wizard.passwordTitle") }}</h2>
          </div>
          <button
            type="button"
            class="rounded-lg px-2 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-60 disabled:cursor-not-allowed"
            @click="backToWelcome"
            :disabled="connectBusy"
            data-tauri-drag-region="false"
          >
            {{ t("wizard.back") }}
          </button>
        </div>
        <p class="text-sm text-[var(--text-secondary)]">
          {{ t("wizard.passwordSubtitle") }}
        </p>
        <input
          v-model="setupPassword"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] px-4 py-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
          type="password"
          :placeholder="t('wizard.passwordPlaceholder')"
          autocomplete="new-password"
        />
        <div v-if="setupPassword" class="flex items-center gap-2 -mt-2">
          <div class="flex-1 h-1.5 bg-[var(--bg-hover)] rounded-full overflow-hidden">
            <div
              class="h-full rounded-full transition-all duration-300"
              :class="strengthBarClass"
              :style="{ width: strengthBarWidth }"
            />
          </div>
          <span class="text-xs font-medium" :class="strengthTextClass">
            {{ t(`wizard.strength.${passwordStrength}`) }}
          </span>
        </div>
        <input
          v-model="setupConfirm"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] px-4 py-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
          type="password"
          :placeholder="t('wizard.passwordConfirmPlaceholder')"
          autocomplete="new-password"
        />
        <button
          type="button"
          class="w-full rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-4 py-3 text-sm font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
          :disabled="setupBusy"
          @click="createMasterPassword"
        >
          {{ t("wizard.create") }}
        </button>
        <p v-if="setupError" class="text-xs text-category-security">
          {{ setupError }}
        </p>
      </div>

      <div v-else-if="setupStep === 'connect'" class="space-y-4">
        <div class="flex items-center justify-between" data-tauri-drag-region>
          <div>
            <p class="text-xs text-[var(--text-tertiary)]">
              {{ t("wizard.stepOf", { current: currentStep, total: totalSteps }) }} — {{ stepLabel }}
            </p>
            <h2 class="text-lg font-semibold">{{ t("wizard.connectTitle") }}</h2>
          </div>
          <button
            type="button"
            class="rounded-lg px-2 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-60 disabled:cursor-not-allowed"
            @click="backToWelcome"
            :disabled="connectBusy"
            data-tauri-drag-region="false"
          >
            {{ t("wizard.back") }}
          </button>
        </div>
        <p class="text-sm text-[var(--text-secondary)]">
          {{ t("wizard.connectSubtitle") }}
        </p>
        <input
          v-model="connectServerUrl"
          class="w-full rounded-lg bg-[var(--bg-tertiary)] px-4 py-3 text-sm placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
          type="text"
          :placeholder="t('wizard.connectPlaceholder')"
          autocomplete="url"
          autocapitalize="off"
          autocorrect="off"
          spellcheck="false"
          inputmode="url"
          :disabled="connectBusy"
          @blur="onUrlBlur"
          @focus="prefillServerUrl"
        />
        <button
          type="button"
          class="w-full rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-4 py-3 text-sm font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
          :disabled="connectBusy"
          @click="beginServerConnect"
        >
          {{ t("wizard.signIn") }}
        </button>
        <div
          v-if="connectStatus === 'waiting'"
          class="rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] p-3 text-sm space-y-2"
        >
          <div class="flex items-center gap-2 font-semibold text-[var(--text-primary)]">
            <svg class="h-4 w-4 animate-spin text-[var(--accent)]" viewBox="0 0 24 24" fill="none">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
            </svg>
            <span>{{ t("wizard.waitingApproval") }}</span>
          </div>
          <div class="flex items-center justify-between">
            <div class="text-xs text-[var(--text-secondary)]">
              {{ t("wizard.approvalHint") }}
            </div>
            <div class="flex items-center gap-3">
              <button
                type="button"
                class="rounded-md p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-60 disabled:cursor-not-allowed"
                :title="t('wizard.openBrowser')"
                @click="openExternal(connectVerification)"
                :disabled="!connectVerification"
              >
                <font-awesome-icon icon="arrow-up-right-from-square" class="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                class="rounded-md p-1 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-60 disabled:cursor-not-allowed"
                :title="t('common.copy')"
                @click="copyToClipboard(connectVerification)"
                :disabled="!connectVerification"
              >
                <font-awesome-icon icon="copy" class="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <input
            :value="connectVerification"
            class="w-full rounded-md bg-[var(--bg-secondary)] px-2 py-1 text-xs text-[var(--text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            type="text"
            readonly
            @click="selectAll"
          />
          <p
            v-if="connectLoginId"
            class="text-[10px] text-[var(--text-tertiary)]"
          >
            Login id: {{ connectLoginId }}
          </p>
        </div>
        <div
          v-else-if="connectStatus === 'fingerprint'"
          class="rounded-lg border border-category-security/40 bg-category-security/10 p-3 text-sm space-y-2"
        >
          <div class="font-semibold text-category-security">
            {{ t("wizard.fingerprintChanged") }}
          </div>
          <div class="text-xs text-[var(--text-secondary)] break-words">
            {{ t("wizard.oldFingerprint") }}: <span class="font-mono">{{ connectOldFp || t("wizard.unknown") }}</span>
          </div>
          <div class="text-xs text-[var(--text-secondary)] break-words">
            {{ t("wizard.newFingerprint") }}: <span class="font-mono">{{ connectNewFp || t("wizard.unknown") }}</span>
          </div>
          <div class="flex gap-2">
              <button
                type="button"
                class="flex-1 rounded-lg border border-[var(--border-color)] px-3 py-2 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-60 disabled:cursor-not-allowed"
                @click="backToWelcome"
                :disabled="connectBusy"
              >
              {{ t("common.close") }}
            </button>
              <button
                type="button"
                class="flex-1 rounded-lg bg-gray-800 dark:bg-gray-600 hover:bg-gray-700 dark:hover:bg-gray-500 px-3 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                @click="trustFingerprint"
                :disabled="connectBusy"
              >
              {{ t("wizard.trustFingerprint") }}
            </button>
          </div>
        </div>
        <div v-else-if="connectBusy" class="rounded-lg border border-[var(--border-color)] bg-[var(--bg-tertiary)] p-3 text-sm">
          <div class="flex items-center gap-2 text-[var(--text-primary)]">
            <svg class="h-4 w-4 animate-spin text-[var(--accent)]" viewBox="0 0 24 24" fill="none">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"></path>
            </svg>
            <span>{{ t("wizard.processing") }}</span>
          </div>
        </div>
        <p v-if="connectStatus === 'success'" class="text-xs text-[var(--text-secondary)]">
          {{ t("wizard.connected") }}
        </p>
        <p v-if="connectError" class="text-xs text-category-security">
          {{ connectError }}
        </p>
      </div>
    </div>
  </div>
</template>
