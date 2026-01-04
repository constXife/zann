<script setup lang="ts">
import type { KeystoreStatus, Settings } from "../../types";

type Translator = (key: string) => string;

defineProps<{
  settings: Settings | null;
  rememberEnabled: boolean;
  error: string;
  t: Translator;
  updateSettings: (patch: Partial<Settings>) => void;
  keystoreStatus: KeystoreStatus | null;
  onTestBiometrics: () => void;
  onRebindBiometrics: () => void;
}>();
</script>

<template>
  <div class="space-y-6 text-sm" v-if="settings">
    <!-- Auto-lock -->
    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.autolock") }}
      </h4>
      <div class="space-y-3">
        <label class="flex items-center justify-between gap-4">
          <span>{{ t("settings.autolockAfter") }}</span>
          <select
            class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            :value="settings.auto_lock_minutes"
            @change="updateSettings({ auto_lock_minutes: Number(($event.target as HTMLSelectElement).value) })"
          >
            <option :value="0">{{ t("time.never") }}</option>
            <option :value="1">1 {{ t("time.minutes") }}</option>
            <option :value="5">5 {{ t("time.minutes") }}</option>
            <option :value="10">10 {{ t("time.minutes") }}</option>
            <option :value="30">30 {{ t("time.minutes") }}</option>
            <option :value="60">{{ t("time.hour") }}</option>
          </select>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded"
            :checked="settings.lock_on_hidden"
            @change="updateSettings({ lock_on_hidden: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("settings.lockOnHidden") }}</span>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded"
            :checked="settings.lock_on_focus_loss"
            @change="updateSettings({ lock_on_focus_loss: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("settings.lockOnFocusLoss") }}</span>
        </label>
      </div>
    </div>

    <!-- Clipboard -->
    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.clipboard") }}
      </h4>
      <div class="space-y-3">
        <label class="flex items-center justify-between gap-4">
          <span>{{ t("settings.clipboardAfter") }}</span>
          <select
            class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            :value="settings.clipboard_clear_seconds"
            @change="updateSettings({ clipboard_clear_seconds: Number(($event.target as HTMLSelectElement).value) })"
          >
            <option :value="0">{{ t("time.never") }}</option>
            <option :value="15">15 {{ t("time.seconds") }}</option>
            <option :value="30">30 {{ t("time.seconds") }}</option>
            <option :value="60">60 {{ t("time.seconds") }}</option>
            <option :value="120">2 {{ t("time.minutes") }}</option>
            <option :value="300">5 {{ t("time.minutes") }}</option>
          </select>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded"
            :checked="settings.clipboard_clear_on_lock"
            @change="updateSettings({ clipboard_clear_on_lock: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("settings.clipboardOnLock") }}</span>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded"
            :checked="settings.clipboard_clear_on_exit"
            @change="updateSettings({ clipboard_clear_on_exit: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("settings.clipboardOnExit") }}</span>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded"
            :checked="settings.clipboard_clear_if_unchanged"
            @change="updateSettings({ clipboard_clear_if_unchanged: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("settings.clipboardIfUnchanged") }}</span>
        </label>
      </div>
    </div>

    <!-- Reveal -->
    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.reveal") }}
      </h4>
      <div class="space-y-3">
        <label class="flex items-center justify-between gap-4">
          <span>{{ t("settings.revealAfter") }}</span>
          <select
            class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            :value="settings.auto_hide_reveal_seconds"
            @change="updateSettings({ auto_hide_reveal_seconds: Number(($event.target as HTMLSelectElement).value) })"
          >
            <option :value="0">{{ t("time.never") }}</option>
            <option :value="10">10 {{ t("time.seconds") }}</option>
            <option :value="30">30 {{ t("time.seconds") }}</option>
            <option :value="60">60 {{ t("time.seconds") }}</option>
          </select>
        </label>
      </div>
    </div>

    <!-- Keystore / Touch ID -->
    <div>
      <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-4">
        {{ t("settings.keystore") }}
      </h4>
      <div class="space-y-3">
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded"
            :checked="settings.remember_unlock"
            @change="updateSettings({ remember_unlock: ($event.target as HTMLInputElement).checked, auto_unlock: false })"
          />
          <span>{{ t("unlock.remember") }}</span>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
            :checked="settings.auto_unlock"
            :disabled="!rememberEnabled"
            @change="updateSettings({ auto_unlock: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("unlock.autoUnlock") }}</span>
        </label>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
            :checked="settings.require_os_auth"
            :disabled="!rememberEnabled"
            @change="updateSettings({ require_os_auth: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("settings.requireOsAuth") }}</span>
        </label>
        <button
          v-if="keystoreStatus?.supported && keystoreStatus?.biometrics_available"
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="onTestBiometrics"
        >
          {{ t("settings.testTouchId") }}
        </button>
        <button
          v-if="rememberEnabled && keystoreStatus?.supported && keystoreStatus?.biometrics_available"
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="onRebindBiometrics"
        >
          {{ t("settings.rebindTouchId") }}
        </button>
        <button
          type="button"
          class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="updateSettings({ remember_unlock: false, auto_unlock: false })"
        >
          {{ t("settings.forgetDevice") }}
        </button>
        <p v-if="error" class="mt-2 text-xs text-category-security">{{ error }}</p>
      </div>
    </div>
  </div>
</template>
