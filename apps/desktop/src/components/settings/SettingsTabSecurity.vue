<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import type { KeystoreStatus, Settings } from "../../types";
import { useHardwareKeys } from "../../composables/useHardwareKeys";

type Translator = (key: string) => string;

const props = defineProps<{
  settings: Settings | null;
  rememberEnabled: boolean;
  error: string;
  t: Translator;
  updateSettings: (patch: Partial<Settings>) => void;
  keystoreStatus: KeystoreStatus | null;
  onTestBiometrics: () => void;
  onRebindBiometrics: () => void;
}>();

const keystoreSupported = computed(() => props.keystoreStatus?.supported === true);
const rememberUnlockDisabled = computed(
  () => !keystoreSupported.value && !props.settings?.remember_unlock,
);
const autoUnlockDisabled = computed(
  () => !props.rememberEnabled || (!keystoreSupported.value && !props.settings?.auto_unlock),
);
const requireOsAuthDisabled = computed(
  () => !props.rememberEnabled || (!keystoreSupported.value && !props.settings?.require_os_auth),
);

const hardwareKeys = useHardwareKeys();
const hardwareSupported = ref(false);
const enrolling = ref(false);
/** Shown once, right after the first key: nobody enrols a backup otherwise. */
const offerBackupKey = ref(false);

onMounted(async () => {
  hardwareSupported.value = await hardwareKeys.supported();
});

const enrolledKeys = computed(() => props.settings?.hardware_keys ?? []);
const usingHardwareKey = computed(() => props.settings?.unlock_source === "hardware_key");

const enrollKey = async () => {
  enrolling.value = true;
  const wasEmpty = enrolledKeys.value.length === 0;
  const entry = await hardwareKeys.enroll("");
  enrolling.value = false;
  if (!entry) {
    return;
  }
  // The source only flips once there is something behind it.
  props.updateSettings({ remember_unlock: true, unlock_source: "hardware_key" });
  offerBackupKey.value = wasEmpty;
};

const removeKey = async (credentialId: string) => {
  await hardwareKeys.remove(credentialId);
  props.updateSettings({});
};

const handleSourceChange = (source: "keystore" | "hardware_key") => {
  if (source === "hardware_key" && enrolledKeys.value.length === 0) {
    void enrollKey();
    return;
  }
  props.updateSettings({ unlock_source: source });
};

const handleRememberUnlockChange = (event: Event) => {
  const checked = (event.target as HTMLInputElement).checked;
  if (!keystoreSupported.value && checked) {
    return;
  }
  props.updateSettings({ remember_unlock: checked, auto_unlock: false });
};
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
      <p
        v-if="!keystoreSupported"
        class="mb-3 text-xs text-[var(--text-tertiary)]"
      >
        {{ t("settings.biometricsUnsupported") }}
      </p>
      <div
        class="space-y-3"
        :class="!keystoreSupported ? 'opacity-60 pointer-events-none' : ''"
      >
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
            :checked="settings.remember_unlock"
            :disabled="rememberUnlockDisabled"
            @change="handleRememberUnlockChange"
          />
          <span>{{ t("unlock.remember") }}</span>
        </label>

        <div v-if="hardwareSupported && rememberEnabled" class="ml-6 space-y-2">
          <label class="flex items-center gap-2 text-[var(--text-secondary)]">
            <input
              type="radio"
              :checked="!usingHardwareKey"
              @change="handleSourceChange('keystore')"
            />
            <span>{{ t("settings.unlockSourceKeystore") }}</span>
          </label>
          <label class="flex items-center gap-2 text-[var(--text-secondary)]">
            <input
              type="radio"
              :checked="usingHardwareKey"
              @change="handleSourceChange('hardware_key')"
            />
            <span>{{ t("settings.unlockSourceHardwareKey") }}</span>
          </label>

          <div v-if="usingHardwareKey" class="ml-6 space-y-2">
            <div
              v-for="key in enrolledKeys"
              :key="key.credential_id"
              class="flex items-center justify-between gap-3 text-xs text-[var(--text-secondary)]"
            >
              <span>{{ key.label }}</span>
              <button
                type="button"
                class="text-category-security hover:underline"
                @click="removeKey(key.credential_id)"
              >
                {{ t("common.delete") }}
              </button>
            </div>
            <button
              type="button"
              class="rounded-lg border border-[var(--border-color)] px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors disabled:opacity-60"
              :disabled="enrolling"
              @click="enrollKey"
            >
              {{ enrolling ? t("settings.hardwareKeyTouch") : t("settings.hardwareKeyEnrol") }}
            </button>
            <p v-if="offerBackupKey" class="text-xs text-[var(--text-tertiary)]">
              {{ t("settings.hardwareKeyBackupHint") }}
            </p>
            <p v-if="hardwareKeys.error.value" class="text-xs text-category-security">
              {{ t(`errors.${hardwareKeys.error.value}`) }}
            </p>
          </div>
        </div>
        <label class="flex items-center gap-2 text-[var(--text-secondary)]">
          <input
            type="checkbox"
            class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
            :checked="settings.auto_unlock"
            :disabled="autoUnlockDisabled"
            @change="updateSettings({ auto_unlock: ($event.target as HTMLInputElement).checked })"
          />
          <span>{{ t("unlock.autoUnlock") }}</span>
        </label>
        <!-- A touch already proves presence; a biometric prompt on top is
             ceremony, so the toggle is hidden while a key is the source. -->
        <label
          v-if="!usingHardwareKey"
          class="flex items-center gap-2 text-[var(--text-secondary)]"
        >
          <input
            type="checkbox"
            class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
            :checked="settings.require_os_auth"
            :disabled="requireOsAuthDisabled"
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
          :disabled="!keystoreSupported"
          @click="updateSettings({ remember_unlock: false, auto_unlock: false })"
        >
          {{ t("settings.forgetDevice") }}
        </button>
        <p v-if="error" class="mt-2 text-xs text-category-security">{{ error }}</p>
      </div>
    </div>
  </div>
</template>
