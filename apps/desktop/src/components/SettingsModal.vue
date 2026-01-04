<script setup lang="ts">
import type { Settings } from "../types";

type Translator = (key: string) => string;

defineProps<{
  open: boolean;
  settings: Settings | null;
  rememberEnabled: boolean;
  error: string;
  locale: string;
  t: Translator;
  updateSettings: (patch: Partial<Settings>) => void;
}>();

const emit = defineEmits<{
  "update:open": [boolean];
}>();
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 flex items-start justify-center bg-black/40 dark:bg-black/60 pt-16 backdrop-blur-xl"
    @click.self="emit('update:open', false)"
  >
    <div class="w-full max-w-xl rounded-xl bg-[var(--bg-secondary)] shadow-2xl overflow-hidden">
      <div class="flex items-center justify-between px-6 py-4 border-b border-[var(--border-color)]">
        <h3 class="text-lg font-semibold">
          {{ t("settings.title") }}
        </h3>
        <button
          type="button"
          class="rounded-lg p-1.5 text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-active)]"
          @click="emit('update:open', false)"
        >
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
      <div class="max-h-[70vh] overflow-auto p-6 space-y-6 text-sm" v-if="settings">
        <div>
          <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
            {{ t("settings.autolock") }}
          </div>
          <div class="space-y-3">
            <label class="flex items-center justify-between gap-4">
              <span>{{ t("settings.autolockAfter") }}</span>
              <select
                class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                :value="settings.auto_lock_minutes"
                @change="
                  updateSettings({
                    auto_lock_minutes: Number(
                      ($event.target as HTMLSelectElement).value,
                    ),
                  })
                "
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
                @change="
                  updateSettings({
                    lock_on_hidden: $event.target.checked,
                  })
                "
              />
              <span>{{ t("settings.lockOnHidden") }}</span>
            </label>
            <label class="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                class="rounded"
                :checked="settings.lock_on_focus_loss"
                @change="
                  updateSettings({
                    lock_on_focus_loss: $event.target.checked,
                  })
                "
              />
              <span>{{ t("settings.lockOnFocusLoss") }}</span>
            </label>
          </div>
        </div>

        <div>
          <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
            {{ t("settings.clipboard") }}
          </div>
          <div class="space-y-3">
            <label class="flex items-center justify-between gap-4">
              <span>{{ t("settings.clipboardAfter") }}</span>
              <select
                class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                :value="settings.clipboard_clear_seconds"
                @change="
                  updateSettings({
                    clipboard_clear_seconds: Number(
                      ($event.target as HTMLSelectElement).value,
                    ),
                  })
                "
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
                @change="
                  updateSettings({
                    clipboard_clear_on_lock: $event.target.checked,
                  })
                "
              />
              <span>{{ t("settings.clipboardOnLock") }}</span>
            </label>
            <label class="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                class="rounded"
                :checked="settings.clipboard_clear_on_exit"
                @change="
                  updateSettings({
                    clipboard_clear_on_exit: $event.target.checked,
                  })
                "
              />
              <span>{{ t("settings.clipboardOnExit") }}</span>
            </label>
            <label class="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                class="rounded"
                :checked="settings.clipboard_clear_if_unchanged"
                @change="
                  updateSettings({
                    clipboard_clear_if_unchanged: $event.target.checked,
                  })
                "
              />
              <span>{{ t("settings.clipboardIfUnchanged") }}</span>
            </label>
          </div>
        </div>

        <div>
          <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
            {{ t("settings.reveal") }}
          </div>
          <div class="space-y-3">
            <label class="flex items-center justify-between gap-4">
              <span>{{ t("settings.revealAfter") }}</span>
              <select
                class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
                :value="settings.auto_hide_reveal_seconds"
                @change="
                  updateSettings({
                    auto_hide_reveal_seconds: Number(
                      ($event.target as HTMLSelectElement).value,
                    ),
                  })
                "
              >
                <option :value="0">{{ t("time.never") }}</option>
                <option :value="10">10 {{ t("time.seconds") }}</option>
                <option :value="30">30 {{ t("time.seconds") }}</option>
                <option :value="60">60 {{ t("time.seconds") }}</option>
              </select>
            </label>
          </div>
        </div>

        <div>
          <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
            {{ t("settings.keystore") }}
          </div>
          <div class="space-y-3">
            <label class="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                class="rounded"
                :checked="settings.remember_unlock"
                @change="
                  updateSettings({
                    remember_unlock: $event.target.checked,
                    auto_unlock: false,
                  })
                "
              />
              <span>{{ t("unlock.remember") }}</span>
            </label>
            <label class="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
                :checked="settings.auto_unlock"
                :disabled="!rememberEnabled"
                @change="updateSettings({ auto_unlock: $event.target.checked })"
              />
              <span>{{ t("unlock.autoUnlock") }}</span>
            </label>
            <label class="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                class="rounded disabled:opacity-60 disabled:cursor-not-allowed"
                :checked="settings.require_os_auth"
                :disabled="!rememberEnabled"
                @change="
                  updateSettings({ require_os_auth: $event.target.checked })
                "
              />
              <span>{{ t("settings.requireOsAuth") }}</span>
            </label>
            <button
              type="button"
              class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              @click="
                updateSettings({
                  remember_unlock: false,
                  auto_unlock: false,
                })
              "
            >
              {{ t("settings.forgetDevice") }}
            </button>
            <p v-if="error" class="mt-2 text-xs text-category-security">
              {{ error }}
            </p>
          </div>
        </div>

        <div>
          <div class="text-xs font-medium text-[var(--text-secondary)] mb-3">
            {{ t("settings.language") }}
          </div>
          <div>
            <select
              class="rounded-lg bg-[var(--bg-tertiary)] px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
              :value="settings.language || locale"
              @change="
                updateSettings({
                  language: ($event.target as HTMLSelectElement).value,
                })
              "
            >
              <option value="en">English</option>
              <option value="ru">Русский</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
