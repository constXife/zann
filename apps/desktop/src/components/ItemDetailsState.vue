<script setup lang="ts">
import { useI18n } from "vue-i18n";

const { t } = useI18n();

type Variant = "system" | "list-error" | "empty" | "no-selection";
type SystemState = "personalLocked" | "sessionExpired" | "syncError" | "offline";

const props = defineProps<{
  variant: Variant;
  contextLabel: string;
  listError?: string;
  filteredItemsCount?: number;
  createShortcut?: string;
  searchShortcut?: string;
  openCreateItem?: () => void;
  openPalette?: () => void;
  systemState?: SystemState;
  syncErrorMessage?: string;
  formattedLastSync?: string | null;
  pendingChangesCount?: number;
  onSignIn?: () => void;
  onUnlockPersonal?: () => void;
  onResetPersonal?: () => void;
  retrySync?: () => void;
}>();
</script>

<template>
  <div class="flex h-full items-center justify-center py-8">
    <div
      v-if="props.variant === 'system'"
      class="w-full max-w-xl rounded-2xl border border-[var(--border-color)] bg-[var(--bg-tertiary)] p-6 text-[var(--text-secondary)]"
    >
      <div class="text-xs uppercase tracking-wide text-[var(--text-tertiary)]">
        {{ t("workspace.contextLabel", { label: props.contextLabel }) }}
      </div>
      <div class="mt-2 text-xl font-semibold text-[var(--text-primary)]">
        {{
          props.systemState === "personalLocked"
            ? t("status.personalLocked")
            : props.systemState === "sessionExpired"
              ? t("status.sessionExpired")
              : props.systemState === "syncError"
                ? t("status.syncError")
                : t("status.offline")
        }}
      </div>
      <div
        v-if="props.systemState === 'personalLocked'"
        class="mt-2 text-sm text-[var(--text-secondary)]"
      >
        {{ t("status.personalLockedDesc") }}
      </div>
      <div
        v-else-if="props.systemState === 'sessionExpired'"
        class="mt-2 text-sm text-[var(--text-secondary)]"
      >
        {{ t("status.sessionExpired") }}
      </div>
      <div
        v-else-if="props.systemState === 'syncError'"
        class="mt-2 text-sm text-[var(--text-secondary)] break-words"
      >
        {{ props.syncErrorMessage }}
      </div>
      <div
        v-else
        class="mt-2 text-sm text-[var(--text-secondary)]"
      >
        {{ t("status.offline") }}
      </div>
      <div
        v-if="props.formattedLastSync"
        class="mt-2 text-xs text-[var(--text-tertiary)]"
      >
        {{ t("storage.lastSynced") }}: {{ props.formattedLastSync }}
      </div>
      <div
        v-if="props.pendingChangesCount && props.pendingChangesCount > 0"
        class="mt-1 text-xs text-[var(--text-tertiary)]"
      >
        {{ t("status.pendingChanges", { count: props.pendingChangesCount }) }}
      </div>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          v-if="props.systemState === 'sessionExpired'"
          type="button"
          class="rounded-lg bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-white hover:opacity-90 transition-opacity"
          @click="props.onSignIn && props.onSignIn()"
        >
          {{ t("auth.signIn") }}
        </button>
        <button
          v-if="props.systemState === 'personalLocked'"
          type="button"
          class="rounded-lg bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-white hover:opacity-90 transition-opacity"
          @click="props.onUnlockPersonal && props.onUnlockPersonal()"
        >
          {{ t("status.personalLockedAction") }}
        </button>
        <button
          v-if="props.systemState === 'personalLocked'"
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-3 py-2 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="props.onResetPersonal && props.onResetPersonal()"
        >
          {{ t("status.personalLockedReset") }}
        </button>
        <button
          v-if="props.systemState === 'syncError' || props.systemState === 'offline'"
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-3 py-2 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="props.retrySync && props.retrySync()"
        >
          {{ t("common.retry") }}
        </button>
      </div>
    </div>

    <div
      v-else-if="props.variant === 'list-error'"
      class="w-full max-w-md rounded-2xl border border-red-500/20 bg-red-500/10 p-6 text-sm text-red-700 dark:text-red-300"
    >
      <div class="text-base font-semibold">{{ t("items.listLoadFailed") }}</div>
      <div class="mt-2 text-xs text-red-600/80 dark:text-red-300/80 break-words">
        {{ props.listError }}
      </div>
      <div class="mt-4 flex gap-2">
        <button
          type="button"
          class="rounded-lg bg-red-500/20 px-3 py-2 text-xs font-semibold text-red-700 dark:text-red-300 hover:bg-red-500/30 transition-colors"
          @click="props.openPalette && props.openPalette()"
        >
          {{ t("workspace.openPalette") }}
        </button>
      </div>
    </div>

    <div
      v-else
      class="w-full max-w-xl rounded-2xl border border-dashed border-[var(--border-color)] bg-[var(--bg-tertiary)] p-8 text-[var(--text-secondary)]"
    >
      <div class="text-xs uppercase tracking-wide text-[var(--text-tertiary)]">
        {{ props.contextLabel }}
      </div>
      <div class="mt-2 text-2xl font-semibold text-[var(--text-primary)]">
        {{ props.variant === "empty" ? t("workspace.emptyTitle") : t("workspace.noSelectionTitle") }}
      </div>
      <div class="mt-2 text-sm text-[var(--text-secondary)]">
        {{
          props.variant === "empty"
            ? t("workspace.emptyBody")
            : t("workspace.noSelectionBody")
        }}
      </div>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-lg bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-white hover:opacity-90 transition-opacity"
          @click="props.openCreateItem && props.openCreateItem()"
        >
          {{ t("onboarding.createItem") }}
        </button>
        <button
          type="button"
          class="rounded-lg border border-[var(--border-color)] px-3 py-2 text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] transition-colors"
          @click="props.openPalette && props.openPalette()"
        >
          {{ t("workspace.openPalette") }}
        </button>
      </div>
      <div
        v-if="props.variant === 'no-selection'"
        class="mt-5 flex items-center justify-between rounded-lg bg-[var(--bg-secondary)] px-4 py-3 text-xs text-[var(--text-secondary)]"
      >
        <span>{{ t("workspace.summary", { count: props.filteredItemsCount ?? 0 }) }}</span>
        <span class="text-[11px] text-[var(--text-tertiary)]">
          {{ t("workspace.searchHint", { search: props.searchShortcut ?? "" }) }}
        </span>
      </div>
      <div
        v-else
        class="mt-4 text-[11px] text-[var(--text-tertiary)]"
      >
        {{ t("workspace.hotkeys", { create: props.createShortcut ?? "", search: props.searchShortcut ?? "" }) }}
      </div>
    </div>
  </div>
</template>
