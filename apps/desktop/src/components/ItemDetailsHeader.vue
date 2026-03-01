<script setup lang="ts">
import { ref, computed, onBeforeUnmount } from "vue";
import { useI18n } from "vue-i18n";
import Button from "./ui/Button.vue";

const { t } = useI18n();

type Breadcrumb = { path: string; label: string };

const props = defineProps<{
  vaultName: string;
  breadcrumbs: Breadcrumb[];
  onSelectBreadcrumb: (crumb: Breadcrumb) => void;
  name: string;
  typeId: string;
  typeLabel: string;
  updatedAtLabel: string;
  isSharedVault: boolean;
  fileStatusLabel?: string | null;
  timeTravelActive: boolean;
  historyLoading: boolean;
  historyError: string;
  openTimeTravel: () => void;
  closeTimeTravel: () => void;
  isDeleted: boolean;
  isConflict: boolean;
  restoreItem: () => void;
  resolveConflict: () => void;
  openEditItem: () => void;
  deleteItem: () => void;
  purgeItem: () => void;
  copyEnv: (options?: { includeProtected?: boolean }) => void;
  copyJson: (options?: { includeProtected?: boolean }) => void;
  copyRaw: () => void;
}>();

const actionMenuOpen = ref(false);
let closeTimer: number | null = null;

const initial = computed(() => props.name?.charAt(0)?.toUpperCase() ?? "");

const closeActionMenu = () => {
  actionMenuOpen.value = false;
};

const toggleActionMenu = () => {
  actionMenuOpen.value = !actionMenuOpen.value;
};

const handleHeaderCopy = (kind: "env" | "json" | "raw") => {
  if (kind === "env") props.copyEnv();
  if (kind === "json") props.copyJson();
  if (kind === "raw") props.copyRaw();
  actionMenuOpen.value = false;
};

onBeforeUnmount(() => {
  if (closeTimer) {
    window.clearTimeout(closeTimer);
    closeTimer = null;
  }
});
</script>

<template>
  <div class="space-y-2">
    <!-- Row 1: Avatar + Name + Badges + Actions -->
    <div class="flex items-center gap-3">
      <div
        class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-white text-sm font-medium"
        :class="`bg-category-${props.typeId}`"
      >
        {{ initial }}
      </div>
      <div class="flex-1 min-w-0 flex items-center gap-2">
        <div class="text-xl font-semibold leading-tight text-[var(--text-primary)] truncate">
          {{ props.name }}
        </div>
        <span
          v-if="props.isSharedVault"
          class="shrink-0 rounded-full bg-category-security/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-category-security"
        >
          {{ t("nav.shared") }}
        </span>
        <span
          v-if="props.fileStatusLabel"
          class="shrink-0 rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-400"
        >
          {{ props.fileStatusLabel }}
        </span>
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        <Button
          variant="secondary"
          size="xs"
          :class="props.timeTravelActive ? 'bg-amber-500/20 text-amber-400 ring-1 ring-amber-500/50' : ''"
          :disabled="props.historyLoading"
          data-testid="history-toggle"
          @click="props.timeTravelActive ? props.closeTimeTravel() : props.openTimeTravel()"
        >
          {{ t("items.historyOpen") }}
        </Button>
        <Button
          v-if="props.isDeleted"
          size="xs"
          @click="props.restoreItem"
        >
          {{ t("items.restore") }}
        </Button>
        <Button
          v-else-if="props.isConflict"
          variant="warning"
          size="xs"
          @click="props.resolveConflict"
        >
          {{ t("items.resolveConflict") }}
        </Button>
        <Button
          v-else
          size="xs"
          @click="props.openEditItem"
        >
          {{ t("common.edit") }}
        </Button>
        <div class="relative">
          <Button
            variant="ghost"
            size="icon-xs"
            data-testid="item-action-menu"
            @click="toggleActionMenu"
          >
            ⋯
          </Button>
          <div
            v-if="actionMenuOpen"
            class="absolute right-0 mt-2 w-44 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-50"
          >
            <button
              type="button"
              class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
              @click="handleHeaderCopy('env')"
            >
              {{ t("items.copyEnv") }}
            </button>
            <button
              type="button"
              class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
              @click="handleHeaderCopy('json')"
            >
              {{ t("items.copyJson") }}
            </button>
            <button
              type="button"
              class="w-full px-3 py-2 text-xs text-left hover:bg-[var(--bg-hover)] transition-colors"
              @click="handleHeaderCopy('raw')"
            >
              {{ t("items.copyRaw") }}
            </button>
            <div class="my-1 border-t border-[var(--border-color)]"></div>
            <button
              v-if="!props.isDeleted"
              type="button"
              class="w-full px-3 py-2 text-xs text-left text-category-security hover:bg-[var(--bg-hover)] transition-colors"
              @click="props.deleteItem(); closeActionMenu()"
            >
              {{ t("items.moveToTrash") }}
            </button>
            <button
              v-if="props.isDeleted"
              type="button"
              class="w-full px-3 py-2 text-xs text-left text-category-security hover:bg-[var(--bg-hover)] transition-colors"
              @click="props.purgeItem(); closeActionMenu()"
            >
              {{ t("items.deleteForever") }}
            </button>
          </div>
          <div
            v-if="actionMenuOpen"
            class="fixed inset-0 z-40"
            @click="closeActionMenu"
          ></div>
        </div>
      </div>
    </div>

    <!-- Row 2: Location + Updated -->
    <div class="flex items-center justify-between pl-[52px]">
      <div class="flex items-center gap-1.5 text-xs text-[var(--text-tertiary)]">
        <span>🔒 {{ props.vaultName }}</span>
        <template v-for="crumb in props.breadcrumbs" :key="crumb.path">
          <span>/</span>
          <Button
            variant="link"
            size="xs"
            class="px-0 h-auto text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            @click="props.onSelectBreadcrumb(crumb)"
          >
            {{ crumb.label }}
          </Button>
        </template>
      </div>
      <div class="text-xs text-[var(--text-tertiary)]">
        {{ props.updatedAtLabel }}
      </div>
    </div>
  </div>
</template>
