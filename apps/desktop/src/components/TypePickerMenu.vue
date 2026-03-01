<script setup lang="ts">
import CategoryIcon from "./CategoryIcon.vue";

const props = defineProps<{
  open: boolean;
  align?: "left" | "right";
  menuWidthClass?: string;
  title?: string;
  subtitle?: string;
  showGroupLabels?: boolean;
  typeOptions: string[];
  typeGroups: { id: string; label: string; types: string[] }[];
  typeMeta: Record<string, { icon: string }>;
  getTypeLabel: (typeId: string) => string;
  showAllTypesOption?: boolean;
  showAllTypesLabel?: string;
  onShowAllTypes?: () => void;
  onSelectType: (typeId: string) => void;
  onClose: () => void;
}>();

const menuAlignClass = props.align === "right" ? "right-0" : "left-0";
const menuWidth = props.menuWidthClass ?? "w-44";
</script>

<template>
  <div
    v-if="props.open"
    class="absolute top-full mt-2 rounded-lg border border-[var(--border-color)] bg-[var(--bg-secondary)] shadow-xl z-50"
    :class="[menuAlignClass, menuWidth]"
  >
    <div v-if="props.title" class="px-3 pt-2 text-xs font-semibold text-[var(--text-primary)]">
      {{ props.title }}
    </div>
    <div v-if="props.subtitle" class="px-3 pb-1 text-[10px] text-[var(--text-tertiary)]">
      {{ props.subtitle }}
    </div>
    <template
      v-for="group in (props.typeGroups.length
        ? props.typeGroups
        : [{ id: 'default', label: 'Types', types: props.typeOptions.length ? props.typeOptions : ['login'] }])"
      :key="group.id"
    >
      <div
        v-if="props.showGroupLabels !== false"
        class="px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--text-tertiary)]"
      >
        {{ group.label }}
      </div>
      <button
        v-for="typeId in group.types"
        :key="typeId"
        type="button"
        class="w-full flex items-center gap-2 px-3 py-2 text-sm text-left hover:bg-[var(--bg-hover)] transition-colors"
        data-tauri-drag-region="false"
        @click="props.onSelectType(typeId)"
      >
        <CategoryIcon
          :icon="props.typeMeta[typeId]?.icon ?? 'key'"
          :class="['h-4 w-4', `text-category-${typeId}`]"
        />
        <span>{{ props.getTypeLabel(typeId) }}</span>
      </button>
    </template>
    <div v-if="props.showAllTypesOption" class="my-1 border-t border-[var(--border-color)]"></div>
    <button
      v-if="props.showAllTypesOption"
      type="button"
      class="w-full flex items-center gap-2 px-3 py-2 text-sm text-left text-[var(--accent)] hover:bg-[var(--bg-hover)] transition-colors"
      data-tauri-drag-region="false"
      @click="props.onShowAllTypes && props.onShowAllTypes()"
    >
      {{ props.showAllTypesLabel ?? "Show all types" }}
    </button>
  </div>
  <div
    v-if="props.open"
    class="fixed inset-0 z-40"
    @click="props.onClose"
  ></div>
</template>
