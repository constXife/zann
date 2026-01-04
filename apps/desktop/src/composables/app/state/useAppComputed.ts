import { computed } from "vue";
import type { ComputedRef, Ref } from "vue";
import type { AppStatus, ItemDetail, ItemSummary, Settings, Status } from "../../../types";

type AppComputedOptions = {
  settings: Ref<Settings | null>;
  status: Ref<Status | null>;
  appStatus: Ref<AppStatus | null>;
  setupOpen: Ref<boolean>;
  items: Ref<ItemSummary[]>;
  selectedItemId: Ref<string | null>;
  selectedItem: Ref<ItemDetail | null>;
  detailSections: Ref<{ fields: { kind: string }[] }[]>;
  getSchemaFieldDefs: (typeId: string) => { type: string }[];
};

export function useAppComputed({
  settings,
  status,
  appStatus,
  setupOpen,
  items,
  selectedItemId,
  selectedItem,
  detailSections,
  getSchemaFieldDefs,
}: AppComputedOptions) {
  const rememberEnabled = computed(() => settings.value?.remember_unlock ?? false);
  const unlocked = computed(() => status.value?.unlocked ?? false);
  const initialized = computed(() => appStatus.value?.initialized ?? false);
  const showWizard = computed(() => !!(appStatus.value && !initialized.value));
  const showUnlock = computed(() => !!(appStatus.value && initialized.value && !unlocked.value));
  const showSetupModal = computed(() => showWizard.value || setupOpen.value);
  const showMain = computed(() => appStatus.value && initialized.value && unlocked.value);

  const selectedItemSummary = computed(
    () => items.value.find((item) => item.id === selectedItemId.value) ?? null,
  );
  const selectedItemDeleted = computed(() => !!selectedItemSummary.value?.deleted_at);
  const selectedItemConflict = computed(
    () => selectedItemSummary.value?.sync_status === "conflict",
  );
  const hasPasswordField = computed(() => {
    if (
      detailSections.value.some((section) =>
        section.fields.some((field) => field.kind === "password"),
      )
    ) {
      return true;
    }
    const typeId = selectedItem.value?.type_id;
    if (!typeId) {
      return false;
    }
    return getSchemaFieldDefs(typeId).some((field) => field.type === "secret");
  });

  return {
    rememberEnabled,
    unlocked,
    initialized,
    showUnlock,
    showSetupModal,
    showMain,
    selectedItemDeleted,
    selectedItemConflict,
    hasPasswordField,
  };
}
