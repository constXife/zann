import { computed, ref, watch } from "vue";
import type { Ref } from "vue";
import type { ItemSummary } from "../types";

type Translator = (key: string) => string;

type PaletteItem = {
  id: string;
  label: string;
  subtitle?: string;
  hint?: string;
  enabled?: boolean;
  action?: () => void;
};

type UsePaletteOptions = {
  t: Translator;
  filteredItems: Ref<ItemSummary[]>;
  hasSelectedItem: Ref<boolean>;
  onSelectItem: (itemId: string) => void;
  onLock: () => void;
  onRevealToggle: () => void;
  onCopyPrimary: () => void;
  onOpenSettings: () => void;
};

export const usePalette = (options: UsePaletteOptions) => {
  const paletteOpen = ref(false);
  const paletteQuery = ref("");
  const paletteIndex = ref(0);

  const paletteItems = computed<PaletteItem[]>(() => {
    const commands: PaletteItem[] = [
      {
        id: "lock",
        label: options.t("palette.lock"),
        hint: "Cmd+L",
        action: () => options.onLock(),
      },
      {
        id: "reveal",
        label: options.t("palette.revealAll"),
        hint: "Cmd+R",
        action: () => options.onRevealToggle(),
        enabled: options.hasSelectedItem.value,
      },
      {
        id: "copy-primary",
        label: options.t("palette.copyPrimary"),
        hint: "Cmd+Shift+C",
        action: () => options.onCopyPrimary(),
        enabled: options.hasSelectedItem.value,
      },
      {
        id: "open-settings",
        label: options.t("palette.openSettings"),
        hint: "Cmd+,",
        action: () => {
          options.onOpenSettings();
          paletteOpen.value = false;
        },
      },
    ];

    const items = options.filteredItems.value.slice(0, 8).map((item, index) => ({
      id: `item:${item.id}`,
      label: item.name,
      subtitle: item.path,
      hint: `${index + 1}`,
      action: () => {
        options.onSelectItem(item.id);
        paletteOpen.value = false;
      },
    }));

    const needle = paletteQuery.value.trim().toLowerCase();
    const all = [
      ...commands.map((cmd) => ({
        ...cmd,
        enabled: cmd.enabled ?? true,
      })),
      ...items,
    ];
    if (!needle) {
      return all;
    }
    return all.filter((entry) =>
      [entry.label, entry.subtitle ?? ""].some((value) =>
        value.toLowerCase().includes(needle),
      ),
    );
  });

  watch(paletteOpen, (value) => {
    if (value) {
      paletteQuery.value = "";
      paletteIndex.value = 0;
    }
  });

  watch(paletteItems, () => {
    paletteIndex.value = 0;
  });

  return {
    paletteOpen,
    paletteQuery,
    paletteIndex,
    paletteItems,
  };
};
