import { describe, it, expect, vi, afterEach } from "vitest";
import { defineComponent, ref, computed, nextTick } from "vue";
import { render, cleanup } from "@testing-library/vue";
import type { Settings } from "../../../../types";
import { useAppEventHandlers } from "../useAppEventHandlers";

const listeners = new Map<string, () => void>();

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (event: string, handler: () => void) => {
    listeners.set(event, handler);
    return () => {
      listeners.delete(event);
    };
  }),
}));

const createSettings = (): Settings => ({
  remember_unlock: false,
  auto_unlock: false,
  language: "en",
  auto_lock_minutes: 10,
  lock_on_focus_loss: false,
  lock_on_hidden: false,
  clipboard_clear_seconds: 30,
  clipboard_clear_on_lock: false,
  clipboard_clear_on_exit: false,
  clipboard_clear_if_unchanged: false,
  auto_hide_reveal_seconds: 20,
  require_os_auth: true,
  biometry_dwk_backup: null,
  trash_auto_purge_days: 90,
  close_to_tray: true,
  close_to_tray_notice_shown: false,
});

const renderHandlers = () => {
  const showToast = vi.fn();
  const Wrapper = defineComponent({
    setup() {
      useAppEventHandlers({
        t: (key) => `t:${key}`,
        settings: ref(createSettings()),
        unlocked: computed(() => true),
        storageDropdownOpen: ref(false),
        vaultDropdownOpen: ref(false),
        paletteOpen: ref(false),
        paletteIndex: ref(0),
        paletteItems: ref([]),
        createModalOpen: ref(false),
        selectedItem: ref(null),
        copyPrimarySecret: vi.fn(),
        revealToggle: vi.fn(),
        openCreateModal: vi.fn(),
        detailsPanel: ref(null),
        moveSelection: vi.fn(),
        selectedItemId: ref(null),
        loadItemDetail: vi.fn(),
        settingsOpen: ref(false),
        openSettings: vi.fn(),
        lockSession: vi.fn(),
        scheduleRemoteSync: vi.fn(),
        selectedStorageId: ref("remote-1"),
        clearClipboardNow: vi.fn(),
        runRemoteSync: vi.fn().mockResolvedValue(true),
        timeTravelActive: ref(false),
        timeTravelIndex: ref(0),
        timeTravelMaxIndex: computed(() => 0),
        setTimeTravelIndex: vi.fn(),
        showToast,
      });

      return () => null;
    },
  });

  render(Wrapper);
  return { showToast };
};

afterEach(() => {
  cleanup();
  listeners.clear();
  vi.clearAllMocks();
});

describe("useAppEventHandlers", () => {
  it("shows a tray notice toast when requested", async () => {
    const { showToast } = renderHandlers();
    await nextTick();

    const handler = listeners.get("zann:close-to-tray");
    expect(handler).toBeTruthy();

    handler?.();
    expect(showToast).toHaveBeenCalledWith("t:status.trayNotice", { duration: 2400 });
  });
});
