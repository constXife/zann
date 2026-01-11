import { render, fireEvent, screen, cleanup } from "@testing-library/vue";
import { describe, it, expect, vi, afterEach } from "vitest";
import type { Settings } from "../../types";
import SettingsTabGeneral from "../settings/SettingsTabGeneral.vue";

const createSettings = (overrides: Partial<Settings> = {}): Settings => ({
  remember_unlock: false,
  auto_unlock: false,
  language: "en",
  auto_lock_minutes: 10,
  lock_on_focus_loss: true,
  lock_on_hidden: true,
  clipboard_clear_seconds: 30,
  clipboard_clear_on_lock: true,
  clipboard_clear_on_exit: false,
  clipboard_clear_if_unchanged: false,
  auto_hide_reveal_seconds: 20,
  require_os_auth: true,
  biometry_dwk_backup: null,
  trash_auto_purge_days: 90,
  close_to_tray: true,
  close_to_tray_notice_shown: false,
  ...overrides,
});

describe("SettingsTabGeneral", () => {
  afterEach(() => {
    cleanup();
  });

  it("updates close-to-tray setting when toggled", async () => {
    const updateSettings = vi.fn();
    const settings = createSettings({ close_to_tray: true });

    render(SettingsTabGeneral, {
      props: {
        settings,
        locale: "en",
        t: (key: string) => key,
        updateSettings,
      },
    });

    const checkbox = screen.getByTestId("settings-close-to-tray");
    await fireEvent.click(checkbox);

    expect(updateSettings).toHaveBeenCalledWith({ close_to_tray: false });
  });
});
