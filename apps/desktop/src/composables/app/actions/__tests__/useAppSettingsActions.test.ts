import { describe, it, expect, vi, afterEach } from "vitest";
import { ref } from "vue";
import { useAppSettingsActions } from "../useAppSettingsActions";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const createActions = (options?: { syncError?: string }) => {
  const settings = ref({
    remember_unlock: false,
    auto_unlock: false,
    auto_lock_minutes: 10,
    lock_on_focus_loss: false,
    lock_on_hidden: false,
    clipboard_clear_seconds: 30,
    clipboard_clear_on_lock: false,
    clipboard_clear_on_exit: false,
    clipboard_clear_if_unchanged: false,
    auto_hide_reveal_seconds: 10,
    require_os_auth: false,
    trash_auto_purge_days: 30,
    close_to_tray: false,
    close_to_tray_notice_shown: false,
  });
  const keystoreStatus = ref(null);
  const locale = ref("en");
  const showToast = vi.fn();
  const setError = vi.fn();
  const runRemoteSync = vi.fn().mockResolvedValue(true);
  const syncError = ref(options?.syncError ?? "");
  const t = (key: string) => key;

  return {
    actions: useAppSettingsActions({
      t,
      settings,
      keystoreStatus,
      locale,
      showToast,
      setError,
      runRemoteSync,
      syncError,
    }),
    showToast,
    runRemoteSync,
    syncError,
  };
};

afterEach(() => {
  vi.clearAllMocks();
});

describe("useAppSettingsActions importPlainBackup", () => {
  it("syncs after remote import and shows sync toasts", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: {
        imported_items: 1,
        skipped_existing: 0,
        skipped_missing_storage: 0,
        skipped_missing_vault: 0,
        skipped_deleted: 0,
      },
    });

    const { actions, showToast, runRemoteSync } = createActions();
    await actions.importPlainBackup(null, "remote-1");

    expect(runRemoteSync).toHaveBeenCalledWith("remote-1");
    expect(showToast).toHaveBeenCalledWith("settings.backups.importSyncStart");
    expect(showToast).toHaveBeenCalledWith("settings.backups.importSyncDone");
  });

  it("shows sync error toast when sync fails", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: {
        imported_items: 1,
        skipped_existing: 0,
        skipped_missing_storage: 0,
        skipped_missing_vault: 0,
        skipped_deleted: 0,
      },
    });

    const { actions, showToast, runRemoteSync, syncError } = createActions({
      syncError: "sync boom",
    });
    runRemoteSync.mockResolvedValue(false);

    await actions.importPlainBackup(null, "remote-2");

    expect(runRemoteSync).toHaveBeenCalledWith("remote-2");
    expect(showToast).toHaveBeenCalledWith("settings.backups.importSyncStart");
    expect(showToast).toHaveBeenCalledWith(syncError.value, { duration: 2000 });
  });

  it("does not sync for local import and shows success toast", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: {
        imported_items: 1,
        skipped_existing: 0,
        skipped_missing_storage: 0,
        skipped_missing_vault: 0,
        skipped_deleted: 0,
      },
    });

    const { actions, showToast, runRemoteSync } = createActions();
    await actions.importPlainBackup(null, "local");

    expect(runRemoteSync).not.toHaveBeenCalled();
    expect(showToast).toHaveBeenCalledWith("settings.backups.importSuccess");
  });
});
