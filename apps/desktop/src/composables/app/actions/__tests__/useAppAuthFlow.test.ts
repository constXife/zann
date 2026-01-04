import { describe, it, expect, vi, afterEach } from "vitest";
import { defineComponent, ref, nextTick } from "vue";
import { render, cleanup } from "@testing-library/vue";
import type { Ref } from "vue";
import type { AppStatus, StorageSummary } from "../../../../types";
import { useAppAuthFlow } from "../useAppAuthFlow";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

type AuthApi = ReturnType<typeof useAppAuthFlow>;

const createWrapper = (options?: {
  formatError?: (err: unknown) => string;
  unlocked?: boolean;
  selectedStorageId?: string;
}) => {
  let api: AuthApi | null = null;
  const runRemoteSync = vi.fn();
  const refreshAppStatus = vi.fn();
  const clearSyncErrors = vi.fn();
  const unlockedValue = options?.unlocked ?? false;
  const selectedStorageValue = options?.selectedStorageId ?? "local";
  const formatError = options?.formatError ?? ((err: unknown) => String(err));

  const Wrapper = defineComponent({
    setup() {
      const uiSettings = ref({ showLocalStorage: true });
      const appStatus = ref<AppStatus | null>(null);
      const unlocked = ref(unlockedValue);
      const selectedStorageId = ref(selectedStorageValue);
      const showSessionExpiredBanner = ref(false);
      const sessionExpiredStorage = ref<StorageSummary | undefined>(undefined);
      const syncError = ref("");

      api = useAppAuthFlow({
        t: (key) => key,
        uiSettings,
        appStatus,
        unlocked,
        selectedStorageId,
        showSessionExpiredBanner,
        sessionExpiredStorage,
        syncError,
        refreshStatus: vi.fn(),
        refreshAppStatus,
        loadStorages: vi.fn(),
        runRemoteSync,
        runBootstrap: vi.fn(),
        clearSyncErrors,
        openConfirm: vi.fn(),
        showToast: vi.fn(),
        openExternal: vi.fn(),
        formatError,
      });

      return () => null;
    },
  });

  render(Wrapper);
  return {
    api: api as AuthApi,
    runRemoteSync,
    refreshAppStatus,
    clearSyncErrors,
  };
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("useAppAuthFlow", () => {
  it("clears the connect url when starting a new connect flow", () => {
    const { api } = createWrapper();
    api.connectServerUrl.value = "https://example.com";
    api.connectStatus.value = "waiting";

    api.startConnect();

    expect(api.connectServerUrl.value).toBe("");
    expect(api.connectStatus.value).toBe("");
  });

  it("uses formatError for network failures", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("error sending request"),
    );

    const { api } = createWrapper({ formatError: () => "friendly message" });
    api.connectServerUrl.value = "https://example.com";

    await api.showAuthMethodSelection();
    await nextTick();

    expect(api.connectError.value).toBe("friendly message");
  });

  it("runs sync for the new storage id after password login", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: {
        status: "success",
        storage_id: "new-storage",
        login_id: null,
        old_fingerprint: null,
        new_fingerprint: null,
      },
    });

    const { api, runRemoteSync, clearSyncErrors } = createWrapper({
      unlocked: true,
      selectedStorageId: "old-storage",
    });

    await api.handlePasswordAuth({
      mode: "login",
      email: "user@example.com",
      password: "pass",
    });

    expect(runRemoteSync).toHaveBeenCalledWith("new-storage");
    expect(clearSyncErrors).toHaveBeenCalledWith("new-storage");
  });

  it("runs sync for the new storage id after oidc login", async () => {
    const { api, runRemoteSync, clearSyncErrors } = createWrapper({
      unlocked: true,
      selectedStorageId: "old-storage",
    });

    api.connectLoginId.value = "login-1";

    await api.handleOidcStatus({
      login_id: "login-1",
      status: "success",
      storage_id: "new-storage",
      email: "user@example.com",
      old_fingerprint: null,
      new_fingerprint: null,
    });

    expect(runRemoteSync).toHaveBeenCalledWith("new-storage");
    expect(clearSyncErrors).toHaveBeenCalledWith("new-storage");
  });
});
