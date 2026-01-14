import { render, cleanup } from "@testing-library/vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent, nextTick, ref } from "vue";
import type { StorageSummary } from "../../types";
import { StorageKind } from "../../constants/enums";
import { useStorages } from "../useStorages";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

type StorageApi = ReturnType<typeof useStorages>;

const remoteStorage: StorageSummary = {
  id: "remote-1",
  name: "Remote",
  kind: StorageKind.Remote,
  server_url: "https://example.com",
  personal_vaults_enabled: true,
};

let online = true;

const setOnline = (value: boolean) => {
  online = value;
};

Object.defineProperty(window.navigator, "onLine", {
  configurable: true,
  get: () => online,
});

const createWrapper = () => {
  let api: StorageApi | null = null;

  const Wrapper = defineComponent({
    setup() {
      api = useStorages({
        selectedStorageId: ref(remoteStorage.id),
        initialized: ref(true),
        unlocked: ref(true),
        t: (key) => key,
        onFatalError: vi.fn(),
        onReloadVaults: vi.fn(),
        onReloadItems: vi.fn(),
        localStorageId: "local",
        onSessionExpired: vi.fn(),
        localStorageVisible: ref(true),
      });
      api.storages.value = [remoteStorage];
      return () => null;
    },
  });

  render(Wrapper);
  return api as StorageApi;
};

beforeEach(() => {
  setOnline(true);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("useStorages", () => {
  it("queues sync when offline and retries once online", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: { locked_vaults: [] },
    });

    const api = createWrapper();
    (invoke as unknown as ReturnType<typeof vi.fn>).mockClear();
    setOnline(false);
    window.dispatchEvent(new Event("offline"));
    await nextTick();

    const result = await api.runRemoteSync(null);
    expect(result).toBe(false);
    expect(invoke).not.toHaveBeenCalled();
    expect(api.storageSyncErrors.value.get(remoteStorage.id)).toBe(
      "errors.server_unreachable",
    );

    setOnline(true);
    window.dispatchEvent(new Event("online"));
    await nextTick();
    await Promise.resolve();

    expect(invoke).toHaveBeenCalled();
  });

  it("marks offline when a network error happens", async () => {
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("error sending request"),
    );

    const api = createWrapper();
    (invoke as unknown as ReturnType<typeof vi.fn>).mockClear();
    setOnline(true);

    const result = await api.runRemoteSync(null);
    expect(result).toBe(false);
    expect(api.isOffline.value).toBe(true);
    expect(api.storageSyncErrors.value.get(remoteStorage.id)).toBe(
      "errors.server_unreachable",
    );
  });
});
