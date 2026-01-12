import { render, screen, cleanup } from "@testing-library/vue";
import { createI18n } from "vue-i18n";
import { describe, it, expect, vi, afterEach } from "vitest";
import type { StorageSummary } from "../../types";
import { AuthMethod, StorageKind } from "../../constants/enums";
import SidebarPanel from "../SidebarPanel.vue";

const baseStorage: StorageSummary = {
  id: "remote-1",
  name: "Remote",
  kind: StorageKind.Remote,
  server_url: "https://example.com",
  server_name: "Example",
  account_subject: "user@example.com",
  personal_vaults_enabled: true,
  auth_method: AuthMethod.Password,
};

const createI18nPlugin = () =>
  createI18n({
    legacy: false,
    locale: "en",
    messages: {
      en: {
        storage: {
          lastSynced: "Last synced",
          localVault: "Local vault",
          servers: "Servers",
        },
        sidebar: { collapse: "Collapse" },
        common: { settings: "Settings" },
        nav: { vaults: "Vaults", sections: "Sections", folders: "Folders", noFolder: "No folder" },
      },
    },
  });

const renderSidebar = (options?: {
  lastSyncTime?: string | null;
  syncStatus?: "idle" | "syncing" | "synced" | "error";
}) => {
  const lastSyncTime = options?.lastSyncTime ?? null;
  const syncStatus = options?.syncStatus ?? "idle";
  const statusMap = new Map([[baseStorage.id, syncStatus]]);

  return render(SidebarPanel, {
    global: {
      plugins: [createI18nPlugin()],
    },
    props: {
      onCollapse: vi.fn(),
      storageDropdownOpen: false,
      storages: [baseStorage],
      remoteStorages: [baseStorage],
      localStorage: undefined,
      showLocalSection: false,
      hasLocalVaults: false,
      selectedStorageId: baseStorage.id,
      currentStorage: baseStorage,
      getSyncStatus: (id: string) => statusMap.get(id) ?? "idle",
      storageSyncErrors: new Map(),
      lastSyncTime,
      toggleStorageDropdown: vi.fn(),
      closeStorageDropdown: vi.fn(),
      openAddStorageWizard: vi.fn(),
      openStorageSettings: vi.fn(),
      openCreateLocalVault: vi.fn(),
      openSettings: vi.fn(),
      switchStorage: vi.fn(),
      vaultDropdownOpen: false,
      vaults: [],
      listLoading: false,
      personalVaults: [],
      sharedVaults: [],
      selectedVaultId: null,
      toggleVaultDropdown: vi.fn(),
      closeVaultDropdown: vi.fn(),
      switchVault: vi.fn(),
      openCreateVault: vi.fn(),
      categories: [],
      categoryCounts: {},
      selectedCategory: null,
      selectCategory: vi.fn(),
      folderTree: [],
      expandedFolders: new Set(),
      selectedFolder: null,
      itemsWithoutFolder: 0,
      toggleFolder: vi.fn(),
      openFolderMenu: vi.fn(),
      selectFolder: vi.fn(),
    },
  });
};

describe("SidebarPanel", () => {
  afterEach(() => {
    cleanup();
  });

  it("shows a warning icon for stale syncs after 7 days", () => {
    const lastSyncTime = new Date(Date.now() - 8 * 86400000).toISOString();
    renderSidebar({ lastSyncTime, syncStatus: "idle" });

    const icon = screen.getByTestId("sync-status-stale");
    expect(icon.getAttribute("class")).toContain("text-amber-500");
    expect(icon.getAttribute("title")).toContain("Last synced");
  });

  it("shows a critical icon for stale syncs after 30 days", () => {
    const lastSyncTime = new Date(Date.now() - 31 * 86400000).toISOString();
    renderSidebar({ lastSyncTime, syncStatus: "idle" });

    const icon = screen.getByTestId("sync-status-stale");
    expect(icon.getAttribute("class")).toContain("text-red-500");
  });

  it("prefers sync error over stale indicators", () => {
    const lastSyncTime = new Date(Date.now() - 31 * 86400000).toISOString();
    renderSidebar({ lastSyncTime, syncStatus: "error" });

    expect(screen.queryByTestId("sync-status-stale")).toBeNull();
    expect(screen.getByTestId("sync-status-error")).toBeTruthy();
  });
});
