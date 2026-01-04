import { computed, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Ref } from "vue";
import type { FolderNode, ItemSummary } from "../types";

type Translator = (key: string) => string;

type UseFoldersOptions = {
  items: Ref<ItemSummary[]>;
  selectedStorageId: Ref<string>;
  createItemFolder: Ref<string>;
  onReloadItems: () => Promise<void>;
  t: Translator;
};

export const useFolders = (options: UseFoldersOptions) => {
  const selectedFolder = ref<string | null>(null);
  const expandedFolders = ref<Set<string>>(new Set());

  const activeItems = computed(() =>
    options.items.value.filter((item) => !item.deleted_at),
  );

  const folderTree = computed(() => {
    const root: FolderNode[] = [];
    const pathMap = new Map<string, FolderNode>();

    activeItems.value.forEach((item) => {
      const parts = item.path.split("/");
      if (parts.length <= 1) return;

      parts.pop();
      let currentPath = "";
      let parent = root;

      parts.forEach((part) => {
        currentPath = currentPath ? `${currentPath}/${part}` : part;
        let node = pathMap.get(currentPath);
        if (!node) {
          node = { name: part, path: currentPath, children: [], itemCount: 0, totalCount: 0 };
          pathMap.set(currentPath, node);
          parent.push(node);
        }
        parent = node.children;
      });
    });

    activeItems.value.forEach((item) => {
      const parts = item.path.split("/");
      if (parts.length <= 1) return;
      parts.pop();
      const folderPath = parts.join("/");
      const node = pathMap.get(folderPath);
      if (node) node.itemCount++;
    });

    const countTotal = (node: FolderNode): number => {
      node.totalCount = node.itemCount + node.children.reduce((sum, child) => sum + countTotal(child), 0);
      return node.totalCount;
    };
    root.forEach(countTotal);

    return root;
  });

  const itemsWithoutFolder = computed(
    () => activeItems.value.filter((item) => !item.path.includes("/")).length,
  );

  const flatFolderPaths = computed(() => {
    const paths: string[] = [];
    const collectPaths = (nodes: FolderNode[]) => {
      for (const node of nodes) {
        paths.push(node.path);
        collectPaths(node.children);
      }
    };
    collectPaths(folderTree.value);
    return paths.sort();
  });

  const showFolderSuggestions = ref(false);
  const folderSuggestions = computed(() => {
    const input = options.createItemFolder.value.toLowerCase().trim();
    if (!input) return flatFolderPaths.value.slice(0, 10);
    return flatFolderPaths.value
      .filter((p) => p.toLowerCase().includes(input))
      .slice(0, 10);
  });

  const selectFolderSuggestion = (path: string) => {
    options.createItemFolder.value = path;
    showFolderSuggestions.value = false;
  };

  const folderMenuOpen = ref(false);
  const folderMenuTarget = ref<FolderNode | null>(null);
  const folderMenuPosition = ref({ x: 0, y: 0 });

  const openFolderMenu = (event: MouseEvent, folder: FolderNode) => {
    event.preventDefault();
    folderMenuTarget.value = folder;
    folderMenuPosition.value = { x: event.clientX, y: event.clientY };
    folderMenuOpen.value = true;
  };

  const closeFolderMenu = () => {
    folderMenuOpen.value = false;
    folderMenuTarget.value = null;
  };

  const copyFolderPath = async () => {
    if (folderMenuTarget.value) {
      await navigator.clipboard.writeText(folderMenuTarget.value.path);
    }
    closeFolderMenu();
  };

  const renameFolderModalOpen = ref(false);
  const renameFolderOldPath = ref("");
  const renameFolderNewName = ref("");
  const renameFolderBusy = ref(false);
  const renameFolderError = ref("");

  const affectedItemsCount = computed(() => {
    if (!renameFolderOldPath.value) return 0;
    return activeItems.value.filter(item =>
      item.path === renameFolderOldPath.value ||
      item.path.startsWith(renameFolderOldPath.value + "/")
    ).length;
  });

  const renameFolderNewPath = computed(() => {
    if (!renameFolderOldPath.value || !renameFolderNewName.value.trim()) return "";
    const parts = renameFolderOldPath.value.split("/");
    parts[parts.length - 1] = renameFolderNewName.value.trim();
    return parts.join("/");
  });

  const openRenameFolderModal = () => {
    if (!folderMenuTarget.value) return;
    renameFolderOldPath.value = folderMenuTarget.value.path;
    renameFolderNewName.value = folderMenuTarget.value.name;
    renameFolderError.value = "";
    renameFolderModalOpen.value = true;
    closeFolderMenu();
  };

  const submitRenameFolder = async () => {
    if (!renameFolderNewName.value.trim()) {
      renameFolderError.value = options.t("errors.name_required");
      return;
    }

    const oldPath = renameFolderOldPath.value;
    const newPath = renameFolderNewPath.value;

    if (oldPath === newPath) {
      renameFolderModalOpen.value = false;
      return;
    }

    renameFolderBusy.value = true;
    renameFolderError.value = "";

    try {
      const itemsToUpdate = options.items.value.filter(item =>
        item.path === oldPath || item.path.startsWith(oldPath + "/")
      );

      for (const item of itemsToUpdate) {
        const updatedPath = item.path === oldPath
          ? newPath
          : newPath + item.path.slice(oldPath.length);

        await invoke("items_update", {
          req: {
            storage_id: options.selectedStorageId.value,
            vault_id: item.vault_id,
            item_id: item.id,
            path: updatedPath,
          },
        });
      }

      await options.onReloadItems();
      renameFolderModalOpen.value = false;
    } catch (e: unknown) {
      renameFolderError.value = e instanceof Error ? e.message : String(e);
    } finally {
      renameFolderBusy.value = false;
    }
  };

  const toggleFolder = (path: string) => {
    if (expandedFolders.value.has(path)) {
      expandedFolders.value.delete(path);
    } else {
      expandedFolders.value.add(path);
    }
    expandedFolders.value = new Set(expandedFolders.value);
  };

  const selectFolderFilter = (path: string | null) => {
    selectedFolder.value = path;
  };

  return {
    selectedFolder,
    expandedFolders,
    folderTree,
    itemsWithoutFolder,
    flatFolderPaths,
    showFolderSuggestions,
    folderSuggestions,
    selectFolderSuggestion,
    folderMenuOpen,
    folderMenuTarget,
    folderMenuPosition,
    openFolderMenu,
    closeFolderMenu,
    copyFolderPath,
    renameFolderModalOpen,
    renameFolderOldPath,
    renameFolderNewName,
    renameFolderBusy,
    renameFolderError,
    affectedItemsCount,
    renameFolderNewPath,
    openRenameFolderModal,
    submitRenameFolder,
    toggleFolder,
    selectFolderFilter,
  };
};
