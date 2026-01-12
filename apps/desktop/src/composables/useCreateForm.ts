import { computed, onBeforeUnmount, ref, watch, type Ref } from "vue";
import type { EncryptedPayload, FieldValue, VaultSummary } from "../types";
import type { FieldInput, Translator } from "../types/createForm";
import { jsonPlaceholders, typeMeta } from "./createFormDefaults";
import { sanitizeToken } from "../utils/inputSanitizer";

type UseCreateFormOptions = {
  variant?: "modal" | "panel";
  createModalOpen: Ref<boolean>;
  createItemVaultId: Ref<string | null>;
  createItemType: Ref<string>;
  createItemTitle: Ref<string>;
  createItemFolder: Ref<string>;
  createItemFields: FieldInput[];
  createEditingItemId: Ref<string | null>;
  flatFolderPaths: string[];
  showFolderSuggestions: Ref<boolean>;
  vaults: VaultSummary[];
  typeOptions: string[];
  revealedFields: Set<string>;
  t: Translator;
  buildPayload: (typeId: string) => EncryptedPayload;
  applyPayload: (payload: EncryptedPayload, typeId: string) => void;
  submitCreate: () => void;
};

export const useCreateForm = (options: UseCreateFormOptions) => {
  const isPanel = computed(() => options.variant === "panel");

  const selectedVaultName = () => {
    if (!options.createItemVaultId.value) {
      return "-";
    }
    return options.vaults.find((vault) => vault.id === options.createItemVaultId.value)?.name ?? "-";
  };

  const pathTokens = ref<string[]>([]);
  const pathInput = ref("");
  const folderInput = ref("");
  const nameInput = ref("");
  const tokenDeleteArmed = ref(false);
  const vaultShake = ref(false);
  const typeMenuOpen = ref(false);
  const titleSnapshot = ref("");
  const rawEditOpen = ref(false);
  const rawJsonText = ref("");
  const rawJsonErrorKey = ref("");
  const copyMenuOpen = ref(false);
  const copyNotice = ref("");
  let copyNoticeTimer: number | null = null;
  const pastePromptOpen = ref(false);
  const pastePromptMessage = ref("");
  let pendingPastePayload: EncryptedPayload | null = null;
  let pendingPasteTypeId: string | null = null;
  const generatorOpenId = ref<string | null>(null);
  const generatorLength = ref(20);
  const generatorIncludeUpper = ref(true);
  const generatorIncludeLower = ref(true);
  const generatorIncludeDigits = ref(true);
  const generatorIncludeSymbols = ref(false);
  const generatorAvoidAmbiguous = ref(false);
  const generatorMemorable = ref(false);

  const currentPathInput = computed({
    get: () => (isPanel.value ? folderInput.value : pathInput.value),
    set: (value: string) => {
      if (isPanel.value) {
        folderInput.value = value;
      } else {
        pathInput.value = value;
      }
    },
  });

  const currentTypeLabel = computed(() => {
    const key = `types.${options.createItemType.value}`;
    const label = options.t(key);
    return label !== key ? label : options.createItemType.value;
  });

  const currentTypeIcon = computed(() => {
    const meta = typeMeta[options.createItemType.value];
    return meta?.icon ?? "key";
  });

  const getTypeLabel = (typeId: string) => {
    const key = `types.${typeId}`;
    const label = options.t(key);
    return label !== key ? label : typeId;
  };

  const jsonPlaceholderText = computed(() =>
    jsonPlaceholders[options.createItemType.value] ?? jsonPlaceholders.default,
  );

  const newFieldId = () => {
    const cryptoObj = globalThis.crypto;
    if (cryptoObj?.randomUUID) {
      return cryptoObj.randomUUID();
    }
    return `f-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  };

  const emptyKvRow = (): FieldInput => ({
    id: newFieldId(),
    key: "",
    value: "",
    fieldType: "text",
    isCustom: true,
    isSecret: false,
  });

  const applyDataRows = (rows: FieldInput[], append = false) => {
    const nextRows =
      rows.length || options.createItemType.value !== "kv" ? rows : [emptyKvRow()];
    if (append) {
      options.createItemFields.splice(
        0,
        options.createItemFields.length,
        ...options.createItemFields,
        ...nextRows,
      );
      return;
    }
    options.createItemFields.splice(0, options.createItemFields.length, ...nextRows);
  };

  const parseJsonPayload = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) {
      return { payload: null, errorKey: "" };
    }
    try {
      const parsed = JSON.parse(trimmed) as EncryptedPayload;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { payload: null, errorKey: "create.invalidJsonObject" };
      }
      const fields = (parsed as EncryptedPayload).fields;
      if (!fields || typeof fields !== "object" || Array.isArray(fields)) {
        return { payload: null, errorKey: "create.invalidJsonObject" };
      }
      return { payload: parsed, errorKey: "" };
    } catch {
      return { payload: null, errorKey: "create.invalidJson" };
    }
  };

  const inferKind = (key: string, value: string): FieldValue["kind"] => {
    const lowered = key.toLowerCase();
    if (lowered.includes("otp")) return "otp";
    if (
      lowered.includes("password") ||
      lowered.includes("secret") ||
      lowered.includes("token") ||
      lowered.endsWith("_key") ||
      lowered.endsWith("key")
    ) {
      return "password";
    }
    if (lowered.includes("url") || lowered.includes("uri")) return "url";
    if (lowered.includes("note") || value.includes("\n")) return "note";
    return "text";
  };

  const toStringValue = (value: unknown): string => {
    if (value === null || value === undefined) return "";
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    return JSON.stringify(value);
  };

  const buildFieldsFromRecord = (record: Record<string, unknown>): Record<string, FieldValue> => {
    const fields: Record<string, FieldValue> = {};
    Object.entries(record).forEach(([key, value]) => {
      if (!key) return;
      if (value && typeof value === "object" && !Array.isArray(value)) {
        const maybeKind = (value as { kind?: unknown }).kind;
        const maybeValue = (value as { value?: unknown }).value;
        if (typeof maybeKind === "string" && "value" in (value as object)) {
          fields[key] = {
            kind: maybeKind as FieldValue["kind"],
            value: toStringValue(maybeValue),
            meta: (value as FieldValue).meta,
          };
          return;
        }
      }
      const rendered = toStringValue(value);
      fields[key] = {
        kind: inferKind(key, rendered),
        value: rendered,
      };
    });
    return fields;
  };

  const parseEnv = (text: string) => {
    const record: Record<string, string> = {};
    text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .forEach((line) => {
        if (line.startsWith("#")) return;
        const idx = line.indexOf("=");
        if (idx === -1) return;
        const key = line.slice(0, idx).trim();
        const value = line.slice(idx + 1).trim();
        if (!key) return;
        record[key] = value;
      });
    return record;
  };

  const parseJsonText = (text: string) => {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return null;
    }
  };

  const parsePastePayload = (text: string) => {
    const envRecord = parseEnv(text);
    if (Object.keys(envRecord).length > 0) {
      return {
        payload: {
          v: 1,
          typeId: "kv",
          fields: buildFieldsFromRecord(envRecord),
        } as EncryptedPayload,
        typeId: "kv",
        count: Object.keys(envRecord).length,
      };
    }
    const parsedJson = parseJsonText(text);
    if (parsedJson && typeof parsedJson === "object" && !Array.isArray(parsedJson)) {
      const payload = parsedJson as EncryptedPayload;
      const fields = payload.fields ?? {};
      const count = Object.keys(fields).length;
      if (payload.typeId && count > 0) {
        return { payload, typeId: payload.typeId, count };
      }
      if (count > 0) {
        return {
          payload: {
            v: 1,
            typeId: "kv",
            fields: buildFieldsFromRecord(fields as Record<string, unknown>),
          } as EncryptedPayload,
          typeId: "kv",
          count,
        };
      }
    }
    return null;
  };

  const handlePaste = (event: ClipboardEvent) => {
    const text = event.clipboardData?.getData("text/plain") ?? "";
    const parsed = parsePastePayload(text);
    if (!parsed || parsed.count === 0) {
      return;
    }
    event.preventDefault();
    pendingPastePayload = parsed.payload;
    pendingPasteTypeId = parsed.typeId;
    pastePromptMessage.value = options.t("create.pasteDetected", { count: parsed.count });
    pastePromptOpen.value = true;
  };

  const applyPastePayload = () => {
    if (!pendingPastePayload) {
      return;
    }
    options.createItemType.value = pendingPasteTypeId ?? options.createItemType.value;
    options.applyPayload(pendingPastePayload, pendingPasteTypeId ?? options.createItemType.value);
    pastePromptOpen.value = false;
    pendingPastePayload = null;
    pendingPasteTypeId = null;
  };

  const dismissPastePrompt = () => {
    pastePromptOpen.value = false;
    pendingPastePayload = null;
    pendingPasteTypeId = null;
  };

  const canRemoveKvRow = computed(
    () => options.createItemType.value !== "kv" || options.createItemFields.length > 1,
  );

  const generateSecret = () => {
    const lowercase = generatorIncludeLower.value ? "abcdefghijklmnopqrstuvwxyz" : "";
    const uppercase = generatorIncludeUpper.value ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "";
    let digits = generatorIncludeDigits.value ? "0123456789" : "";
    const symbols = generatorIncludeSymbols.value ? "!@#" : "";
    const avoidAmbiguous = generatorAvoidAmbiguous.value;
    const length = Math.max(4, Math.min(128, Math.floor(generatorLength.value)));
    const cryptoObj = globalThis.crypto;
    const randomInt = (max: number) => {
      if (max <= 0) {
        return 0;
      }
      if (!cryptoObj?.getRandomValues) {
        return Math.floor(Math.random() * max);
      }
      const buffer = new Uint32Array(1);
      cryptoObj.getRandomValues(buffer);
      return buffer[0] % max;
    };
    const filterAmbiguous = (value: string) =>
      avoidAmbiguous ? value.replace(/[IlOilo01]/g, "") : value;
    const filteredLower = filterAmbiguous(lowercase);
    const filteredUpper = filterAmbiguous(uppercase);
    digits = filterAmbiguous(digits);

    if (generatorMemorable.value) {
      let consonants = "bcdfghjklmnpqrstvwxyz";
      let vowels = "aeiou";
      if (avoidAmbiguous) {
        consonants = consonants.replace(/[il]/g, "");
        vowels = vowels.replace(/[io]/g, "");
      }
      if (!consonants || !vowels) {
        consonants = "bcdfghjkmnpqrstvwxyz";
        vowels = "aeu";
      }
      if (!filteredLower && !filteredUpper) {
        const fallbackCharset = `${digits}${symbols}`;
        if (!fallbackCharset) {
          return "";
        }
        let fallback = "";
        for (let i = 0; i < length; i += 1) {
          fallback += fallbackCharset[randomInt(fallbackCharset.length)];
        }
        return fallback;
      }
      let result = "";
      let useConsonant = true;
      while (result.length < length) {
        const pool = useConsonant ? consonants : vowels;
        let nextChar = pool[randomInt(pool.length)];
        if (filteredUpper && !filteredLower) {
          nextChar = nextChar.toUpperCase();
        } else if (filteredUpper && filteredLower) {
          if (randomInt(100) < 25) {
            nextChar = nextChar.toUpperCase();
          }
        }
        result += nextChar;
        useConsonant = !useConsonant;
      }
      let chars = result.split("");
      if (digits) {
        const idx = randomInt(chars.length);
        chars[idx] = digits[randomInt(digits.length)];
      }
      if (symbols) {
        const idx = randomInt(chars.length);
        chars[idx] = symbols[randomInt(symbols.length)];
      }
      return chars.join("");
    }

    const charset = `${filteredLower}${filteredUpper}${digits}${symbols}`;
    if (!charset) {
      return "";
    }
    if (!cryptoObj?.getRandomValues) {
      let fallback = "";
      for (let i = 0; i < length; i += 1) {
        fallback += charset[randomInt(charset.length)];
      }
      return fallback;
    }
    const bytes = new Uint32Array(length);
    cryptoObj.getRandomValues(bytes);
    let result = "";
    for (let i = 0; i < bytes.length; i += 1) {
      result += charset[bytes[i] % charset.length];
    }
    return result;
  };

  const toggleTypeMenu = () => {
    typeMenuOpen.value = !typeMenuOpen.value;
  };

  const closeTypeMenu = () => {
    typeMenuOpen.value = false;
  };

  const toggleCopyMenu = () => {
    copyMenuOpen.value = !copyMenuOpen.value;
  };

  const closeCopyMenu = () => {
    copyMenuOpen.value = false;
  };

  const selectType = (typeId: string) => {
    options.createItemType.value = typeId;
    typeMenuOpen.value = false;
  };

  const pathDraft = computed(() =>
    [...pathTokens.value, currentPathInput.value].filter(Boolean).join("/"),
  );

  const filteredPathSuggestions = computed(() => {
    if (!options.showFolderSuggestions.value || !currentPathInput.value.trim()) {
      return [];
    }
    const needle = pathDraft.value.toLowerCase();
    return options.flatFolderPaths
      .filter((path) => path.toLowerCase().startsWith(needle) && path.toLowerCase() !== needle)
      .slice(0, 8);
  });

  const commitToken = () => {
    const value = currentPathInput.value.trim();
    if (!value) {
      return;
    }
    pathTokens.value = [...pathTokens.value, value];
    currentPathInput.value = "";
    tokenDeleteArmed.value = false;
    if (!isPanel.value && options.createEditingItemId.value && titleSnapshot.value) {
      currentPathInput.value = titleSnapshot.value;
    }
  };

  const handlePathKeydown = (event: KeyboardEvent) => {
    if (event.key === "/") {
      event.preventDefault();
      commitToken();
      return;
    }
    if (event.key === "Backspace" && !currentPathInput.value) {
      if (pathTokens.value.length === 0) {
        if (!vaultShake.value) {
          vaultShake.value = true;
          window.setTimeout(() => {
            vaultShake.value = false;
          }, 280);
        }
        return;
      }
      if (tokenDeleteArmed.value) {
        const tokens = [...pathTokens.value];
        const last = tokens.pop();
        pathTokens.value = tokens;
        currentPathInput.value = last ?? "";
        tokenDeleteArmed.value = false;
      } else {
        tokenDeleteArmed.value = true;
      }
      return;
    }
    if (event.key === "Escape") {
      options.showFolderSuggestions.value = false;
    } else {
      tokenDeleteArmed.value = false;
    }
  };

  const handlePathPaste = (event: ClipboardEvent) => {
    const text = event.clipboardData?.getData("text") ?? "";
    if (!text.includes("/")) {
      return;
    }
    event.preventDefault();
    applyPathInsert(text);
  };

  const applyPathInsert = (text: string) => {
    const parts = text
      .split("/")
      .map((part) => sanitizeToken(part))
      .filter(Boolean);
    if (parts.length === 0) {
      return;
    }
    if (currentPathInput.value) {
      parts[0] = `${currentPathInput.value}${parts[0]}`;
    }
    if (parts.length > 1) {
      pathTokens.value = [...pathTokens.value, ...parts.slice(0, -1)];
      currentPathInput.value = parts[parts.length - 1];
    } else {
      currentPathInput.value = parts[0];
    }
    tokenDeleteArmed.value = false;
  };

  const applySuggestion = (path: string) => {
    const parts = path.split("/").filter(Boolean);
    pathTokens.value = parts;
    currentPathInput.value = "";
    tokenDeleteArmed.value = false;
    options.showFolderSuggestions.value = false;
  };

  const scheduleHideFolderSuggestions = () => {
    setTimeout(() => {
      options.showFolderSuggestions.value = false;
    }, 150);
  };

  const closeModal = () => {
    options.createModalOpen.value = false;
  };

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      copyNotice.value = options.t("common.copied");
      if (copyNoticeTimer) {
        window.clearTimeout(copyNoticeTimer);
      }
      copyNoticeTimer = window.setTimeout(() => {
        copyNotice.value = "";
        copyNoticeTimer = null;
      }, 1400);
    } catch {
      // noop
    }
  };

  const buildEnv = (payload: EncryptedPayload) => {
    const lines = Object.entries(payload.fields ?? {}).map(([key, entry]) =>
      `${key}=${entry.value ?? ""}`,
    );
    return lines.join("\n");
  };

  const buildFlatJson = (payload: EncryptedPayload) => {
    const flat: Record<string, string> = {};
    Object.entries(payload.fields ?? {}).forEach(([key, entry]) => {
      flat[key] = String(entry.value ?? "");
    });
    return JSON.stringify(flat, null, 2);
  };

  const openRawEditor = () => {
    rawEditOpen.value = true;
    rawJsonText.value = JSON.stringify(options.buildPayload(options.createItemType.value), null, 2);
    copyMenuOpen.value = false;
  };

  const closeRawEditor = () => {
    rawEditOpen.value = false;
  };

  const applyRawEditor = () => {
    const parsed = parseJsonPayload(rawJsonText.value);
    rawJsonErrorKey.value = parsed.errorKey;
    if (!parsed.payload) {
      return;
    }
    options.applyPayload(parsed.payload, parsed.payload.typeId ?? options.createItemType.value);
    rawEditOpen.value = false;
  };

  const copyJson = () => copyText(buildFlatJson(options.buildPayload(options.createItemType.value)));
  const copyEnv = () => copyText(buildEnv(options.buildPayload(options.createItemType.value)));
  const copyRaw = () =>
    copyText(JSON.stringify(options.buildPayload(options.createItemType.value), null, 2));

  const handleShortcut = (event: KeyboardEvent) => {
    if (!options.createModalOpen.value) {
      return;
    }
    if (!(event.metaKey || event.ctrlKey) || event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    options.submitCreate();
  };

  watch(
    () => options.createModalOpen.value,
    (open) => {
      if (!open) {
        return;
      }
      pathTokens.value = options.createItemFolder.value
        ? options.createItemFolder.value.split("/").filter(Boolean)
        : [];
      pathInput.value = options.createItemTitle.value;
      nameInput.value = options.createItemTitle.value;
      folderInput.value = "";
      titleSnapshot.value = options.createItemTitle.value;
      tokenDeleteArmed.value = false;
      typeMenuOpen.value = false;
      rawEditOpen.value = false;
      rawJsonText.value = "";
      rawJsonErrorKey.value = "";
      copyMenuOpen.value = false;
      pastePromptOpen.value = false;
      generatorOpenId.value = null;
    },
    { immediate: true },
  );

  watch(
    () => [pathTokens.value, pathInput.value, folderInput.value, nameInput.value, isPanel.value],
    ([tokens, input, folderValue, nameValue, panel]) => {
      if (panel) {
        options.createItemFolder.value = [...tokens, folderValue].filter(Boolean).join("/");
        options.createItemTitle.value = nameValue;
      } else {
        options.createItemFolder.value = tokens.join("/");
        options.createItemTitle.value = input;
      }
    },
    { deep: true },
  );

  watch(
    () => options.createItemType.value,
    () => {
      rawEditOpen.value = false;
      rawJsonText.value = "";
      rawJsonErrorKey.value = "";
    },
  );

  watch(options.createModalOpen, (open) => {
    if (open) {
      window.addEventListener("keydown", handleShortcut);
    } else {
      window.removeEventListener("keydown", handleShortcut);
    }
  });

  onBeforeUnmount(() => {
    window.removeEventListener("keydown", handleShortcut);
    if (copyNoticeTimer) {
      window.clearTimeout(copyNoticeTimer);
      copyNoticeTimer = null;
    }
  });

  return {
    applyDataRows,
    applyPastePayload,
    applyRawEditor,
    buildEnv,
    buildFlatJson,
    canRemoveKvRow,
    closeModal,
    closeCopyMenu,
    closeTypeMenu,
    copyMenuOpen,
    copyNotice,
    copyText,
    copyEnv,
    copyJson,
    copyRaw,
    currentPathInput,
    currentTypeIcon,
    currentTypeLabel,
    dismissPastePrompt,
    filteredPathSuggestions,
    generatorIncludeDigits,
    generatorIncludeSymbols,
    generatorIncludeLower,
    generatorIncludeUpper,
    generatorAvoidAmbiguous,
    generatorLength,
    generatorMemorable,
    generatorOpenId,
    generateSecret,
    getTypeLabel,
    handlePaste,
    handlePathKeydown,
    handlePathPaste,
    applyPathInsert,
    isPanel,
    jsonPlaceholderText,
    closeRawEditor,
    nameInput,
    openRawEditor,
    pastePromptMessage,
    pastePromptOpen,
    applySuggestion,
    pathTokens,
    rawEditOpen,
    rawJsonErrorKey,
    rawJsonText,
    scheduleHideFolderSuggestions,
    selectedVaultName,
    selectType,
    toggleTypeMenu,
    toggleCopyMenu,
    tokenDeleteArmed,
    typeMenuOpen,
    typeMeta,
    vaultShake,
  };
};
