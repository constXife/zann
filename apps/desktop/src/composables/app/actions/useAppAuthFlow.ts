import { onBeforeUnmount, onMounted, ref } from "vue";
import type { ComputedRef, Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { UiSettings } from "../../useUiSettings";
import type { ApiResponse, AppStatus, StorageSummary } from "../../../types";
import { AuthMethod, StorageKind } from "../../../constants/enums";

type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => Promise<void> | void;
};

type PasswordAuthPayload = {
  mode: "login" | "register";
  email: string;
  password: string;
  fullName?: string | null;
};

type AppAuthFlowOptions = {
  t: (key: string, params?: Record<string, unknown>) => string;
  uiSettings: Ref<UiSettings>;
  appStatus: Ref<AppStatus | null>;
  unlocked: ComputedRef<boolean>;
  selectedStorageId: Ref<string>;
  localStorageId: string;
  showSessionExpiredBanner: ComputedRef<boolean>;
  sessionExpiredStorage: ComputedRef<StorageSummary | undefined>;
  syncError: Ref<string>;
  refreshStatus: () => Promise<void>;
  refreshAppStatus: () => Promise<void>;
  loadStorages: () => Promise<void>;
  runRemoteSync: (storageId?: string | null) => Promise<boolean>;
  runBootstrap: () => Promise<void>;
  clearSyncErrors: (storageId: string) => void;
  openConfirm: (options: ConfirmOptions) => void;
  showToast: (message: string, options?: { duration?: number }) => void;
  openExternal: (url: string) => Promise<void>;
  formatError: (err: unknown) => string;
};

export function useAppAuthFlow({
  t,
  uiSettings,
  appStatus,
  unlocked,
  selectedStorageId,
  localStorageId,
  showSessionExpiredBanner,
  sessionExpiredStorage,
  syncError,
  refreshStatus,
  refreshAppStatus,
  loadStorages,
  runRemoteSync,
  runBootstrap,
  clearSyncErrors,
  openConfirm,
  showToast,
  openExternal,
  formatError,
}: AppAuthFlowOptions) {
  const setupStep = ref<"welcome" | "password" | "connect">("welcome");
  const setupFlow = ref<"local" | "remote">("remote");
  const setupOpen = ref(false);
  const setupPassword = ref("");
  const setupConfirm = ref("");
  const setupError = ref("");
  const setupBusy = ref(false);
  const connectServerUrl = ref("");
  const connectLoginId = ref("");
  const connectVerification = ref("");
  const connectStatus = ref("");
  const connectError = ref("");
  const connectOldFp = ref("");
  const connectNewFp = ref("");
  const connectBusy = ref(false);
  const authMethodOpen = ref(false);
  const availableMethods = ref<AuthMethod[]>([]);
  const passwordLoginOpen = ref(false);
  const passwordLoginBusy = ref(false);
  const passwordLoginError = ref("");
  let oidcUnlisten: null | (() => void) = null;

  const normalizeServerUrl = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) {
      return trimmed;
    }
    if (/^https?:\/\//i.test(trimmed)) {
      return trimmed;
    }
    return `https://${trimmed}`;
  };

  const startLocalSetup = () => {
    setupError.value = "";
    setupFlow.value = "local";
    setupStep.value = "password";
  };

  const startConnect = () => {
    setupError.value = "";
    connectServerUrl.value = "";
    connectError.value = "";
    connectStatus.value = "";
    connectBusy.value = false;
    connectLoginId.value = "";
    setupFlow.value = "remote";
    connectVerification.value = "";
    connectOldFp.value = "";
    connectNewFp.value = "";
    syncError.value = "";
    setupStep.value = "connect";
  };

  const backToWelcome = () => {
    setupError.value = "";
    connectError.value = "";
    connectStatus.value = "";
    connectBusy.value = false;
    setupStep.value = "welcome";
    if (appStatus.value?.initialized) {
      setupOpen.value = false;
    }
  };

  const createMasterPassword = async () => {
    setupError.value = "";
    if (!setupPassword.value) {
      setupError.value = t("errors.password_required");
      return;
    }
    if (setupPassword.value !== setupConfirm.value) {
      setupError.value = t("wizard.passwordMismatch");
      return;
    }
    setupBusy.value = true;
    try {
      if (setupFlow.value === "local") {
        const identityResponse = await invoke<ApiResponse<null>>(
          "initialize_local_identity",
        );
        if (!identityResponse.ok) {
          const key = identityResponse.error?.kind ?? "generic";
          throw new Error(t(`errors.${key}`));
        }
      }
      const response = await invoke<ApiResponse<null>>(
        "initialize_master_password",
        { password: setupPassword.value },
      );
      if (!response.ok) {
        const key = response.error?.kind ?? "generic";
        throw new Error(t(`errors.${key}`));
      }
      setupPassword.value = "";
      setupConfirm.value = "";
      await refreshStatus();
      await refreshAppStatus();
      await loadStorages();
      if (setupFlow.value === "local") {
        selectedStorageId.value = localStorageId;
      }
      syncError.value = "";
      if (setupFlow.value === "remote") {
        const syncOk = await runRemoteSync();
        if (!syncOk && syncError.value) {
          setupError.value = syncError.value;
          return;
        }
      }
      uiSettings.value.showLocalStorage = true;
      if (appStatus.value?.initialized) {
        setupOpen.value = false;
        setupStep.value = "welcome";
      }
    } catch (err) {
      setupError.value = String(err);
    } finally {
      setupBusy.value = false;
    }
  };

  const beginOidcConnect = async () => {
    connectError.value = "";
    connectStatus.value = "";
    connectBusy.value = true;
    try {
      const response = await invoke<ApiResponse<{
        login_id: string;
        authorization_url: string;
      }>>("remote_begin_login", { serverUrl: connectServerUrl.value });
      if (!response.ok || !response.data) {
        const key = response.error?.kind ?? "generic";
        throw new Error(t(`errors.${key}`));
      }
      connectLoginId.value = response.data.login_id;
      console.info("[oidc] login id set", connectLoginId.value);
      connectVerification.value = response.data.authorization_url;
      connectStatus.value = "waiting";
      connectOldFp.value = "";
      connectNewFp.value = "";
    } catch (err) {
      connectError.value = formatError(err);
      connectBusy.value = false;
    }
  };

  const showAuthMethodSelection = async () => {
    const normalized = normalizeServerUrl(connectServerUrl.value);
    connectServerUrl.value = normalized;
    connectError.value = "";
    connectBusy.value = true;

    try {
      const response = await invoke<ApiResponse<{ auth_methods: AuthMethod[] }>>(
        "get_server_info",
        {
          serverUrl: normalized,
        },
      );

      if (!response.ok || !response.data) {
        connectError.value = response.error?.message || "Failed to get server info";
        connectBusy.value = false;
        return;
      }

      const methods = response.data.auth_methods;
      const interactiveMethods = methods.filter(
        (method) => method === AuthMethod.Password || method === AuthMethod.Oidc,
      );
      availableMethods.value = interactiveMethods;
      connectBusy.value = false;

      if (interactiveMethods.length === 0) {
        connectError.value = "No interactive auth methods available";
        return;
      }

      if (interactiveMethods.length === 1) {
        if (interactiveMethods[0] === AuthMethod.Oidc) {
          await beginOidcConnect();
          if (connectVerification.value) {
            await openExternal(connectVerification.value);
          }
        } else if (interactiveMethods[0] === AuthMethod.Password) {
          passwordLoginError.value = "";
          passwordLoginOpen.value = true;
        }
        return;
      }

      authMethodOpen.value = true;
    } catch (err) {
      connectError.value = formatError(err);
      connectBusy.value = false;
    }
  };

  const handleBannerSignIn = async () => {
    const storage = sessionExpiredStorage.value;
    if (!storage?.server_url) {
      showToast(t("errors.generic"));
      return;
    }

    connectServerUrl.value = normalizeServerUrl(storage.server_url);

    try {
      await showAuthMethodSelection();
      if (connectError.value) {
        showToast(connectError.value, { duration: 1800 });
      }
    } catch (err) {
      showToast(formatError(err), { duration: 1800 });
    }
  };

  const handleSelectOidc = async () => {
    authMethodOpen.value = false;
    await beginOidcConnect();
    if (connectVerification.value) {
      await openExternal(connectVerification.value);
    }
  };

  const handleSelectPassword = () => {
    authMethodOpen.value = false;
    passwordLoginError.value = "";
    passwordLoginOpen.value = true;
  };

  const handlePasswordAuth = async (payload: PasswordAuthPayload) => {
    console.info("[auth] password_handler_start", {
      mode: payload.mode,
      serverUrl: connectServerUrl.value,
      email: payload.email,
    });
    const submitPasswordAuth = async () => {
      passwordLoginBusy.value = true;
      passwordLoginError.value = "";
      try {
        console.info("[auth] password_submit", {
          mode: payload.mode,
          serverUrl: connectServerUrl.value,
          email: payload.email,
        });
        const command =
          payload.mode === "register" ? "password_register" : "password_login";
        const response = await invoke<
          ApiResponse<{
            status: string;
            storage_id?: string | null;
            email?: string | null;
            old_fingerprint?: string | null;
            new_fingerprint?: string | null;
            login_id?: string | null;
          }>
        >(command, {
          serverUrl: connectServerUrl.value,
          email: payload.email,
          password: payload.password,
          fullName: payload.fullName ?? null,
        });
        if (!response.ok || !response.data) {
          const key = response.error?.kind ?? "generic";
          const message = response.error?.message ?? t(`errors.${key}`);
          throw new Error(message);
        }
        const data = response.data;
        if (data.status === "fingerprint_changed") {
          passwordLoginOpen.value = false;
          connectLoginId.value = data.login_id ?? "";
          connectStatus.value = "fingerprint";
          connectOldFp.value = data.old_fingerprint ?? "";
          connectNewFp.value = data.new_fingerprint ?? "";
          return;
        }
        if (data.status === "success") {
          passwordLoginOpen.value = false;
          connectLoginId.value = "";
          const syncStorageId = data.storage_id ?? selectedStorageId.value;
          clearSyncErrors(syncStorageId);
          await refreshAppStatus();
          const needsSetup = !appStatus.value?.initialized;
          if (needsSetup) {
            setupStep.value = "password";
          }
          if (unlocked.value) {
            await runRemoteSync(syncStorageId);
          }
          await runBootstrap();
          if (needsSetup) {
            setupOpen.value = true;
          } else {
            setupOpen.value = false;
            setupStep.value = "welcome";
          }
        }
      } catch (err) {
        passwordLoginError.value = formatError(err);
      } finally {
        passwordLoginBusy.value = false;
      }
    };

    const storage = sessionExpiredStorage.value;
    const hasActiveSession =
      payload.mode === "register" &&
      storage?.kind === StorageKind.Remote &&
      !!storage.account_subject &&
      !showSessionExpiredBanner.value;

    if (hasActiveSession) {
      console.info("[auth] password_register_requires_confirm", {
        currentAccount: storage?.account_subject ?? "",
      });
      openConfirm({
        title: t("auth.registerWillSignOutTitle"),
        message: t("auth.registerWillSignOutDesc", {
          email: storage?.account_subject ?? t("auth.currentAccount"),
        }),
        confirmLabel: t("common.continue"),
        cancelLabel: t("common.cancel"),
        onConfirm: submitPasswordAuth,
      });
      return;
    }

    await submitPasswordAuth();
  };

  const handleOidcStatus = async (payload: {
    login_id: string;
    status: string;
    message?: string | null;
    storage_id?: string | null;
    email?: string | null;
    old_fingerprint?: string | null;
    new_fingerprint?: string | null;
  }) => {
    console.info("[oidc] status event", payload);
    console.info("[oidc] current login id", connectLoginId.value);
    if (!payload.login_id || payload.login_id !== connectLoginId.value) {
      return;
    }
    if (payload.status === "fingerprint_changed") {
      connectStatus.value = "fingerprint";
      connectOldFp.value = payload.old_fingerprint ?? "";
      connectNewFp.value = payload.new_fingerprint ?? "";
      connectBusy.value = false;
      return;
    }
    if (payload.status === "success") {
      connectStatus.value = "success";
      const syncStorageId = payload.storage_id ?? selectedStorageId.value;
      clearSyncErrors(syncStorageId);
      await refreshAppStatus();
      const needsSetup = !appStatus.value?.initialized;
      if (needsSetup) {
        setupStep.value = "password";
      }
      if (unlocked.value) {
        await runRemoteSync(syncStorageId);
      }
      await runBootstrap();
      connectBusy.value = false;
      if (needsSetup) {
        setupOpen.value = true;
      } else {
        setupOpen.value = false;
        setupStep.value = "welcome";
      }
      return;
    }
    if (payload.status === "pending") {
      connectStatus.value = "waiting";
      connectBusy.value = false;
      return;
    }
    connectError.value = payload.message ?? t("errors.generic");
    connectBusy.value = false;
  };

  const trustFingerprint = async () => {
    connectError.value = "";
    try {
      connectBusy.value = true;
      await invoke<ApiResponse<null>>("remote_trust_fingerprint", {
        loginId: connectLoginId.value,
      });
      connectStatus.value = "waiting";
      connectOldFp.value = "";
      connectNewFp.value = "";
      connectBusy.value = false;
    } catch (err) {
      connectError.value = formatError(err);
      connectBusy.value = false;
    }
  };

  const initOidcListener = async () => {
    if (oidcUnlisten) {
      return;
    }
    oidcUnlisten = await listen("oidc-login-status", (event) => {
      const payload = event.payload as {
        login_id: string;
        status: string;
        message?: string | null;
        storage_id?: string | null;
        email?: string | null;
        old_fingerprint?: string | null;
        new_fingerprint?: string | null;
      };
      void handleOidcStatus(payload);
    });
  };

  onMounted(() => {
    void initOidcListener();
  });

  onBeforeUnmount(() => {
    if (oidcUnlisten) {
      oidcUnlisten();
      oidcUnlisten = null;
    }
  });

  return {
    setupStep,
    setupFlow,
    setupOpen,
    setupPassword,
    setupConfirm,
    setupError,
    setupBusy,
    connectServerUrl,
    connectLoginId,
    connectVerification,
    connectStatus,
    connectError,
    connectOldFp,
    connectNewFp,
    connectBusy,
    authMethodOpen,
    availableMethods,
    passwordLoginOpen,
    passwordLoginBusy,
    passwordLoginError,
    normalizeServerUrl,
    startLocalSetup,
    startConnect,
    backToWelcome,
    createMasterPassword,
    showAuthMethodSelection,
    trustFingerprint,
    handleBannerSignIn,
    handleSelectOidc,
    handleSelectPassword,
    handlePasswordAuth,
    handleOidcStatus,
  };
}
