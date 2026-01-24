import { render, fireEvent, screen, cleanup } from "@testing-library/vue";
import { defineComponent, ref } from "vue";
import { describe, it, expect, vi, afterEach } from "vitest";
import SetupWizardModal from "../SetupWizardModal.vue";

const renderModal = (options?: {
  connectServerUrl?: string;
  connectError?: string;
}) => {
  const connectServerUrl = options?.connectServerUrl ?? "";
  const connectError = options?.connectError ?? "";

  const Wrapper = defineComponent({
    components: { SetupWizardModal },
    setup() {
      const step = ref<"welcome" | "password" | "connect">("connect");
      const flow = ref<"local" | "remote">("remote");
      const setupPassword = ref("");
      const setupConfirm = ref("");
      const connectUrl = ref(connectServerUrl);

      return {
        step,
        flow,
        setupPassword,
        setupConfirm,
        connectUrl,
        connectError,
        t: (key: string) => key,
        normalizeServerUrl: (value: string) =>
          value.startsWith("https://") ? value : `https://${value}`,
        startLocalSetup: vi.fn(),
        startConnect: vi.fn(),
        backToWelcome: vi.fn(),
        createMasterPassword: vi.fn(),
        beginServerConnect: vi.fn(),
        trustFingerprint: vi.fn(),
        openExternal: vi.fn(),
        copyToClipboard: vi.fn(),
      };
    },
    template: `
      <SetupWizardModal
        :open="true"
        v-model:step="step"
        v-model:flow="flow"
        v-model:setup-password="setupPassword"
        v-model:setup-confirm="setupConfirm"
        v-model:connect-server-url="connectUrl"
        password-mode="create"
        logo-url="/logo.png"
        setup-error=""
        :setup-busy="false"
        connect-verification=""
        connect-status=""
        :connect-error="connectError"
        connect-old-fp=""
        connect-new-fp=""
        :connect-busy="false"
        connect-login-id=""
        :t="t"
        :normalize-server-url="normalizeServerUrl"
        :start-local-setup="startLocalSetup"
        :start-connect="startConnect"
        :back-to-welcome="backToWelcome"
        :create-master-password="createMasterPassword"
        :begin-server-connect="beginServerConnect"
        :trust-fingerprint="trustFingerprint"
        :open-external="openExternal"
        :copy-to-clipboard="copyToClipboard"
      />
    `,
  });

  return render(Wrapper, {
    global: {
      stubs: {
        "font-awesome-icon": true,
      },
    },
  });
};

describe("SetupWizardModal", () => {
  afterEach(() => {
    cleanup();
  });

  it("prefills the server url when focusing an empty field", async () => {
    renderModal({ connectServerUrl: "" });
    const input = screen.getByPlaceholderText(
      "wizard.connectPlaceholder",
    ) as HTMLInputElement;

    await fireEvent.focus(input);

    expect(input.value).toBe("https://");
  });

  it("shows connect error messages", () => {
    renderModal({ connectError: "boom" });
    expect(screen.getByText("boom")).toBeTruthy();
  });

  it("normalizes the url on blur", async () => {
    renderModal({ connectServerUrl: "example.com" });
    const input = screen.getByPlaceholderText(
      "wizard.connectPlaceholder",
    ) as HTMLInputElement;

    await fireEvent.blur(input);

    expect(input.value).toBe("https://example.com");
  });
});
