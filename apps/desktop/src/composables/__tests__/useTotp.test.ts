import { render, cleanup } from "@testing-library/vue";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defineComponent, nextTick } from "vue";
import type { TotpFieldData } from "../../types";
import { useTotp } from "../useTotp";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

type TotpApi = ReturnType<typeof useTotp>;

const createWrapper = () => {
  let api: TotpApi | null = null;

  const Wrapper = defineComponent({
    setup() {
      api = useTotp();
      return () => null;
    },
  });

  render(Wrapper);
  return api as TotpApi;
};

const totpData: TotpFieldData = {
  secret: "JBSWY3DPEHPK3PXP",
  algorithm: "SHA1",
  digits: 6,
  period: 2,
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe("useTotp", () => {
  it("fetches and refreshes codes on interval", async () => {
    vi.useFakeTimers();
    const { invoke } = await import("@tauri-apps/api/core");
    (invoke as unknown as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        ok: true,
        data: { code: "123456", remaining_seconds: 2, period: 2 },
      })
      .mockResolvedValueOnce({
        ok: true,
        data: { code: "654321", remaining_seconds: 2, period: 2 },
      });

    const api = createWrapper();
    api.start(totpData);
    await Promise.resolve();
    await nextTick();

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(api.code.value).toBe("123456");
    expect(api.remainingSeconds.value).toBe(2);

    vi.advanceTimersByTime(1000);
    await Promise.resolve();
    expect(api.remainingSeconds.value).toBe(1);

    vi.advanceTimersByTime(1000);
    await Promise.resolve();
    await nextTick();

    expect(invoke).toHaveBeenCalledTimes(2);
    expect(api.code.value).toBe("654321");

    api.stop();
  });
});
