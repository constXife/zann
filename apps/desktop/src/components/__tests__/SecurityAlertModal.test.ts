import { render, screen } from "@testing-library/vue";
import { describe, it, expect, afterEach } from "vitest";
import { cleanup } from "@testing-library/vue";
import { defineComponent, ref } from "vue";
import SecurityAlertModal from "../SecurityAlertModal.vue";

const renderModal = (openValue = true) => {
  const Wrapper = defineComponent({
    components: { SecurityAlertModal },
    setup() {
      const open = ref(openValue);
      return {
        open,
        title: "Security alert",
        message: "Critical security error",
        t: (key: string) => key,
      };
    },
    template: `
      <SecurityAlertModal
        v-model:open="open"
        :title="title"
        :message="message"
        :t="t"
      />
    `,
  });

  return render(Wrapper);
};

afterEach(() => {
  cleanup();
});

describe("SecurityAlertModal", () => {
  it("renders when open", () => {
    renderModal(true);
    expect(screen.getByText("Security alert")).toBeTruthy();
    expect(screen.getByText("Critical security error")).toBeTruthy();
  });

  it("does not render when closed", () => {
    renderModal(false);
    expect(screen.queryByText("Security alert")).toBeNull();
  });
});
