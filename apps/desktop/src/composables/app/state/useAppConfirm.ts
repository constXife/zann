import { ref, watch } from "vue";

type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => Promise<void> | void;
  confirmInputExpected?: string;
  confirmInputLabel?: string;
  confirmInputPlaceholder?: string;
};

export function useAppConfirm() {
  const confirmOpen = ref(false);
  const confirmTitle = ref("");
  const confirmMessage = ref("");
  const confirmConfirmLabel = ref("");
  const confirmCancelLabel = ref("");
  const confirmBusy = ref(false);
  const confirmInputExpected = ref("");
  const confirmInputLabel = ref("");
  const confirmInputPlaceholder = ref("");
  let confirmAction: (() => Promise<void> | void) | null = null;

  const openConfirm = (options: ConfirmOptions) => {
    confirmTitle.value = options.title;
    confirmMessage.value = options.message;
    confirmConfirmLabel.value = options.confirmLabel;
    confirmCancelLabel.value = options.cancelLabel ?? "";
    confirmInputExpected.value = options.confirmInputExpected ?? "";
    confirmInputLabel.value = options.confirmInputLabel ?? "";
    confirmInputPlaceholder.value = options.confirmInputPlaceholder ?? "";
    confirmAction = options.onConfirm;
    confirmOpen.value = true;
  };

  const handleConfirm = async () => {
    if (!confirmAction) {
      confirmOpen.value = false;
      return;
    }
    confirmBusy.value = true;
    try {
      await confirmAction();
      confirmOpen.value = false;
    } finally {
      confirmBusy.value = false;
    }
  };

  watch(confirmOpen, (open) => {
    if (!open) {
      confirmAction = null;
      confirmTitle.value = "";
      confirmMessage.value = "";
      confirmConfirmLabel.value = "";
      confirmCancelLabel.value = "";
      confirmInputExpected.value = "";
      confirmInputLabel.value = "";
      confirmInputPlaceholder.value = "";
    }
  });

  return {
    confirmOpen,
    confirmTitle,
    confirmMessage,
    confirmConfirmLabel,
    confirmCancelLabel,
    confirmBusy,
    confirmInputExpected,
    confirmInputLabel,
    confirmInputPlaceholder,
    openConfirm,
    handleConfirm,
  };
}
