type TokenOptions = {
  allowSlash?: boolean;
};

const isAllowedTokenChar = (char: string, options?: TokenOptions) =>
  /[A-Za-z0-9_-]/.test(char) || (options?.allowSlash && char === "/");

export const sanitizeToken = (value: string, options?: TokenOptions) =>
  value
    .split("")
    .filter((char) => isAllowedTokenChar(char, options))
    .join("");

export const allowTokenKeydown = (event: KeyboardEvent, options?: TokenOptions) => {
  if (event.isComposing || event.ctrlKey || event.metaKey || event.altKey) {
    return;
  }
  if (event.key.length !== 1) {
    return;
  }
  if (!isAllowedTokenChar(event.key, options)) {
    event.preventDefault();
  }
};

export const allowTokenBeforeInput = (event: InputEvent, options?: TokenOptions) => {
  if (event.isComposing || event.inputType?.startsWith("delete")) {
    return;
  }
  const data = event.data ?? "";
  if (!data) return;
  for (const char of data) {
    if (!isAllowedTokenChar(char, options)) {
      event.preventDefault();
      return;
    }
  }
};

export const handleTokenPaste = (event: ClipboardEvent, options?: TokenOptions) => {
  const text = event.clipboardData?.getData("text") ?? "";
  const sanitized = sanitizeToken(text, options);
  if (sanitized === text) {
    return;
  }
  event.preventDefault();
  const input = event.target as HTMLInputElement | null;
  if (!input) return;
  const start = input.selectionStart ?? input.value.length;
  const end = input.selectionEnd ?? input.value.length;
  const next = `${input.value.slice(0, start)}${sanitized}${input.value.slice(end)}`;
  input.value = next;
  const cursor = start + sanitized.length;
  input.setSelectionRange(cursor, cursor);
  input.dispatchEvent(new Event("input", { bubbles: true }));
};
