import {
  clickButtonByText,
  clickWhenReady,
  setInputValueForElement,
} from "./tauri.e2e.utils.mjs";
import { UI_TIMEOUT } from "./tauri.e2e.config.mjs";

const ensureAuthFlow = async (browser) => {
  const passwordMethod = await browser.$('[data-testid="auth-method-password"]');
  const authToggle = await browser.$('[data-testid="auth-toggle"]');
  await browser.waitUntil(
    async () => (await passwordMethod.isExisting()) || (await authToggle.isExisting()),
    { timeout: UI_TIMEOUT, interval: 500 },
  );
  if (await passwordMethod.isExisting()) {
    await clickWhenReady(browser, '[data-testid="auth-method-password"]');
  }
};

const ensureAuthMode = async (browser, mode) => {
  const fullNameInput = await browser.$('[data-testid="auth-full-name"]');
  const isRegister = await fullNameInput.isExisting();
  if (mode === "register" && !isRegister) {
    await clickWhenReady(browser, '[data-testid="auth-toggle"]');
  }
  if (mode === "login" && isRegister) {
    await clickWhenReady(browser, '[data-testid="auth-toggle"]');
  }
};

const maybeUnlock = async (browser, password) => {
  const input = await browser.$('input[placeholder="Master password"]');
  if (await input.isExisting()) {
    await setInputValueForElement(browser, input, password, 20000, "master password");
    await clickButtonByText(browser, "Unlock", 20000);
  }
};

export {
  ensureAuthFlow,
  ensureAuthMode,
  maybeUnlock,
};
