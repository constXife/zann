import {
  clickButtonByText,
  clickWhenReady,
  setInputValueForElement,
} from "./tauri.e2e.utils.mjs";
import { UI_TIMEOUT } from "./tauri.e2e.config.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const debugUiEnabled = process.env.TAURI_E2E_DEBUG_UI === "1";
const debugIntervalMs = Number(process.env.TAURI_E2E_DEBUG_UI_INTERVAL_MS ?? 2000);
const elementTimeoutMs = Number(process.env.TAURI_E2E_ELEMENT_TIMEOUT_MS ?? 1000);

if (debugUiEnabled) {
  console.log("[e2e] auth debug enabled");
}

const getElement = async (browser, selector, label) => {
  let timer;
  try {
    return await Promise.race([
      browser.$(selector),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`element lookup timed out: ${label}`));
        }, elementTimeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const elementExists = async (element, label) => {
  let timer;
  try {
    return await Promise.race([
      element.isExisting(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`element check timed out: ${label}`));
        }, elementTimeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const ensureAuthFlow = async (browser) => {
  const passwordMethod = await getElement(
    browser,
    '[data-testid="auth-method-password"]',
    "auth-method-password",
  );
  const authToggle = await getElement(browser, '[data-testid="auth-toggle"]', "auth-toggle");
  const connectError = await getElement(
    browser,
    '[data-testid="wizard-connect-error"]',
    "wizard-connect-error",
  );
  const connectWaiting = await getElement(
    browser,
    '[data-testid="wizard-connect-waiting"]',
    "wizard-connect-waiting",
  );
  const connectBusy = await getElement(
    browser,
    '[data-testid="wizard-connect-busy"]',
    "wizard-connect-busy",
  );
  const startedAt = Date.now();
  let nextDebugAt = startedAt + debugIntervalMs;

  while (Date.now() - startedAt < UI_TIMEOUT) {
    if (debugUiEnabled && Date.now() >= nextDebugAt) {
      nextDebugAt = Date.now() + debugIntervalMs;
      let bodyText = "";
      let debugError = "";
      try {
        const body = await browser.$("body");
        if (await elementExists(body, "body")) {
          bodyText = await body.getText();
        }
      } catch (error) {
        debugError = String(error);
      }
      const title = await browser.getTitle().catch(() => "");
      let connectErrorExists = false;
      let connectWaitingExists = false;
      let connectBusyExists = false;
      let authToggleExists = false;
      let passwordMethodExists = false;
      try {
        connectErrorExists = await elementExists(connectError, "wizard-connect-error");
        connectWaitingExists = await elementExists(connectWaiting, "wizard-connect-waiting");
        connectBusyExists = await elementExists(connectBusy, "wizard-connect-busy");
        authToggleExists = await elementExists(authToggle, "auth-toggle");
        passwordMethodExists = await elementExists(passwordMethod, "auth-method-password");
      } catch (error) {
        debugError = debugError ? `${debugError}; ${error}` : String(error);
      }
      const status = {
        title,
        connectError: connectErrorExists,
        connectWaiting: connectWaitingExists,
        connectBusy: connectBusyExists,
        authToggle: authToggleExists,
        passwordMethod: passwordMethodExists,
        body: bodyText.slice(0, 200),
        error: debugError || undefined,
      };
      console.log(`[e2e] auth debug: ${JSON.stringify(status)}`);
    }
    if (await elementExists(connectError, "wizard-connect-error")) {
      const errorText = await connectError.getText();
      throw new Error(`Connect error: ${errorText}`);
    }
    if (await elementExists(connectWaiting, "wizard-connect-waiting")) {
      throw new Error("Connect waiting for approval (OIDC flow detected)");
    }
    if (
      (await elementExists(passwordMethod, "auth-method-password")) ||
      (await elementExists(authToggle, "auth-toggle"))
    ) {
      if (await elementExists(passwordMethod, "auth-method-password")) {
        await clickWhenReady(browser, '[data-testid="auth-method-password"]');
      }
      return;
    }
    if (await elementExists(connectBusy, "wizard-connect-busy")) {
      throw new Error("Connect still processing (server did not respond)");
    }
    await sleep(500);
  }

  throw new Error("Auth flow timed out");
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
