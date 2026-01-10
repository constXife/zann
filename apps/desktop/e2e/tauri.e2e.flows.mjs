import assert from "node:assert/strict";
import {
  fixture,
  loginPassword,
  serverUrl,
  UI_TIMEOUT,
} from "./tauri.e2e.config.mjs";
import {
  clickWhenReady,
  getBodyText,
  logStep,
  setInputValue,
  waitForTitle,
} from "./tauri.e2e.utils.mjs";
import {
  ensureAuthFlow,
  ensureAuthMode,
  maybeUnlock,
} from "./tauri.e2e.auth.mjs";
import {
  createKvItem,
  createLoginItem,
  deleteAndRestoreItem,
  openItemFromList,
  restoreFromHistory,
  updateLoginPassword,
} from "./tauri.e2e.items.mjs";

const registerAndCreateKvScenario = async (browser) => {
  logStep("Waiting for title");
  await waitForTitle(browser);

  const title = await browser.getTitle();
  assert.equal(title, "Zann Desktop");
  logStep("Title OK");

  logStep("Click connect");
  await clickWhenReady(browser, '[data-testid="wizard-connect"]', UI_TIMEOUT);

  const serverInput = await browser.$('[data-testid="wizard-server-url"]');
  await serverInput.waitForExist({ timeout: UI_TIMEOUT });
  logStep("Set server URL");
  await setInputValue(browser, '[data-testid="wizard-server-url"]', serverUrl, UI_TIMEOUT);
  const normalizedValue = await serverInput.getValue();
  if (!normalizedValue.startsWith("http://")) {
    throw new Error(`Unexpected server URL value: ${normalizedValue}`);
  }

  logStep("Click sign in");
  await clickWhenReady(browser, '[data-testid="wizard-sign-in"]', UI_TIMEOUT);

  try {
    await ensureAuthFlow(browser);
  } catch (error) {
    const bodyText = await getBodyText(browser);
    throw new Error(`Auth flow not visible: ${bodyText.slice(0, 400)}`);
  }

  logStep("Ensure register mode");
  await ensureAuthMode(browser, "register");

  const fullNameInput = await browser.$('[data-testid="auth-full-name"]');
  await fullNameInput.waitForExist({ timeout: UI_TIMEOUT });
  logStep("Fill registration form");
  await setInputValue(browser, '[data-testid="auth-full-name"]', "E2E User", UI_TIMEOUT);

  fixture.loginEmail = `e2e-${Date.now()}@example.com`;
  await setInputValue(browser, '[data-testid="auth-email"]', fixture.loginEmail, UI_TIMEOUT);

  await setInputValue(browser, '[data-testid="auth-password"]', loginPassword, UI_TIMEOUT);
  await setInputValue(browser, '[data-testid="auth-confirm"]', loginPassword, UI_TIMEOUT);

  logStep("Submit registration");
  await clickWhenReady(browser, '[data-testid="auth-submit"]', UI_TIMEOUT);
  await browser.$('[data-testid="auth-submit"]').waitForExist({ reverse: true, timeout: UI_TIMEOUT });

  const masterPasswordInput = await browser.$('[data-testid="wizard-master-password"]');
  try {
    await masterPasswordInput.waitForExist({ timeout: UI_TIMEOUT });
    logStep("Create master password");
    await setInputValue(browser, '[data-testid="wizard-master-password"]', loginPassword, UI_TIMEOUT);
    await setInputValue(browser, '[data-testid="wizard-master-confirm"]', loginPassword, UI_TIMEOUT);
    await clickWhenReady(browser, '[data-testid="wizard-master-create"]', UI_TIMEOUT);
    await browser
      .$('[data-testid="wizard-master-password"]')
      .waitForExist({ reverse: true, timeout: UI_TIMEOUT });
  } catch (error) {
    if (!(await masterPasswordInput.isExisting())) {
      // Already initialized on this client.
    } else {
      throw error;
    }
  }

  logStep("Create KV item");
  await createKvItem(browser, {
    name: "kv-first",
    path: "test",
    key: "foo",
    value: "bar",
  });

  await openItemFromList(browser, "kv-first");
  logStep("KV item created");

  logStep("Delete and restore KV item");
  await deleteAndRestoreItem(browser, "kv-first");
};

const reloginAndRestoreScenario = async (browser) => {
  assert.ok(fixture.loginEmail, "fixture loginEmail is required; run registration first.");
  logStep("Waiting for title");
  await waitForTitle(browser);

  logStep("Connect to server");
  const wizardConnect = await browser.$('[data-testid="wizard-connect"]');
  if (await wizardConnect.isExisting()) {
    logStep("Click connect");
    await clickWhenReady(browser, '[data-testid="wizard-connect"]', UI_TIMEOUT);

    const serverInput = await browser.$('[data-testid="wizard-server-url"]');
    await serverInput.waitForExist({ timeout: UI_TIMEOUT });
    logStep("Set server URL");
    await setInputValue(browser, '[data-testid="wizard-server-url"]', serverUrl, UI_TIMEOUT);

    logStep("Click sign in");
    await clickWhenReady(browser, '[data-testid="wizard-sign-in"]', UI_TIMEOUT);
  }

  const authToggle = await browser.$('[data-testid="auth-toggle"]');
  const authPassword = await browser.$('[data-testid="auth-password"]');
  if (await authToggle.isExisting() || await authPassword.isExisting()) {
    try {
      await ensureAuthFlow(browser);
    } catch (error) {
      const bodyText = await getBodyText(browser);
      throw new Error(`Auth flow not visible: ${bodyText.slice(0, 400)}`);
    }

    logStep("Ensure login mode");
    await ensureAuthMode(browser, "login");

  await setInputValue(browser, '[data-testid="auth-email"]', fixture.loginEmail, UI_TIMEOUT);
  await setInputValue(browser, '[data-testid="auth-password"]', loginPassword, UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="auth-submit"]', UI_TIMEOUT);
  }

  await maybeUnlock(browser, loginPassword);

  logStep("Create KV item");
  await createKvItem(browser, {
    name: "kv-second",
    path: "test",
    key: "alpha",
    value: "beta",
  });

  logStep("Delete and restore KV item");
  await deleteAndRestoreItem(browser, "kv-second");

  logStep("Create login item");
  await createLoginItem(browser, {
    name: "login-item",
    path: "test",
    username: "user@example.com",
    password: "OldPass123!",
  });
  await openItemFromList(browser, "login-item");

  logStep("Change password");
  await updateLoginPassword(browser, "NewPass456!");

  logStep("Restore previous version from history");
  await restoreFromHistory(browser);
};

export {
  registerAndCreateKvScenario,
  reloginAndRestoreScenario,
};
