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
  withTimeout,
  waitForTitle,
} from "./tauri.e2e.utils.mjs";
import {
  ensureAuthFlow,
  ensureAuthMode,
  maybeUnlock,
} from "./tauri.e2e.auth.mjs";
import {
  setCloseToTray,
  expectCloseToTray,
} from "./tauri.e2e.settings.mjs";
import {
  createKvItem,
  createKvItemExpectError,
  createLoginItem,
  deleteAndRestoreItem,
  openItemFromList,
  restoreFromHistory,
  updateLoginPassword,
} from "./tauri.e2e.items.mjs";

const localOnlyScenario = async (browser) => {
  logStep("Waiting for title");
  await waitForTitle(browser);

  const startLocalButton = await browser.$('[data-testid="wizard-start-local"]');
  if (await startLocalButton.isExisting()) {
    logStep("Start local setup");
    await clickWhenReady(browser, '[data-testid="wizard-start-local"]', UI_TIMEOUT);

    const masterPasswordInput = await browser.$('[data-testid="wizard-master-password"]');
    await masterPasswordInput.waitForExist({ timeout: UI_TIMEOUT });
    logStep("Create master password");
    await setInputValue(browser, '[data-testid="wizard-master-password"]', loginPassword, UI_TIMEOUT);
    await setInputValue(browser, '[data-testid="wizard-master-confirm"]', loginPassword, UI_TIMEOUT);
    await clickWhenReady(browser, '[data-testid="wizard-master-create"]', UI_TIMEOUT);
    await browser
      .$('[data-testid="wizard-master-password"]')
      .waitForExist({ reverse: true, timeout: UI_TIMEOUT });
  } else {
    await maybeUnlock(browser, loginPassword);
  }

  logStep("Open storage menu");
  await clickWhenReady(browser, '[data-testid="storage-dropdown-toggle"]', UI_TIMEOUT);

  let createLocalVaultButton = await browser.$('[data-testid="storage-create-local-vault"]');
  let localEntryButton = await browser.$('[data-testid="storage-local-entry"]');
  if (!(await createLocalVaultButton.isExisting()) && !(await localEntryButton.isExisting())) {
    await clickWhenReady(browser, '[data-testid="storage-dropdown-toggle"]', UI_TIMEOUT);
    createLocalVaultButton = await browser.$('[data-testid="storage-create-local-vault"]');
    localEntryButton = await browser.$('[data-testid="storage-local-entry"]');
  }
  if (await createLocalVaultButton.isExisting()) {
    logStep("Create local vault");
    await clickWhenReady(browser, '[data-testid="storage-create-local-vault"]', UI_TIMEOUT);

    const vaultNameInput = await browser.$('[data-testid="create-vault-name"]');
    try {
      await withTimeout(
        vaultNameInput.waitForExist({ timeout: UI_TIMEOUT }),
        UI_TIMEOUT + 2000,
        "local vault modal",
      );
    } catch (error) {
      const bodyText = await getBodyText(browser);
      throw new Error(
        `Local vault modal not visible: ${bodyText.slice(0, 400)}`,
      );
    }
    logStep("Local vault modal ready");
    logStep("Fill local vault name");
    await setInputValue(browser, '[data-testid="create-vault-name"]', "Local Vault", UI_TIMEOUT);
    logStep("Submit local vault");
    const submitButton = await browser.$('[data-testid="create-submit"]');
    await submitButton.waitForExist({ timeout: UI_TIMEOUT });
    const isDisabled = await submitButton.getAttribute("disabled");
    if (isDisabled !== null) {
      const bodyText = await getBodyText(browser);
      throw new Error(`Create vault submit disabled: ${bodyText.slice(0, 400)}`);
    }
    await clickWhenReady(browser, '[data-testid="create-submit"]', UI_TIMEOUT);
    const modalSelector = '[data-testid="create-vault-name"]';
    logStep("Waiting for local vault modal to close");
    try {
      await withTimeout(
        browser.$(modalSelector).then((el) =>
          el.waitForExist({ reverse: true, timeout: UI_TIMEOUT }),
        ),
        UI_TIMEOUT + 2000,
        "local vault modal close",
      );
    } catch (error) {
      const createError = await browser.$('[data-testid="create-error"]');
      if (await createError.isExisting()) {
        const errorText = await createError.getText();
        throw new Error(`Create vault error: ${errorText}`);
      }
      const bodyText = await getBodyText(browser);
      throw new Error(
        `Local vault modal did not close: ${bodyText.slice(0, 400)}`,
      );
    }
  } else if (await localEntryButton.isExisting()) {
    logStep("Select local vault");
    await clickWhenReady(browser, '[data-testid="storage-local-entry"]', UI_TIMEOUT);
  }

  const storageToggle = await browser.$('[data-testid="storage-dropdown-toggle"]');
  const storageText = await storageToggle.getText();
  if (!storageText.toLowerCase().includes("local vault")) {
    throw new Error(`Expected local storage context, got "${storageText}"`);
  }

  const offlineBanner = await browser.$('[data-testid="offline-banner"]');
  if (await offlineBanner.isExisting()) {
    const bodyText = await getBodyText(browser);
    throw new Error(`Unexpected offline banner in local-only flow: ${bodyText.slice(0, 400)}`);
  }
  const syncErrorBanner = await browser.$('[data-testid="sync-error-banner"]');
  if (await syncErrorBanner.isExisting()) {
    const bodyText = await getBodyText(browser);
    throw new Error(`Unexpected sync error banner in local-only flow: ${bodyText.slice(0, 400)}`);
  }

  logStep("Create KV item");
  await createKvItem(browser, {
    name: "kv-local",
    path: "local",
    key: "foo",
    value: "bar",
    vaultName: "Local Vault",
  });

  await openItemFromList(browser, "kv-local");
  logStep("KV item created");

  logStep("Reject duplicate item name");
  await createKvItemExpectError(browser, {
    name: "kv-local",
    path: "local",
    key: "dup",
    value: "dup",
  });
  await clickWhenReady(browser, '[data-testid="create-cancel"]', UI_TIMEOUT);

  const pendingIcon = await browser.$('[data-testid="item-sync-pending"]');
  if (await pendingIcon.isExisting()) {
    const bodyText = await getBodyText(browser);
    throw new Error(`Unexpected sync pending icon in local-only flow: ${bodyText.slice(0, 400)}`);
  }

  logStep("Delete and restore KV item");
  await deleteAndRestoreItem(browser, "kv-local");

  logStep("Create login item");
  await createLoginItem(browser, {
    name: "login-local",
    path: "local",
    username: "user@example.com",
    password: "OldPass123!",
  });
  await openItemFromList(browser, "login-local");

  logStep("Change password");
  await updateLoginPassword(browser, "NewPass456!");

  logStep("Restore previous version from history");
  await restoreFromHistory(browser);
};

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
    logStep("Wait for auth outcome");
    await withTimeout(ensureAuthFlow(browser), UI_TIMEOUT + 2000, "auth outcome");
  } catch (error) {
    const bodyText = await getBodyText(browser);
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Auth flow not visible: ${message}; ${bodyText.slice(0, 400)}`);
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

  logStep("Toggle close-to-tray setting");
  await setCloseToTray(browser, false);
  await expectCloseToTray(browser, false);
  await setCloseToTray(browser, true);
  await expectCloseToTray(browser, true);

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
      await withTimeout(ensureAuthFlow(browser), UI_TIMEOUT + 2000, "auth outcome");
    } catch (error) {
      const bodyText = await getBodyText(browser);
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Auth flow not visible: ${message}; ${bodyText.slice(0, 400)}`);
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
  localOnlyScenario,
  registerAndCreateKvScenario,
  reloginAndRestoreScenario,
};
