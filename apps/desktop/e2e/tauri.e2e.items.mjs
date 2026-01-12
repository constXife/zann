import {
  clickButtonByText,
  clickByXPath,
  clickConfirmModalButton,
  clickWhenReady,
  logStep,
  setInputValue,
  setInputValueByLabel,
  withTimeout,
  waitForButtonByText,
} from "./tauri.e2e.utils.mjs";
import { UI_TIMEOUT } from "./tauri.e2e.config.mjs";

const openItemActionMenu = async (browser) => {
  await clickWhenReady(browser, '[data-testid="item-action-menu"]', UI_TIMEOUT);
};

const openItemFromList = async (browser, name, timeout = UI_TIMEOUT) => {
  const selector =
    `//button[.//div[contains(@class,"font-medium") and normalize-space()="${name}"]]`;
  await clickByXPath(browser, selector, timeout, `open item ${name}`);
};

const createKvItem = async (browser, { name, path, key, value, vaultName }) => {
  await clickWhenReady(browser, '[data-testid="item-create"]', UI_TIMEOUT);
  if (vaultName) {
    const vaultLabel = await browser.$('[data-testid="create-vault-label"]');
    await vaultLabel.waitForExist({ timeout: UI_TIMEOUT });
    const labelText = await vaultLabel.getText();
    if (!labelText.includes(vaultName)) {
      throw new Error(`Expected vault label to include "${vaultName}", got "${labelText}"`);
    }
  }
  await clickWhenReady(browser, '[data-testid="create-type-menu"]', UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="create-type-kv"]', UI_TIMEOUT);

  const pathInput = await browser.$('[data-testid="create-path"]');
  await pathInput.waitForExist({ timeout: UI_TIMEOUT });
  await setInputValue(browser, '[data-testid="create-path"]', path, UI_TIMEOUT);

  const nameInput = await browser.$('[data-testid="create-name"]');
  await nameInput.waitForExist({ timeout: UI_TIMEOUT });
  await setInputValue(browser, '[data-testid="create-name"]', name, UI_TIMEOUT);

  await setInputValue(browser, '[data-testid="kv-key-0"]', key, UI_TIMEOUT);
  await setInputValue(browser, '[data-testid="kv-value-0"]', value, UI_TIMEOUT);

  await clickWhenReady(browser, '[data-testid="create-submit"]', UI_TIMEOUT);
};

const createKvItemExpectError = async (browser, { name, path, key, value }) => {
  await clickWhenReady(browser, '[data-testid="item-create"]', UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="create-type-menu"]', UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="create-type-kv"]', UI_TIMEOUT);

  const pathInput = await browser.$('[data-testid="create-path"]');
  await pathInput.waitForExist({ timeout: UI_TIMEOUT });
  await setInputValue(browser, '[data-testid="create-path"]', path, UI_TIMEOUT);

  const nameInput = await browser.$('[data-testid="create-name"]');
  await nameInput.waitForExist({ timeout: UI_TIMEOUT });
  await setInputValue(browser, '[data-testid="create-name"]', name, UI_TIMEOUT);

  await setInputValue(browser, '[data-testid="kv-key-0"]', key, UI_TIMEOUT);
  await setInputValue(browser, '[data-testid="kv-value-0"]', value, UI_TIMEOUT);

  await clickWhenReady(browser, '[data-testid="create-submit"]', UI_TIMEOUT);
  await withTimeout(
    browser
      .$('[data-testid="create-error"]')
      .then((el) => el.waitForExist({ timeout: UI_TIMEOUT })),
    UI_TIMEOUT,
    "create error",
  );
};

const createLoginItem = async (browser, { name, path, username, password }) => {
  await clickWhenReady(browser, '[data-testid="item-create"]', UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="create-type-menu"]', UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="create-type-login"]', UI_TIMEOUT);

  const pathInput = await browser.$('[data-testid="create-path"]');
  await pathInput.waitForExist({ timeout: UI_TIMEOUT });
  await setInputValue(browser, '[data-testid="create-path"]', path, UI_TIMEOUT);

  const nameInput = await browser.$('[data-testid="create-name"]');
  await nameInput.waitForExist({ timeout: UI_TIMEOUT });
  await setInputValue(browser, '[data-testid="create-name"]', name, UI_TIMEOUT);

  await setInputValueByLabel(browser, "Username", username, UI_TIMEOUT);
  await setInputValueByLabel(browser, "Password", password, UI_TIMEOUT);

  await clickWhenReady(browser, '[data-testid="create-submit"]', UI_TIMEOUT);
};

const deleteAndRestoreItem = async (browser, name) => {
  await openItemFromList(browser, name);
  await openItemActionMenu(browser);
  await clickButtonByText(browser, "Move to Trash", UI_TIMEOUT);
  await clickConfirmModalButton(browser, "Move to Trash", "Move to Trash", UI_TIMEOUT);

  await clickButtonByText(browser, "Trash", UI_TIMEOUT);
  await openItemFromList(browser, name);
  await clickButtonByText(browser, "Restore", UI_TIMEOUT);

  await clickButtonByText(browser, "All items", UI_TIMEOUT);
};

const updateLoginPassword = async (browser, nextPassword) => {
  await clickButtonByText(browser, "Edit", UI_TIMEOUT);
  await setInputValueByLabel(browser, "Password", nextPassword, UI_TIMEOUT);
  await clickWhenReady(browser, '[data-testid="create-submit"]', UI_TIMEOUT);
};

const restoreFromHistory = async (browser) => {
  const resolveButton = await browser.$(
    '//button[contains(normalize-space(), "Resolve conflict")]',
  );
  if (await resolveButton.isExisting()) {
    logStep("Resolve conflict");
    await clickButtonByText(browser, "Resolve conflict", UI_TIMEOUT);
  }

  logStep("Open history");
  await clickWhenReady(browser, '[data-testid="history-toggle"]', UI_TIMEOUT);
  await withTimeout(
    browser
      .$('[data-testid="history-panel"]')
      .then((el) => el.waitForExist({ timeout: UI_TIMEOUT })),
    UI_TIMEOUT,
    "history panel open",
  );
  await withTimeout(
    browser
      .$('[data-testid="history-restore"]')
      .then((el) => el.waitForExist({ timeout: UI_TIMEOUT })),
    UI_TIMEOUT,
    "history restore ready",
  );
  await withTimeout(
    browser.execute(() => {
      const slider = document.querySelector('[data-testid="history-slider"]');
      if (!slider) {
        return;
      }
      slider.value = "0";
      slider.dispatchEvent(new Event("input", { bubbles: true }));
    }),
    UI_TIMEOUT,
    "history slider",
  );
  logStep("Apply history restore");
  await clickWhenReady(browser, '[data-testid="history-restore"]', UI_TIMEOUT);
  await clickConfirmModalButton(browser, "Restore previous version", "Restore", UI_TIMEOUT);
  const historyToggle = await browser.$('[data-testid="history-toggle"]');
  const state = await historyToggle.getAttribute("data-state");
  if (state === "open") {
    await clickWhenReady(browser, '[data-testid="history-toggle"]', UI_TIMEOUT);
    await withTimeout(
      browser
        .$('[data-testid="history-panel"]')
        .then((el) => el.waitForExist({ timeout: UI_TIMEOUT, reverse: true })),
      UI_TIMEOUT,
      "history panel close",
    );
  } else {
    logStep("History already closed");
  }
};

export {
  createKvItemExpectError,
  createKvItem,
  createLoginItem,
  deleteAndRestoreItem,
  openItemFromList,
  restoreFromHistory,
  updateLoginPassword,
};
