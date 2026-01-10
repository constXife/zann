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
  const selector =
    '//button[normalize-space()="Edit"]/following::button[1]' +
    ' | //button[normalize-space()="Restore"]/following::button[1]';
  await clickByXPath(browser, selector, UI_TIMEOUT, "item action menu");
};

const openItemFromList = async (browser, name, timeout = UI_TIMEOUT) => {
  const selector =
    `//button[.//div[contains(@class,"font-medium") and normalize-space()="${name}"]]`;
  await clickByXPath(browser, selector, timeout, `open item ${name}`);
};

const createKvItem = async (browser, { name, path, key, value }) => {
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
  await waitForButtonByText(browser, "History", UI_TIMEOUT);
  const clicked = await withTimeout(
    browser.execute(() => {
      const buttons = Array.from(document.querySelectorAll("button"));
      const target = buttons.find(
        (btn) => btn.textContent?.includes("History"),
      );
      if (!target) {
        return false;
      }
      target.scrollIntoView({ block: "center", inline: "center" });
      target.click();
      return true;
    }),
    UI_TIMEOUT,
    "history click",
  );
  if (!clicked) {
    throw new Error("History button not found for click.");
  }
  const rangeSelector = "input.time-travel-range";
  await withTimeout(
    browser.$(rangeSelector).then((el) => el.waitForExist({ timeout: UI_TIMEOUT })),
    UI_TIMEOUT,
    "history panel open",
  );
  await waitForButtonByText(browser, "Close history", UI_TIMEOUT);
  await waitForButtonByText(browser, "Restore this version", UI_TIMEOUT);
  await withTimeout(
    browser.execute(() => {
      const slider = document.querySelector("input.time-travel-range");
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
  await clickButtonByText(browser, "Restore this version", UI_TIMEOUT);
  await clickConfirmModalButton(browser, "Restore previous version", "Restore", UI_TIMEOUT);
  const closeSelector =
    `//button[contains(normalize-space(), "Close history")]` +
    ` | //button[.//span[contains(normalize-space(), "Close history")]]`;
  const closeButton = await browser.$(closeSelector);
  if (await closeButton.isExisting()) {
    await clickByXPath(browser, closeSelector, UI_TIMEOUT, "close history");
  } else {
    logStep("History already closed");
  }
};

export {
  createKvItem,
  createLoginItem,
  deleteAndRestoreItem,
  openItemFromList,
  restoreFromHistory,
  updateLoginPassword,
};
