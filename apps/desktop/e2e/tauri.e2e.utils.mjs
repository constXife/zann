import { UI_TIMEOUT } from "./tauri.e2e.config.mjs";

const TIMEOUT_SLACK = Number(process.env.TAURI_E2E_TIMEOUT_SLACK ?? 0);

const logStep = (message) => {
  if (globalThis.__e2eTimedOut) {
    throw new Error("e2e timed out");
  }
  globalThis.__e2eLastStep = message;
  console.log(`[e2e] ${message}`);
};

const getBodyText = async (browser) => {
  try {
    const body = await browser.$("body");
    if (await body.isExisting()) {
      return await body.getText();
    }
  } catch {}
  return "";
};

const withTimeout = async (promiseOrFactory, timeoutMs, label) => {
  const forced = Number(process.env.TAURI_E2E_FORCE_TIMEOUT_MS ?? 0);
  const effectiveTimeout = forced > 0 ? forced : timeoutMs;
  if (forced > 0) {
    console.log(`[e2e] force-timeout ${label}: ${effectiveTimeout}ms`);
  }
  const controller = typeof promiseOrFactory === "function" ? new AbortController() : null;
  const work =
    typeof promiseOrFactory === "function"
      ? promiseOrFactory(controller.signal)
      : promiseOrFactory;
  let timer;
  try {
    return await Promise.race([
      work,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          globalThis.__e2eTimedOut = true;
          if (controller) {
            controller.abort();
          }
          const lastStep = globalThis.__e2eLastStep;
          const lastStepInfo = lastStep ? ` (last step: ${lastStep})` : "";
          const error = new Error(
            `${label} timed out after ${effectiveTimeout}ms${lastStepInfo}`,
          );
          globalThis.__e2eTimeoutError = error;
          console.log(`[e2e] timeout fired: ${label}${lastStepInfo}`);
          if (process.env.TAURI_E2E_FORCE_EXIT_ON_TIMEOUT === "1") {
            process.exit(1);
          }
          reject(error);
        }, effectiveTimeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const scrollElementIntoView = async (browser, element) => {
  await browser.execute((target) => {
    if (!target) {
      return;
    }
    target.scrollIntoView({ block: "center", inline: "center" });
  }, element);
};

const scrollIntoView = async (browser, selector) => {
  await browser.execute((sel) => {
    const target = document.querySelector(sel);
    if (!target) {
      return;
    }
    target.scrollIntoView({ block: "center", inline: "center" });
  }, selector);
};

const clickByXPath = async (browser, selector, timeout = UI_TIMEOUT, label = selector) => {
  return await withTimeout(
    (async () => {
      let lastError;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const element = await browser.$(selector);
          await element.waitForExist({ timeout });
          await scrollElementIntoView(browser, element);
          await element.waitForDisplayed({ timeout });
          await element.waitForEnabled({ timeout });
          try {
            await element.waitForClickable({ timeout: Math.min(timeout, UI_TIMEOUT) });
          } catch {}
          await browser.execute((target) => {
            if (!target) {
              return;
            }
            target.scrollIntoView({ block: "center", inline: "center" });
            target.click();
          }, element);
          return element;
        } catch (error) {
          lastError = error;
          if (!String(error).includes("stale element reference")) {
            throw error;
          }
          await sleep(200);
        }
      }
      throw lastError;
    })(),
    timeout + TIMEOUT_SLACK,
    `click ${label}`,
  );
};

const clickWhenReady = async (browser, selector, timeout = UI_TIMEOUT) => {
  return await withTimeout(
    (async () => {
      let lastError;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const element = await browser.$(selector);
          await element.waitForExist({ timeout });
          await scrollIntoView(browser, selector);
          await element.waitForDisplayed({ timeout });
          await element.waitForEnabled({ timeout });
          try {
            await element.waitForClickable({ timeout: Math.min(timeout, UI_TIMEOUT) });
          } catch {}
          await browser.execute((sel) => {
            const target = document.querySelector(sel);
            if (!target) {
              return;
            }
            target.scrollIntoView({ block: "center", inline: "center" });
            target.click();
          }, selector);
          return element;
        } catch (error) {
          lastError = error;
          if (!String(error).includes("stale element reference")) {
            throw error;
          }
          await sleep(200);
        }
      }
      throw lastError;
    })(),
    timeout + TIMEOUT_SLACK,
    `click ${selector}`,
  );
};

const clickButtonByText = async (browser, text, timeout = UI_TIMEOUT) => {
  const selector =
    `//button[contains(normalize-space(), "${text}")]` +
    ` | //button[.//span[contains(normalize-space(), "${text}")]]`;
  return await clickByXPath(browser, selector, timeout, `button ${text}`);
};

const waitForButtonByText = async (browser, text, timeout = UI_TIMEOUT) => {
  const selector =
    `//button[contains(normalize-space(), "${text}")]` +
    ` | //button[.//span[contains(normalize-space(), "${text}")]]`;
  const element = await browser.$(selector);
  await element.waitForExist({ timeout });
  return element;
};

const clickConfirmModalButton = async (browser, title, label, timeout = UI_TIMEOUT) => {
  const selector =
    `//div[contains(@class,"fixed") and .//h3[normalize-space()="${title}"]]` +
    `//button[normalize-space()="${label}"]`;
  return await clickByXPath(browser, selector, timeout, `confirm ${label}`);
};

const setInputValueForElement = async (
  browser,
  element,
  value,
  timeout = UI_TIMEOUT,
  label = "input",
) => {
  return await withTimeout(
    (async () => {
      let lastError;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          await element.waitForExist({ timeout });
          await scrollElementIntoView(browser, element);
          await element.waitForDisplayed({ timeout });
          await element.waitForEnabled({ timeout });
          await browser.execute(
            (target, nextValue) => {
              if (!target) {
                return;
              }
              target.focus();
              target.value = nextValue;
              target.dispatchEvent(new Event("input", { bubbles: true }));
              target.dispatchEvent(new Event("change", { bubbles: true }));
              target.blur();
            },
            element,
            value,
          );
          return element;
        } catch (error) {
          lastError = error;
          if (!String(error).includes("stale element reference")) {
            throw error;
          }
          await sleep(200);
        }
      }
      throw lastError;
    })(),
    timeout + TIMEOUT_SLACK,
    `set ${label}`,
  );
};

const setInputValue = async (browser, selector, value, timeout = UI_TIMEOUT) => {
  return await withTimeout(
    (async () => {
      const element = await browser.$(selector);
      await element.waitForExist({ timeout });
      await scrollIntoView(browser, selector);
      await element.waitForDisplayed({ timeout });
      await element.waitForEnabled({ timeout });
      await browser.execute(
        (sel, nextValue) => {
          const input = document.querySelector(sel);
          if (!input) {
            return;
          }
          input.focus();
          input.value = nextValue;
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
          input.blur();
        },
        selector,
        value,
      );
      return element;
    })(),
    timeout + TIMEOUT_SLACK,
    `set ${selector}`,
  );
};

const setInputValueByLabel = async (browser, labelText, value, timeout = UI_TIMEOUT) => {
  const selector =
    `//label[normalize-space()="${labelText}"]/following::input[1]` +
    ` | //label[normalize-space()="${labelText}"]/following::textarea[1]`;
  const element = await browser.$(selector);
  return await setInputValueForElement(browser, element, value, timeout, `label ${labelText}`);
};

const waitForTitle = async (browser) => {
  await browser.waitUntil(async () => (await browser.getTitle()) === "Zann Desktop", {
    timeout: UI_TIMEOUT,
    interval: 500,
  });
};

export {
  clickButtonByText,
  clickByXPath,
  clickConfirmModalButton,
  clickWhenReady,
  getBodyText,
  logStep,
  scrollElementIntoView,
  setInputValue,
  setInputValueByLabel,
  setInputValueForElement,
  waitForButtonByText,
  waitForTitle,
  withTimeout,
};
