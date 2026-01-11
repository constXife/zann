import { clickWhenReady } from "./tauri.e2e.utils.mjs";

const openSettingsAccounts = async (browser) => {
  await clickWhenReady(browser, 'button[title="Settings"]', 20000);
};

const openSettingsGeneral = async (browser) => {
  await openSettingsAccounts(browser);
  await clickWhenReady(browser, '[data-testid="settings-tab-general"]', 20000);
};

const waitForCloseToTray = async (browser, enabled) => {
  const selector = '[data-testid="settings-close-to-tray"]';
  await browser.waitUntil(
    async () => {
      const checkbox = await browser.$(selector);
      if (!(await checkbox.isExisting())) {
        return false;
      }
      return (await checkbox.isSelected()) === enabled;
    },
    {
      timeout: 20000,
      timeoutMsg: `Expected close-to-tray=${enabled} not reached`,
    },
  );
};

const setCloseToTray = async (browser, enabled) => {
  await openSettingsGeneral(browser);
  const checkbox = await browser.$('[data-testid="settings-close-to-tray"]');
  await checkbox.waitForExist({ timeout: 20000 });
  const checked = await checkbox.isSelected();
  if (checked !== enabled) {
    await clickWhenReady(browser, '[data-testid="settings-close-to-tray"]', 20000);
    await waitForCloseToTray(browser, enabled);
  }
  await clickWhenReady(browser, '[data-testid="settings-close"]', 20000);
};

const expectCloseToTray = async (browser, enabled) => {
  await openSettingsGeneral(browser);
  await waitForCloseToTray(browser, enabled);
  await clickWhenReady(browser, '[data-testid="settings-close"]', 20000);
};

export { openSettingsAccounts, openSettingsGeneral, setCloseToTray, expectCloseToTray };
