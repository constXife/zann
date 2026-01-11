import { clickWhenReady } from "./tauri.e2e.utils.mjs";

const openSettingsAccounts = async (browser) => {
  await clickWhenReady(browser, 'button[title="Settings"]', 20000);
};

export { openSettingsAccounts };
