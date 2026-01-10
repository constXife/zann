import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  createSession,
} from "./tauri.e2e.session.mjs";
import {
  registerAndCreateKvScenario,
  reloginAndRestoreScenario,
} from "./tauri.e2e.flows.mjs";

const ARTIFACTS_DIR =
  process.env.TAURI_E2E_ARTIFACTS_DIR ?? path.join(process.cwd(), "e2e", "artifacts");

const withTimeout = async (promise, timeoutMs, label) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${label} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const saveArtifacts = async (browser, label) => {
  if (!browser.sessionId) {
    return;
  }
  await mkdir(ARTIFACTS_DIR, { recursive: true });
  const safeLabel = label.replace(/[^a-zA-Z0-9-_]/g, "_");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const prefix = path.join(ARTIFACTS_DIR, `${timestamp}-${safeLabel}`);

  try {
    await browser.saveScreenshot(`${prefix}.png`);
  } catch {}

  try {
    const source = await browser.getPageSource();
    await writeFile(`${prefix}.html`, source, "utf8");
  } catch {}

  try {
    const logs = await browser.getLogs("browser");
    await writeFile(`${prefix}.logs.json`, JSON.stringify(logs, null, 2), "utf8");
  } catch {}
};

const runWithArtifacts = async (browser, label, timeoutMs, fn) => {
  try {
    return await withTimeout(fn(), timeoutMs, label);
  } catch (error) {
    await saveArtifacts(browser, label);
    throw error;
  }
};

const deleteSessionWithTimeout = async (browser, label) => {
  try {
    await withTimeout(browser.deleteSession(), 15000, `deleteSession ${label}`);
  } catch (error) {
    await saveArtifacts(browser, `cleanup-${label}`);
    throw error;
  }
};

const runScenario = async (state, label, timeoutMs, fn) => {
  state.label = label;
  return await runWithArtifacts(state.browser, label, timeoutMs, fn);
};

test("e2e scenario", { timeout: 360000 }, async () => {
  const state = { browser: null, label: "init" };
  try {
    await withTimeout(
      (async () => {
        state.browser = await createSession();
        await runScenario(state, "scenario-1", 150000, () =>
          registerAndCreateKvScenario(state.browser),
        );
        await deleteSessionWithTimeout(state.browser, "scenario-1");
        state.browser = null;

        state.browser = await createSession();
        await runScenario(state, "scenario-2", 150000, () =>
          reloginAndRestoreScenario(state.browser),
        );
        await deleteSessionWithTimeout(state.browser, "scenario-2");
        state.browser = null;
      })(),
      320000,
      "e2e scenario",
    );
  } catch (error) {
    if (state.browser) {
      await saveArtifacts(state.browser, `timeout-${state.label}`);
    }
    throw error;
  } finally {
    if (state.browser) {
      await deleteSessionWithTimeout(state.browser, `final-${state.label}`);
    }
  }
});
