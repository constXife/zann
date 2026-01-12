import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  createSession,
} from "./tauri.e2e.session.mjs";
import { e2eEnabled, e2eFlow } from "./tauri.e2e.config.mjs";
import {
  localOnlyScenario,
  registerAndCreateKvScenario,
  reloginAndRestoreScenario,
} from "./tauri.e2e.flows.mjs";
import assert from "node:assert/strict";

const ARTIFACTS_DIR =
  process.env.TAURI_E2E_ARTIFACTS_DIR ?? path.join(process.cwd(), "e2e", "artifacts");
const forcedTimeoutMs = Number(process.env.TAURI_E2E_FORCE_TIMEOUT_MS ?? 0);
const forceExitOnTimeout =
  process.env.TAURI_E2E_FORCE_EXIT_ON_TIMEOUT === "1" ||
  (forcedTimeoutMs > 0 && process.env.TAURI_E2E_FORCE_EXIT_ON_TIMEOUT !== "0");
const forceExitGraceMs = Number(process.env.TAURI_E2E_FORCE_EXIT_GRACE_MS ?? 2000);

const withTimeout = async (promise, timeoutMs, label, { allowForce = true } = {}) => {
  const effectiveTimeout =
    allowForce && forcedTimeoutMs > 0 ? forcedTimeoutMs : timeoutMs;
  if (allowForce && forcedTimeoutMs > 0) {
    console.log(`[e2e] force-timeout ${label}: ${effectiveTimeout}ms`);
  }
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const lastStep = globalThis.__e2eLastStep;
          const lastStepInfo = lastStep ? ` (last step: ${lastStep})` : "";
          const error = new Error(
            `${label} timed out after ${effectiveTimeout}ms${lastStepInfo}`,
          );
          globalThis.__e2eTimedOut = true;
          globalThis.__e2eTimeoutError = error;
          console.log(`[e2e] timeout fired: ${label}${lastStepInfo}`);
          reject(error);
        }, effectiveTimeout);
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
  const tickMs = Number(process.env.TAURI_E2E_PROGRESS_TICK_MS ?? 1000);
  const start = Date.now();
  const interval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - start) / 1000);
    const lastStep = globalThis.__e2eLastStep;
    const stepInfo = lastStep ? ` (step: ${lastStep})` : "";
    console.log(`[e2e] ${label} running ${elapsed}s${stepInfo}`);
  }, tickMs);
  let timeoutGuardInterval;
  let forceExitTimer;
  const timeoutGuard = new Promise((_, reject) => {
    timeoutGuardInterval = setInterval(() => {
      if (globalThis.__e2eTimedOut) {
        clearInterval(timeoutGuardInterval);
        if (forceExitOnTimeout && !forceExitTimer) {
          forceExitTimer = setTimeout(() => {
            const message =
              globalThis.__e2eTimeoutError?.message ?? "e2e timed out";
            console.error(`[e2e] hard-exit after timeout: ${message}`);
            process.exit(1);
          }, forceExitGraceMs);
        }
        Promise.resolve(
          state.browser ? saveArtifacts(state.browser, `timeout-${label}`) : null,
        ).finally(() => {
          reject(globalThis.__e2eTimeoutError ?? new Error("e2e timed out"));
        });
      }
    }, 100);
  });
  try {
    return await Promise.race([
      runWithArtifacts(state.browser, label, timeoutMs, fn),
      timeoutGuard,
    ]);
  } finally {
    clearInterval(interval);
    if (timeoutGuardInterval) {
      clearInterval(timeoutGuardInterval);
    }
    if (forceExitTimer) {
      clearTimeout(forceExitTimer);
    }
  }
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("e2e scenario", { timeout: 360000, skip: !e2eEnabled }, async () => {
  const state = { browser: null, label: "init" };
  const runLocal = e2eFlow === "local" || e2eFlow === "all";
  const runRemote = e2eFlow === "remote" || e2eFlow === "all";
  const localTimeoutMs = Number(process.env.TAURI_E2E_LOCAL_TIMEOUT ?? 60000);
  try {
    await withTimeout(
      (async () => {
        if (runRemote) {
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
        }

        if (runLocal) {
          state.browser = await createSession();
          await runScenario(state, "scenario-local", localTimeoutMs, () =>
            localOnlyScenario(state.browser),
          );
          await deleteSessionWithTimeout(state.browser, "scenario-local");
          state.browser = null;
        }
      })(),
      320000,
      "e2e scenario",
      { allowForce: false },
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

test("[@probe] timeout check", { timeout: 1000 }, async () => {
  await assert.rejects(
    async () => {
      await withTimeout(sleep(10000), 10, "timeout probe", { allowForce: false });
    },
    (error) => {
      assert.match(String(error?.message ?? error), /timed out/i);
      return true;
    },
    "Expected timeout probe to time out",
  );
});
