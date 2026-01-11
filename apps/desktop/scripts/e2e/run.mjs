import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { access, mkdtemp, rm, mkdir, readdir, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(SCRIPT_DIR, "../..");
const REPO_ROOT = path.resolve(APP_ROOT, "../..");
const PLATFORM = process.platform;

const ensureSupportedPlatform = () => {
  if (PLATFORM === "darwin") {
    console.error("E2E tests are not supported on macOS.");
    process.exit(1);
  }
};

const runCommand = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", ...options });
    child.on("error", (error) => {
      reject(
        new Error(`command failed: ${command} ${args.join(" ")}\n${error.message}`),
      );
    });
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`command failed: ${command} ${args.join(" ")} (code ${code})`));
      }
    });
  });

const runCommandQuiet = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "ignore", ...options });
    child.on("error", (error) => {
      reject(
        new Error(`command failed: ${command} ${args.join(" ")}\n${error.message}`),
      );
    });
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`command failed: ${command} ${args.join(" ")} (code ${code})`));
      }
    });
  });

const commandExists = (command) =>
  runCommand("sh", ["-c", `command -v ${command} >/dev/null 2>&1`]);

const resolveCommandPath = (command) =>
  new Promise((resolve, reject) => {
    const child = spawn("sh", ["-c", `command -v ${command}`], { stdio: ["ignore", "pipe", "ignore"] });
    let output = "";
    child.stdout?.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        const resolved = output.trim();
        resolve(resolved || null);
      } else {
        resolve(null);
      }
    });
  });

const cleanupComposeArtifacts = async (composeBin, namePrefix, serverPort) => {
  const nameFilter = `^${namePrefix}`;
  const portFilter = String(serverPort);
  const script =
    `ids=$(${composeBin} ps -aq --filter name=${nameFilter});` +
    `port_ids=$(${composeBin} ps -aq --filter publish=${portFilter});` +
    'all="$ids $port_ids";' +
    'if [ -n "$all" ]; then ' +
    `${composeBin} rm -f $all >/dev/null 2>&1 || true; ` +
    "fi";
  await runCommandQuiet("sh", ["-c", script]);
};

const startXvfb = async () => {
  const display = process.env.TAURI_E2E_DISPLAY ?? ":99";
  const xvfbStdio = process.env.TAURI_E2E_XVFB_STDIO === "inherit" ? "inherit" : "ignore";
  const xvfbProcess = spawn("Xvfb", [display, "-screen", "0", "1280x720x24"], {
    stdio: xvfbStdio,
  });

  const stopXvfb = () => {
    if (!xvfbProcess.killed) {
      xvfbProcess.kill();
    }
  };

  process.on("exit", stopXvfb);
  process.on("SIGINT", () => {
    stopXvfb();
    process.exit(1);
  });
  process.on("SIGTERM", () => {
    stopXvfb();
    process.exit(1);
  });

  await new Promise((resolve) => setTimeout(resolve, 500));

  return {
    display,
    stopXvfb,
  };
};

const ensureXvfbAvailable = async () => {
  if (process.platform !== "linux" || process.env.TAURI_E2E_HEADLESS !== "1") {
    return;
  }

  try {
    await commandExists("xvfb-run");
    return;
  } catch {}

  try {
    await commandExists("Xvfb");
  } catch (error) {
    throw new Error(
      `xvfb-run or Xvfb not found. Install xorg.xorgserver or use nix develop.\\n${error.message}`,
    );
  }
};

const waitForPort = (port, timeoutMs = 30000) =>
  new Promise((resolve, reject) => {
    const start = Date.now();

    const tryConnect = () => {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      socket.once("connect", () => {
        socket.end();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Timed out waiting for tauri-driver on port ${port}`));
        } else {
          setTimeout(tryConnect, 250);
        }
      });
    };

    tryConnect();
  });

const ensureDriverAvailable = async (driverBin) => {
  try {
    if (driverBin.includes(path.sep)) {
      await access(driverBin);
    } else {
      await commandExists(driverBin);
    }
  } catch (error) {
    throw new Error(
      `tauri-driver not found. Install it with "cargo install tauri-driver" or set TAURI_DRIVER_BIN.\n${error.message}`,
    );
  }
};

const resolveNativeDriverBin = async () => {
  const configured = process.env.TAURI_E2E_NATIVE_DRIVER;
  if (configured) {
    try {
      if (configured.includes(path.sep)) {
        await access(configured);
        return configured;
      }
      const resolved = await resolveCommandPath(configured);
      if (resolved) {
        return resolved;
      }
    } catch {
      return null;
    }
  }

  try {
    const resolved = await resolveCommandPath("WebKitWebDriver");
    if (resolved) {
      return resolved;
    }
  } catch {}

  const candidates = [
    "/usr/libexec/webkit2gtk-4.1/WebKitWebDriver",
    "/usr/libexec/webkit2gtk-4.0/WebKitWebDriver",
    "/usr/libexec/WebKitWebDriver",
    "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebDriver",
    "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0/WebKitWebDriver",
    "/usr/lib/webkit2gtk-4.1/WebKitWebDriver",
    "/usr/lib/webkit2gtk-4.0/WebKitWebDriver",
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {}
  }

  return null;
};

const resolveDriverBin = async () => {
  const configured = process.env.TAURI_DRIVER_BIN;
  if (configured) {
    return configured;
  }

  try {
    await commandExists("tauri-driver");
    return "tauri-driver";
  } catch {}

  const driverName = PLATFORM === "win32" ? "tauri-driver.exe" : "tauri-driver";
  const cargoDriver = path.join(os.homedir(), ".cargo", "bin", driverName);
  try {
    await access(cargoDriver);
    return cargoDriver;
  } catch {
    return "tauri-driver";
  }
};

const resolveComposeCommand = async () => {
  try {
    await commandExists("docker");
    return { bin: "docker", args: ["compose"] };
  } catch {}

  try {
    await commandExists("podman");
    return { bin: "podman", args: ["compose"] };
  } catch (error) {
    throw new Error(
      `docker/podman not found for compose. Install docker or set TAURI_E2E_SKIP_SERVER=1.\\n${error.message}`,
    );
  }
};

const imageExists = async (composeBin, imageName) => {
  try {
    await runCommandQuiet(composeBin, ["image", "inspect", imageName]);
    return true;
  } catch {
    return false;
  }
};

const startCompose = async (serverPort) => {
  if (process.env.TAURI_E2E_SKIP_SERVER === "1") {
    return null;
  }

  const composeFile = process.env.TAURI_E2E_COMPOSE_FILE ?? path.join(REPO_ROOT, "compose.e2e.yaml");
  const projectName = process.env.TAURI_E2E_PROJECT ?? `zann-e2e-${Date.now()}`;
  const compose = await resolveComposeCommand();
  const imageName = process.env.TAURI_E2E_SERVER_IMAGE ?? "zann-e2e/server:dev";
  const shouldBuild = process.env.TAURI_E2E_BUILD_SERVER === "1";

  await cleanupComposeArtifacts(compose.bin, "zann-e2e-", serverPort);

  if (shouldBuild || !(await imageExists(compose.bin, imageName))) {
    const buildArgs = [...compose.args, "-f", composeFile, "-p", projectName, "build"];
    await runCommand(compose.bin, buildArgs, { cwd: REPO_ROOT });
  }

  const args = [...compose.args, "-f", composeFile, "-p", projectName, "up", "-d"];

  await runCommand(compose.bin, args, {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      TAURI_E2E_SERVER_PORT: String(serverPort),
    },
  });

  return { compose, composeFile, projectName };
};

const stopCompose = async (state) => {
  if (!state) {
    return;
  }

  const args = [
    ...state.compose.args,
    "-f",
    state.composeFile,
    "-p",
    state.projectName,
    "down",
    "-v",
  ];

  try {
    await runCommand(state.compose.bin, args, { cwd: REPO_ROOT });
  } catch (error) {
    console.warn(
      `[e2e] compose down failed: ${error.stack || error.message || error}`,
    );
  }
};

const wrapWithXvfb = async (command, args, extraEnv = {}) => {
  if (process.platform !== "linux" || process.env.TAURI_E2E_HEADLESS !== "1") {
    return { command, args, env: { ...process.env, ...extraEnv }, cleanup: () => {} };
  }

  const baseEnv = { ...process.env, ...extraEnv };
  delete baseEnv.DISPLAY;
  delete baseEnv.WAYLAND_DISPLAY;
  baseEnv.XDG_SESSION_TYPE = "x11";
  baseEnv.GDK_BACKEND = "x11";

  try {
    await commandExists("xvfb-run");
    return {
      command: "xvfb-run",
      args: ["-a", command, ...args],
      env: baseEnv,
      cleanup: () => {},
    };
  } catch {
    const { display, stopXvfb } = await startXvfb();
    return {
      command,
      args,
      env: {
        ...baseEnv,
        DISPLAY: display,
      },
      cleanup: stopXvfb,
    };
  }
};

const rotateArtifacts = async (artifactsDir, keepCount) => {
  if (keepCount <= 0) {
    await rm(artifactsDir, { recursive: true, force: true });
    await mkdir(artifactsDir, { recursive: true });
    return;
  }

  await mkdir(artifactsDir, { recursive: true });
  const entries = await readdir(artifactsDir, { withFileTypes: true });
  const dirs = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const fullPath = path.join(artifactsDir, entry.name);
    const info = await stat(fullPath);
    dirs.push({ path: fullPath, mtimeMs: info.mtimeMs });
  }

  dirs.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const keepExisting = Math.max(0, keepCount - 1);
  const toRemove = dirs.slice(keepExisting);
  for (const entry of toRemove) {
    await rm(entry.path, { recursive: true, force: true });
  }
};

let testsCompleted = false;

const logActiveHandles = (label) => {
  const getHandles = process._getActiveHandles?.() ?? [];
  const getRequests = process._getActiveRequests?.() ?? [];
  if (!getHandles.length && !getRequests.length) {
    console.warn(`[e2e] ${label}: no active handles`);
    return;
  }
  console.warn(
    `[e2e] ${label}: handles=${getHandles.length} requests=${getRequests.length}`,
  );
  for (const handle of getHandles) {
    const name = handle?.constructor?.name ?? "unknown";
    console.warn(`[e2e] active handle: ${name}`);
  }
  for (const req of getRequests) {
    const name = req?.constructor?.name ?? "unknown";
    console.warn(`[e2e] active request: ${name}`);
  }
};

const main = async () => {
  ensureSupportedPlatform();
  const driverBin = await resolveDriverBin();
  if (!process.env.TAURI_E2E_HEADLESS) {
    process.env.TAURI_E2E_HEADLESS = "1";
  }
  if (!process.env.LIBGL_ALWAYS_SOFTWARE) {
    process.env.LIBGL_ALWAYS_SOFTWARE = "1";
  }
  if (!process.env.LIBGL_ALWAYS_INDIRECT) {
    process.env.LIBGL_ALWAYS_INDIRECT = "1";
  }
  if (!process.env.GDK_GL) {
    process.env.GDK_GL = "disabled";
  }
  if (!process.env.GDK_DISABLE) {
    process.env.GDK_DISABLE = "gl";
  }
  if (!process.env.GSK_RENDERER) {
    process.env.GSK_RENDERER = "cairo";
  }
  if (!process.env.NO_AT_BRIDGE) {
    process.env.NO_AT_BRIDGE = "1";
  }
  if (!process.env.VITE_E2E) {
    process.env.VITE_E2E = "1";
  }
  const driverPort = Number(process.env.TAURI_DRIVER_PORT ?? 4444);
  const serverUrl = process.env.TAURI_E2E_SERVER_URL ?? "http://127.0.0.1:18081";
  const serverPort = Number(process.env.TAURI_E2E_SERVER_PORT ?? 18081);
  const e2eHome =
    process.env.TAURI_E2E_HOME ??
    (await mkdtemp(path.join(os.tmpdir(), "zann-e2e-")));
  const appBinary = PLATFORM === "win32" ? "zann-desktop.exe" : "zann-desktop";
  const defaultAppPath = path.join(APP_ROOT, "src-tauri", "target", "debug", appBinary);
  const appPath = process.env.TAURI_APP_PATH ?? defaultAppPath;

  await ensureDriverAvailable(driverBin);
  await ensureXvfbAvailable();
  const nativeDriverBin = await resolveNativeDriverBin();

  const composeState = await startCompose(serverPort);
  if (composeState) {
    await waitForPort(serverPort, 60000);
  }

  try {
    if (!process.env.TAURI_E2E_SKIP_BUILD) {
      await runCommand("bun", ["run", "tauri", "build", "--debug", "--no-bundle"], {
        cwd: APP_ROOT,
      });
    }

    try {
      await access(appPath);
    } catch {
      throw new Error(`Tauri app binary not found at ${appPath}`);
    }

    const driverArgs = ["--port", String(driverPort)];
    if (nativeDriverBin) {
      driverArgs.push("--native-driver", nativeDriverBin);
    }
    const wrapped = await wrapWithXvfb(driverBin, driverArgs, { HOME: e2eHome });
    const artifactsDir = path.join(APP_ROOT, "e2e", "artifacts");
    const keepCount = Number(process.env.TAURI_E2E_ARTIFACTS_KEEP ?? "1");
    await rotateArtifacts(artifactsDir, keepCount);
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const runArtifactsDir = path.join(artifactsDir, timestamp);
    await mkdir(runArtifactsDir, { recursive: true });
    const driverLogPath = path.join(runArtifactsDir, "driver.log");
    const driverErrPath = path.join(runArtifactsDir, "driver.err.log");
    const driverLog = createWriteStream(driverLogPath, { flags: "a" });
    const driverErr = createWriteStream(driverErrPath, { flags: "a" });

    const driverProcess = spawn(wrapped.command, wrapped.args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: wrapped.env,
    });
    const filterGtkGlWarning = (text) =>
      text
        .split("\n")
        .filter(
          (line) =>
            !line.includes("Disabled hardware acceleration because GTK failed to initialize GL"),
        )
        .join("\n");

    driverProcess.stdout?.on("data", (chunk) => {
      const text = filterGtkGlWarning(String(chunk));
      if (!text) return;
      driverLog.write(text);
      process.stdout.write(text);
    });
    driverProcess.stderr?.on("data", (chunk) => {
      const text = filterGtkGlWarning(String(chunk));
      if (!text) return;
      driverErr.write(text);
      process.stderr.write(text);
    });

    const closeStream = (stream) =>
      new Promise((resolve) => {
        if (!stream.writableEnded) {
          stream.end(() => resolve());
        } else {
          resolve();
        }
      });

    const stopDriver = async () => {
      if (!driverProcess.killed) {
        driverProcess.kill();
      }
      await Promise.all([closeStream(driverLog), closeStream(driverErr)]);
      wrapped.cleanup();
    };

    process.on("exit", () => {
      stopDriver().catch(() => {});
    });
    process.on("SIGINT", async () => {
      await stopDriver();
      process.exit(1);
    });
    process.on("SIGTERM", async () => {
      await stopDriver();
      process.exit(1);
    });

    try {
      await waitForPort(driverPort);
      const bunBin = process.env.BUN_BIN ?? "bun";
      await runCommand(
        bunBin,
        ["test", path.join(APP_ROOT, "e2e", "tauri.e2e.test.mjs")],
        {
          cwd: APP_ROOT,
          env: {
            ...process.env,
            TAURI_APP_PATH: appPath,
            TAURI_DRIVER_PORT: String(driverPort),
            TAURI_E2E_SERVER_URL: serverUrl,
            TAURI_E2E_HOME: e2eHome,
            TAURI_E2E_ARTIFACTS_DIR: runArtifactsDir,
          },
        },
      );
      testsCompleted = true;
    } finally {
      await stopDriver();
    }
  } finally {
    await stopCompose(composeState);
    if (process.env.TAURI_E2E_KEEP_HOME !== "1") {
      try {
        await rm(e2eHome, { recursive: true, force: true });
      } catch (error) {
        console.warn(
          `[e2e] cleanup failed: ${error.stack || error.message || error}`,
        );
      }
    }
  }
};

main()
  .then(() => {
    if (process.env.TAURI_E2E_LOG_HANDLES === "1") {
      logActiveHandles("post-run");
    }
    if (process.env.TAURI_E2E_FORCE_EXIT === "1" && testsCompleted) {
      process.exit(0);
    }
  })
  .catch((error) => {
    if (process.env.TAURI_E2E_LOG_HANDLES === "1") {
      logActiveHandles("error");
    }
  if (String(error?.message || error).includes("The operation was canceled") && testsCompleted) {
    console.warn(`[e2e] cleanup canceled after tests: ${error.message}`);
    process.exit(0);
  }
  console.error(error.message);
  process.exit(1);
  });
