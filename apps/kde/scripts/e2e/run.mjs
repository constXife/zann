import { spawn } from "node:child_process";
import { constants as fsConstants, promises as fs } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(SCRIPT_DIR, "../..");
const REPO_ROOT = path.resolve(APP_ROOT, "../..");

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

const commandExists = async (command) => {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const exts =
    process.platform === "win32"
      ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD")
          .split(";")
          .filter(Boolean)
      : [""];
  for (const dir of dirs) {
    for (const ext of exts) {
      try {
        await fs.access(path.join(dir, command + ext), fsConstants.X_OK);
        return;
      } catch {}
    }
  }
  throw new Error(`command not found: ${command}`);
};

const resolveRustRunner = async () => {
  if (process.env.ZANN_E2E_USE_BUN === "1") {
    return { bin: "bun", args: [] };
  }
  try {
    await commandExists("bun");
    return { bin: "bun", args: [] };
  } catch {}
  return { bin: "cargo", args: [] };
};

const resolveComposeCommand = async () => {
  try {
    await runCommand("docker", ["compose", "version"], { stdio: "ignore" });
    return { bin: "docker", args: ["compose"] };
  } catch {}
  try {
    await commandExists("podman");
    return { bin: "podman", args: ["compose"] };
  } catch {}
  try {
    await commandExists("podman-compose");
    return { bin: "podman-compose", args: [] };
  } catch {}
  await commandExists("docker-compose");
  return { bin: "docker-compose", args: [] };
};

const findFreePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

const waitForHttp = async (url, timeoutMs = 30000) => {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Timed out waiting for ${url}`);
};

const main = async () => {
  const serverPort = Number(process.env.TAURI_E2E_SERVER_PORT ?? 18081);
  const dbPort = Number(process.env.TAURI_E2E_DB_PORT ?? 15433);
  const useMock = true;
  let serverUrl =
    process.env.TAURI_E2E_SERVER_URL ?? `http://127.0.0.1:${serverPort}`;
  const composeFile =
    process.env.TAURI_E2E_COMPOSE_FILE ?? path.join(REPO_ROOT, "compose.e2e.yaml");
  const projectName = process.env.TAURI_E2E_PROJECT ?? "zann-e2e";

  const loginPassword =
    process.env.ZANN_E2E_LOGIN_PASSWORD ?? "E2ePass123!";
  const masterPassword =
    process.env.ZANN_E2E_MASTER_PASSWORD ?? loginPassword;

  let mockProcess;
  const rustRunner = await resolveRustRunner();
  {
    const mockPort = await findFreePort();
    serverUrl = `http://127.0.0.1:${mockPort}`;
    const mockRoot = path.join(APP_ROOT, "mock-server");
    const mockBin =
      process.env.ZANN_E2E_MOCK_BIN ??
      path.join(mockRoot, "target", "debug", "zann-kde-mock-server");

    let mockCmd;
    let mockArgs = [];
    if (process.env.ZANN_E2E_MOCK_BIN) {
      mockCmd = mockBin;
    } else {
      try {
        await fs.access(mockBin, fsConstants.X_OK);
        mockCmd = mockBin;
      } catch {
        const manifestPath = path.join(mockRoot, "Cargo.toml");
        const buildArgs =
          rustRunner.bin === "bun"
            ? ["run", "cargo", "--", "build", "--manifest-path", manifestPath]
            : ["build", "--manifest-path", manifestPath];
        await runCommand(rustRunner.bin, buildArgs, { cwd: APP_ROOT });
        mockCmd = mockBin;
      }
    }

    mockProcess = spawn(mockCmd, mockArgs, {
      cwd: mockRoot,
      stdio: "inherit",
      env: {
        ...process.env,
        ZANN_MOCK_PORT: String(mockPort),
      },
    });
    await waitForHttp(`${serverUrl}/v1/system/info`, 60000);
  }

  try {
    const testArgs =
      rustRunner.bin === "bun"
        ? ["run", "cargo", "--", "run", "--bin", "zann-qml-tests"]
        : ["run", "--bin", "zann-qml-tests"];
    await runCommand(rustRunner.bin, testArgs, {
      cwd: APP_ROOT,
      env: {
        ...process.env,
        ZANN_E2E_MODE: "mock",
        ZANN_E2E_SERVER_URL: serverUrl,
        ZANN_E2E_LOGIN_PASSWORD: loginPassword,
        ZANN_E2E_MASTER_PASSWORD: masterPassword,
        ZANN_QML_TEST_PATH: "tests/qml-mock",
        ZANN_TEST_SKIP_REMOTE_SYNC: "1",
        ZANN_TEST_ENABLE: "1",
        ZANN_TEST_ALLOW_CLEANUP: "1",
      },
    });
  } finally {
    if (mockProcess) {
      mockProcess.kill("SIGTERM");
    }
  }
};

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exit(1);
});
