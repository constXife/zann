const appPath = process.env.TAURI_APP_PATH ?? "";
const e2eEnabled = Boolean(process.env.TAURI_APP_PATH);
const driverPort = Number(process.env.TAURI_DRIVER_PORT ?? 4444);
const serverUrl = process.env.TAURI_E2E_SERVER_URL ?? "http://127.0.0.1:18081";
const loginPassword = "E2ePass123!";
const UI_TIMEOUT = 5000;
const fixture = {
  loginEmail: "",
};

export {
  appPath,
  driverPort,
  e2eEnabled,
  fixture,
  UI_TIMEOUT,
  loginPassword,
  serverUrl,
};
