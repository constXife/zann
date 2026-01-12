const appPath = process.env.TAURI_APP_PATH ?? "";
const e2eEnabled =
  process.env.TAURI_E2E_ENABLE === "1" && Boolean(process.env.TAURI_APP_PATH);
const driverPort = Number(process.env.TAURI_DRIVER_PORT ?? 4444);
const serverUrl = process.env.TAURI_E2E_SERVER_URL ?? "http://127.0.0.1:18081";
const e2eFlow = process.env.TAURI_E2E_FLOW ?? "all";
const loginPassword = "E2ePass123!";
const rawTimeout = Number(process.env.TAURI_E2E_UI_TIMEOUT ?? 5000);
const UI_TIMEOUT = Number.isFinite(rawTimeout) && rawTimeout > 0 ? rawTimeout : 5000;
const fixture = {
  loginEmail: "",
};

export {
  appPath,
  driverPort,
  e2eFlow,
  e2eEnabled,
  fixture,
  UI_TIMEOUT,
  loginPassword,
  serverUrl,
};
