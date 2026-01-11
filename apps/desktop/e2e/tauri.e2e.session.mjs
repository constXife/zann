import { remote } from "webdriverio";
import { appPath, driverPort } from "./tauri.e2e.config.mjs";

const buildCapabilities = () => {
  return {
    "tauri:options": {
      application: appPath,
    },
  };
};

const createSession = () =>
  remote({
    hostname: "127.0.0.1",
    port: driverPort,
    path: "/",
    capabilities: buildCapabilities(),
    logLevel: "error",
  });

export { createSession };
