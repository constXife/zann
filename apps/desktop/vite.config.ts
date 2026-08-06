import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5174,
    strictPort: true,
    host: "127.0.0.1",
    // The i18n catalogue is shared with the COSMIC client and lives at the repo
    // root. The dev server only serves files it has been allowed to reach, and
    // it would otherwise stop at this app.
    fs: { allow: ["../.."] },
  },
  test: {
    environment: "jsdom",
    exclude: ["e2e/**", "**/node_modules/**"],
  },
});
