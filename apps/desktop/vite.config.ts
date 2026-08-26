import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5174,
    strictPort: true,
    host: "127.0.0.1",
    // The shared translation catalogue lives at the repository root.
    fs: { allow: ["../.."] },
  },
  test: {
    environment: "jsdom",
    exclude: ["e2e/**", "**/node_modules/**"],
  },
});
