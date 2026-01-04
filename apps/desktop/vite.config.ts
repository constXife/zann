import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5174,
    strictPort: true,
    host: "127.0.0.1",
  },
  test: {
    environment: "jsdom",
  },
});
