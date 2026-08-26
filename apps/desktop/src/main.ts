import { createApp } from "vue";
import { createI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";
import { library } from "@fortawesome/fontawesome-svg-core";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { fas } from "@fortawesome/free-solid-svg-icons";
import { far } from "@fortawesome/free-regular-svg-icons";
import { fab } from "@fortawesome/free-brands-svg-icons";
import App from "./App.vue";
// The catalogue is shared with native clients through `zann-ui-core`.
import en from "../../../i18n/en.json";
import ru from "../../../i18n/ru.json";
import "./styles.css";

const logError = (label: string, value: unknown) => {
  console.error(`[ui] ${label}`, value);
};

window.addEventListener("error", (event) => {
  logError("window_error", {
    message: event.message,
    filename: event.filename,
    lineno: event.lineno,
    colno: event.colno,
    error: event.error ? String(event.error) : null,
  });
});

window.addEventListener("unhandledrejection", (event) => {
  logError("unhandled_rejection", {
    reason: event.reason ? String(event.reason) : null,
  });
});

library.add(fas, far, fab);

const fallbackLocale = "en" as const;
const normalizeLocale = (value?: string): "en" | "ru" =>
  value?.split("-")[0] === "ru" ? "ru" : fallbackLocale;
const systemLocale = normalizeLocale(navigator.language);

if (import.meta.env.VITE_E2E === "1") {
  document.documentElement.dataset.e2e = "true";
}

const i18n = createI18n({
  legacy: false,
  locale: systemLocale,
  fallbackLocale,
  messages: { en, ru },
});

invoke<{ ok: boolean; data?: string }>("system_locale")
  .then((response) => {
    if (response.ok && response.data) {
      i18n.global.locale.value = normalizeLocale(response.data);
    }
  })
  .catch(() => {});

createApp(App)
  .component("font-awesome-icon", FontAwesomeIcon)
  .use(i18n)
  .mount("#app");
