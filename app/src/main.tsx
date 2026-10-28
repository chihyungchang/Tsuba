import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { initLang } from "./i18n";
import { initTheme } from "./theme";

initTheme();
initLang();

// In development, opened in a plain browser (no Tauri backend), render with mock data to make styling easier
const ready = import.meta.env.DEV && !("__TAURI_INTERNALS__" in window) ? import("./devMock") : Promise.resolve();

ready.then(() => {
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
});
