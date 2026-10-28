import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { initTheme } from "./theme";

initTheme();

// 开发时在普通浏览器里打开（没有 Tauri 后端）时，用假数据渲染界面，方便调样式
const ready = import.meta.env.DEV && !("__TAURI_INTERNALS__" in window) ? import("./devMock") : Promise.resolve();

ready.then(() => {
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
});
