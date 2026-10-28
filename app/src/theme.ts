// 浅色 / 深色：用户可以跟随系统，也可以固定一种。
// 结果写在 <html data-theme>，CSS 只认这一个开关；渲染前就写好，避免先闪一下错的颜色。

import { getCurrentWindow } from "@tauri-apps/api/window";

export type ThemePreference = "system" | "light" | "dark";

const STORAGE_KEY = "tsuba-theme";
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");
// 在 Tauri 窗口里才有原生毛玻璃；浏览器里预览时用 CSS 渐变代替
const isNativeWindow = "__TAURI_INTERNALS__" in window;

export function loadThemePreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    // 存储不可用时就跟随系统
  }
  return "system";
}

function apply(pref: ThemePreference) {
  const dark = pref === "dark" || (pref === "system" && systemDark.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  // 原生毛玻璃的明暗跟着窗口外观走：用户固定了深色而系统是浅色时，要把窗口也切过去，否则玻璃是亮的、文字是白的
  if (isNativeWindow) getCurrentWindow().setTheme(pref === "system" ? null : pref).catch(() => {});
}

export function setThemePreference(pref: ThemePreference) {
  try {
    if (pref === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // 记不住也不影响这次切换
  }
  apply(pref);
}

export function initTheme() {
  if (isNativeWindow) document.documentElement.dataset.vibrancy = "";
  apply(loadThemePreference());
  systemDark.addEventListener("change", () => apply(loadThemePreference()));
}
