// 浅色 / 深色：用户可以跟随系统，也可以固定一种。
// 结果写在 <html data-theme>，CSS 只认这一个开关；渲染前就写好，避免先闪一下错的颜色。

import { getCurrentWindow } from "@tauri-apps/api/window";

export type ThemePreference = "system" | "light" | "dark";

const STORAGE_KEY = "tsuba-theme";
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");
// 浏览器里预览时没有 Tauri 窗口，不去设置窗口外观
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
  // 窗口外观（标题栏、红绿灯、系统弹窗）跟着一起切，否则固定深色时系统控件还是浅色的
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
  apply(loadThemePreference());
  systemDark.addEventListener("change", () => apply(loadThemePreference()));
}
