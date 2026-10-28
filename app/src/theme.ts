// Light / dark: follow the system or pin one.
// The result goes on <html data-theme>, the only switch CSS looks at; it is set before rendering so the wrong colors never flash.

import { getCurrentWindow } from "@tauri-apps/api/window";

export type ThemePreference = "system" | "light" | "dark";

const STORAGE_KEY = "tsuba-theme";
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");
// No Tauri window when previewing in a browser, so leave the window appearance alone
const isNativeWindow = "__TAURI_INTERNALS__" in window;

export function loadThemePreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    // Storage unavailable: follow the system
  }
  return "system";
}

function apply(pref: ThemePreference) {
  const dark = pref === "dark" || (pref === "system" && systemDark.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  // Switch the window appearance too (title bar, traffic lights, system dialogs), or system controls stay light when dark is pinned
  if (isNativeWindow) getCurrentWindow().setTheme(pref === "system" ? null : pref).catch(() => {});
}

export function setThemePreference(pref: ThemePreference) {
  try {
    if (pref === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Not remembered, but this switch still applies
  }
  apply(pref);
}

export function initTheme() {
  apply(loadThemePreference());
  systemDark.addEventListener("change", () => apply(loadThemePreference()));
}
