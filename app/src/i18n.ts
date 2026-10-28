// User-facing text in English and Simplified Chinese.
//
// Components write the English text: t("Scan a folder"), t("{n} checks", { n }). The Chinese
// catalog maps that English text to Chinese (gettext style); a missing entry falls back to
// English. `pnpm check:i18n` fails when a t() string has no entry or an entry is unused.
//
// The backend is told about every change and saves it to the config, so notifications, the tray menu,
// new findings, AI answers and the terminal check all come out in the same language as the window.

import { useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";
import zhHans from "./locales/zh-Hans.json";

export type Lang = "en" | "zh-Hans";
export type LangPreference = "system" | Lang;

const STORAGE_KEY = "tsuba-lang";
const ZH_HANS: Record<string, string> = zhHans;
// No Tauri backend when previewing in a plain browser
const isNativeWindow = "__TAURI_INTERNALS__" in window;

/** Same rule as the engine's Lang::parse: Simplified Chinese tags → zh-Hans; Traditional Chinese and everything else → en. */
export function parseLang(tag: string): Lang {
  const t = tag.toLowerCase().replace(/_/g, "-");
  const isTraditional = ["hant", "-tw", "-hk", "-mo"].some((m) => t.includes(m));
  return (t === "zh" || t.startsWith("zh-")) && !isTraditional ? "zh-Hans" : "en";
}

function systemLang(): Lang {
  return parseLang(navigator.languages?.[0] ?? navigator.language ?? "en");
}

export function loadLangPreference(): LangPreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "en" || v === "zh-Hans") return v;
  } catch {
    // Storage unavailable: follow the system
  }
  return "system";
}

function resolve(pref: LangPreference): Lang {
  return pref === "system" ? systemLang() : pref;
}

let current: Lang = resolve(loadLangPreference());
const listeners = new Set<() => void>();

function apply(pref: LangPreference) {
  current = resolve(pref);
  document.documentElement.lang = current;
  // The backend saves the preference, so the terminal check and AI answers follow this window's language too
  if (isNativeWindow) invoke("set_lang", { preference: pref, lang: current }).catch(() => {});
  listeners.forEach((l) => l());
}

export function setLangPreference(pref: LangPreference) {
  try {
    if (pref === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Not remembered, but this switch still applies
  }
  apply(pref);
}

export function initLang() {
  apply(loadLangPreference());
  window.addEventListener("languagechange", () => {
    if (loadLangPreference() === "system") apply("system");
  });
}

export function lang(): Lang {
  return current;
}

/** Re-renders the caller when the language changes. Used once at the root; everything below re-renders with it. */
export function useLang(): Lang {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

/** The text in the current language, with `{name}` placeholders filled. Named, because word order differs between languages. */
export function t(en: string, vars?: Record<string, string | number>): string {
  let text = current === "zh-Hans" ? (ZH_HANS[en] ?? en) : en;
  if (vars) for (const [k, v] of Object.entries(vars)) text = text.split(`{${k}}`).join(String(v));
  return text;
}
