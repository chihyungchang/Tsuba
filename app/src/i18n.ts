// User-facing text in English and nine other languages.
//
// Components write the English text: t("Scan a folder"), t("{n} checks", { n }). Each language's
// catalog (locales/<code>.json) maps that English text to the translation (gettext style); a missing
// entry falls back to English. `pnpm check:i18n` fails when a t() string has no entry in some
// language, an entry is unused, or a translation drops a {placeholder}.
//
// The backend is told about every change and saves it to the config, so notifications, the tray menu,
// new findings, AI answers and the terminal check all come out in the same language as the window.

import { useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";
import de from "./locales/de.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";
import ja from "./locales/ja.json";
import ko from "./locales/ko.json";
import ptBR from "./locales/pt-BR.json";
import ru from "./locales/ru.json";
import zhHans from "./locales/zh-Hans.json";
import zhHant from "./locales/zh-Hant.json";

/** Every supported language with its name in that language, so people can find theirs whatever is showing now. Same set as the engine's Lang */
export const LANGS = [
  { id: "en", name: "English" },
  { id: "zh-Hans", name: "简体中文" },
  { id: "zh-Hant", name: "繁體中文" },
  { id: "ja", name: "日本語" },
  { id: "ko", name: "한국어" },
  { id: "es", name: "Español" },
  { id: "fr", name: "Français" },
  { id: "de", name: "Deutsch" },
  { id: "pt-BR", name: "Português (Brasil)" },
  { id: "ru", name: "Русский" },
] as const;

export type Lang = (typeof LANGS)[number]["id"];
export type LangPreference = "system" | Lang;

const STORAGE_KEY = "tsuba-lang";
const CATALOGS: Partial<Record<Lang, Record<string, string>>> = { "zh-Hans": zhHans, "zh-Hant": zhHant, ja, ko, es, fr, de, "pt-BR": ptBR, ru };
// No Tauri backend when previewing in a plain browser
const isNativeWindow = "__TAURI_INTERNALS__" in window;

/** Same rule as the engine's Lang::parse: by the language subtag; Chinese splits by script or region, any Portuguese → pt-BR, the rest → en. */
export function parseLang(tag: string): Lang {
  const t = tag.toLowerCase().replace(/_/g, "-");
  const primary = t.split(/[-.@]/)[0];
  if (primary === "zh") return ["hant", "-tw", "-hk", "-mo"].some((m) => t.includes(m)) ? "zh-Hant" : "zh-Hans";
  if (primary === "pt") return "pt-BR";
  return LANGS.find((l) => l.id === primary)?.id ?? "en";
}

function systemLang(): Lang {
  return parseLang(navigator.languages?.[0] ?? navigator.language ?? "en");
}

export function loadLangPreference(): LangPreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (LANGS.some((l) => l.id === v)) return v as Lang;
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
  let text = CATALOGS[current]?.[en] ?? en;
  if (vars) for (const [k, v] of Object.entries(vars)) text = text.split(`{${k}}`).join(String(v));
  return text;
}
