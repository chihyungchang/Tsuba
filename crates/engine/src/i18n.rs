//! User-facing text in English and the other supported languages.
//!
//! Code holds the English text; each crate ships one catalog per language (`locales/<code>.json`) that maps that
//! English text to the translation (gettext style). A missing entry falls back to English instead of failing, so a
//! rule pack updated without a release still shows something readable. Every crate has a test that each `tr!`
//! literal has an entry in every catalog, so missing translations are caught before a release.
//!
//! The language is process-wide: the CLI picks it once at startup and the App sets it when the
//! user switches, and nothing in a single process needs two languages at once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lang {
    En,
    ZhHans,
    ZhHant,
    Ja,
    Ko,
    Es,
    Fr,
    De,
    PtBr,
    Ru,
}

impl Lang {
    /// Every supported language, English first. The order is the index stored in the process-wide setting.
    pub const ALL: [Lang; 10] = [Lang::En, Lang::ZhHans, Lang::ZhHant, Lang::Ja, Lang::Ko, Lang::Es, Lang::Fr, Lang::De, Lang::PtBr, Lang::Ru];

    /// Accepts BCP 47 tags and POSIX locales by their language subtag: `zh_CN.UTF-8` → zh-Hans, `zh-TW` → zh-Hant,
    /// `ja-JP` → ja, any Portuguese → pt-BR; anything unsupported → English.
    pub fn parse(tag: &str) -> Lang {
        let t = tag.trim().to_ascii_lowercase().replace('_', "-");
        let primary = t.split(['-', '.', '@']).next().unwrap_or("");
        match primary {
            "zh" if ["hant", "-tw", "-hk", "-mo"].iter().any(|m| t.contains(m)) => Lang::ZhHant,
            "zh" => Lang::ZhHans,
            "ja" => Lang::Ja,
            "ko" => Lang::Ko,
            "es" => Lang::Es,
            "fr" => Lang::Fr,
            "de" => Lang::De,
            "pt" => Lang::PtBr,
            "ru" => Lang::Ru,
            _ => Lang::En,
        }
    }

    /// The BCP 47 code, also the catalog file name and the value stored in the config
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhHans => "zh-Hans",
            Lang::ZhHant => "zh-Hant",
            Lang::Ja => "ja",
            Lang::Ko => "ko",
            Lang::Es => "es",
            Lang::Fr => "fr",
            Lang::De => "de",
            Lang::PtBr => "pt-BR",
            Lang::Ru => "ru",
        }
    }

    /// How to name the language to a model, so it answers in it
    pub fn english_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::ZhHans => "Simplified Chinese (简体中文)",
            Lang::ZhHant => "Traditional Chinese (繁體中文)",
            Lang::Ja => "Japanese (日本語)",
            Lang::Ko => "Korean (한국어)",
            Lang::Es => "Spanish (Español)",
            Lang::Fr => "French (Français)",
            Lang::De => "German (Deutsch)",
            Lang::PtBr => "Brazilian Portuguese (Português)",
            Lang::Ru => "Russian (Русский)",
        }
    }

    /// The rule pack meta key holding a rule's message in this language. Simplified Chinese keeps `message_zh`,
    /// which packs already in the wild carry; English is the plain `message`.
    pub fn rule_message_key(self) -> &'static str {
        match self {
            Lang::En => "message",
            Lang::ZhHans => "message_zh",
            Lang::ZhHant => "message_zh_hant",
            Lang::Ja => "message_ja",
            Lang::Ko => "message_ko",
            Lang::Es => "message_es",
            Lang::Fr => "message_fr",
            Lang::De => "message_de",
            Lang::PtBr => "message_pt_br",
            Lang::Ru => "message_ru",
        }
    }

    fn index(self) -> u8 {
        Lang::ALL.iter().position(|l| *l == self).unwrap_or(0) as u8
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(lang: Lang) {
    CURRENT.store(lang.index(), Ordering::Relaxed);
}

pub fn lang() -> Lang {
    Lang::ALL.get(CURRENT.load(Ordering::Relaxed) as usize).copied().unwrap_or(Lang::En)
}

/// The user's language: POSIX locale variables first (what a terminal user set on purpose),
/// then the first of the macOS preferred languages, for GUI apps and shells where LANG is unset or "C".
pub fn system_lang() -> Lang {
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(key)
            && !v.is_empty()
            && v != "C"
            && v != "POSIX"
            && !v.starts_with("C.")
        {
            return Lang::parse(&v);
        }
    }
    // Read the preferences file instead of running `defaults`: the terminal check runs before every command.
    let prefs = crate::home_dir().join("Library/Preferences/.GlobalPreferences.plist");
    if let Ok(plist::Value::Dictionary(d)) = plist::Value::from_file(prefs)
        && let Some(first) = d.get("AppleLanguages").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_string())
    {
        return Lang::parse(first);
    }
    Lang::En
}

/// One crate's English → translation tables, one per language other than English, parsed on first use.
/// Build it with `catalog!("../locales")`, which compiles every language's file in.
pub struct Catalog {
    load: fn() -> Vec<(Lang, &'static str)>,
    tables: OnceLock<HashMap<Lang, HashMap<String, String>>>,
}

impl Catalog {
    pub const fn new(load: fn() -> Vec<(Lang, &'static str)>) -> Self {
        Catalog { load, tables: OnceLock::new() }
    }

    fn tables(&self) -> &HashMap<Lang, HashMap<String, String>> {
        self.tables.get_or_init(|| (self.load)().into_iter().map(|(lang, json)| (lang, parse_catalog(json))).collect())
    }

    /// The text in the current language; English when there is no entry.
    pub fn get<'a>(&'a self, en: &'a str) -> &'a str {
        match lang() {
            Lang::En => en,
            other => self.tables().get(&other).and_then(|t| t.get(en)).map(String::as_str).unwrap_or(en),
        }
    }

    /// Each translated language with its table, for the completeness test
    pub fn languages(&self) -> impl Iterator<Item = (Lang, &HashMap<String, String>)> {
        self.tables().iter().map(|(lang, table)| (*lang, table))
    }
}

/// `catalog!("../locales")`: a crate's catalog with every language's `<code>.json` compiled in. The path is relative
/// to the file using it, like `include_str!`.
#[macro_export]
macro_rules! catalog {
    ($dir:literal) => {
        $crate::i18n::Catalog::new(|| {
            use $crate::i18n::Lang;
            vec![
                (Lang::ZhHans, include_str!(concat!($dir, "/zh-Hans.json"))),
                (Lang::ZhHant, include_str!(concat!($dir, "/zh-Hant.json"))),
                (Lang::Ja, include_str!(concat!($dir, "/ja.json"))),
                (Lang::Ko, include_str!(concat!($dir, "/ko.json"))),
                (Lang::Es, include_str!(concat!($dir, "/es.json"))),
                (Lang::Fr, include_str!(concat!($dir, "/fr.json"))),
                (Lang::De, include_str!(concat!($dir, "/de.json"))),
                (Lang::PtBr, include_str!(concat!($dir, "/pt-BR.json"))),
                (Lang::Ru, include_str!(concat!($dir, "/ru.json"))),
            ]
        })
    };
}

/// Parses a catalog file. Panics on bad JSON: catalogs are compiled in, so the catalog test catches it.
pub fn parse_catalog(json: &str) -> HashMap<String, String> {
    serde_json::from_str(json).expect("invalid translation catalog")
}

/// Replaces `{name}` placeholders. Named rather than positional, because word order differs between languages.
pub fn fill(template: &str, args: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// `tr_in!(CATALOG, "Found {n} files", n = count)`. Each crate wraps this in its own `tr!`.
#[macro_export]
macro_rules! tr_in {
    ($catalog:expr, $en:literal) => {
        $catalog.get($en).to_string()
    };
    ($catalog:expr, $en:literal, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::fill($catalog.get($en), &[$((stringify!($name), $value.to_string())),+])
    };
}

/// English literals passed to `tr!` in a crate's sources, for the catalog completeness test.
/// Only single-line literals are recognized, so keep `tr!` strings on one line. Comment lines are skipped.
pub fn tr_literals(source: &str) -> Vec<String> {
    static CALL: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"\btr!\(\s*"((?:[^"\\]|\\.)*)""#).unwrap());
    let code: String = source.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    CALL.captures_iter(&code).map(|c| c[1].replace("\\\"", "\"").replace("\\n", "\n").replace("\\\\", "\\")).collect()
}

/// Contents of every `.rs` file under `dir`, for the catalog completeness test.
pub fn read_sources(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            // i18n.rs itself only has `tr!` examples in docs and tests
            } else if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("i18n.rs") {
                out.push(std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    out
}

/// Checks a crate's catalogs against its sources: in every language, each `tr!` literal has an entry, every entry is
/// used, and every entry keeps the English text's `{placeholders}` (a lost one would print a raw value nowhere).
/// `extra` lists keys used without `tr!` (rule pack messages and the like).
pub fn check_catalog(catalog: &Catalog, sources: &[&str], extra: &[&str]) -> Result<(), String> {
    static PLACEHOLDER: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\{\w+\}").unwrap());
    let used: std::collections::BTreeSet<String> = sources.iter().flat_map(|s| tr_literals(s)).chain(extra.iter().map(|s| s.to_string())).collect();
    let mut problems = Vec::new();
    for (lang, table) in catalog.languages() {
        let code = lang.code();
        let missing: Vec<&String> = used.iter().filter(|k| !table.contains_key(*k)).collect();
        let unused: Vec<&String> = table.keys().filter(|k| !used.contains(*k)).collect();
        let placeholders = |text: &str| PLACEHOLDER.find_iter(text).map(|m| m.as_str().to_string()).collect::<std::collections::BTreeSet<_>>();
        let broken: Vec<&String> = table.iter().filter(|(en, text)| placeholders(en) != placeholders(text)).map(|(en, _)| en).collect();
        if !missing.is_empty() {
            problems.push(format!("missing {code} entries: {missing:#?}"));
        }
        if !unused.is_empty() {
            problems.push(format!("unused {code} entries: {unused:#?}"));
        }
        if !broken.is_empty() {
            problems.push(format!("{code} entries with different placeholders: {broken:#?}"));
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locale_tags() {
        for zh in ["zh", "zh-Hans", "zh-Hans-CN", "zh_CN.UTF-8", "zh-CN", "zh-SG"] {
            assert_eq!(Lang::parse(zh), Lang::ZhHans, "{zh}");
        }
        for hant in ["zh-Hant", "zh-TW", "zh_HK.UTF-8", "zh-Hant-MO"] {
            assert_eq!(Lang::parse(hant), Lang::ZhHant, "{hant}");
        }
        for (tag, lang) in [("ja_JP.UTF-8", Lang::Ja), ("ko-KR", Lang::Ko), ("es-419", Lang::Es), ("fr-CA", Lang::Fr), ("de-DE", Lang::De), ("pt-PT", Lang::PtBr), ("pt_BR", Lang::PtBr), ("ru", Lang::Ru)] {
            assert_eq!(Lang::parse(tag), lang, "{tag}");
        }
        for en in ["en", "en-US", "en_GB.UTF-8", "it-IT", "", "C"] {
            assert_eq!(Lang::parse(en), Lang::En, "{en}");
        }
        for lang in Lang::ALL {
            assert_eq!(Lang::parse(lang.code()), lang, "codes round-trip");
        }
    }

    #[test]
    fn fills_named_placeholders_in_any_order() {
        assert_eq!(fill("{b} 之后 {a}", &[("a", "1".into()), ("b", "2".into())]), "2 之后 1");
    }

    #[test]
    fn finds_tr_literals() {
        let src = r#"let a = tr!("Scanned {n} files", n = 3); tr!( "Say \"hi\"" ); not_tr!("x");"#;
        assert_eq!(tr_literals(src), vec!["Scanned {n} files", "Say \"hi\""]);
    }
}
