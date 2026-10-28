//! User-facing text in English and Simplified Chinese.
//!
//! Code holds the English text; each crate ships a catalog that maps that English text to Chinese
//! (gettext style). A missing entry falls back to English instead of failing, so a rule pack
//! updated without a release still shows something readable. Every crate has a test that each
//! `tr!` literal has an entry, so missing translations are caught before a release.
//!
//! The language is process-wide: the CLI picks it once at startup and the App sets it when the
//! user switches, and nothing in a single process needs two languages at once.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    ZhHans,
}

impl Lang {
    /// Accepts BCP 47 tags and POSIX locales: `zh`, `zh-Hans`, `zh_CN.UTF-8` → Chinese; anything else → English.
    /// Traditional Chinese falls back to English rather than showing Simplified characters.
    pub fn parse(tag: &str) -> Lang {
        let t = tag.trim().to_ascii_lowercase().replace('_', "-");
        let is_traditional = ["hant", "-tw", "-hk", "-mo"].iter().any(|m| t.contains(m));
        if (t == "zh" || t.starts_with("zh-")) && !is_traditional { Lang::ZhHans } else { Lang::En }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhHans => "zh-Hans",
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(lang: Lang) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    if CURRENT.load(Ordering::Relaxed) == Lang::ZhHans as u8 { Lang::ZhHans } else { Lang::En }
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

/// One crate's English → Chinese table, parsed on first use.
pub struct Catalog {
    zh_hans: LazyLock<HashMap<String, String>>,
}

impl Catalog {
    pub const fn new(parse: fn() -> HashMap<String, String>) -> Self {
        Catalog { zh_hans: LazyLock::new(parse) }
    }

    /// The text in the current language; English when there is no entry.
    pub fn get<'a>(&'a self, en: &'a str) -> &'a str {
        match lang() {
            Lang::En => en,
            Lang::ZhHans => self.zh_hans.get(en).map(String::as_str).unwrap_or(en),
        }
    }

    pub fn has(&self, en: &str) -> bool {
        self.zh_hans.contains_key(en)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.zh_hans.keys().map(String::as_str)
    }
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

/// Checks a crate's catalog against its sources: every `tr!` literal has a Chinese entry and every entry is used.
/// `extra` lists keys used without `tr!` (rule pack messages and the like).
pub fn check_catalog(catalog: &Catalog, sources: &[&str], extra: &[&str]) -> Result<(), String> {
    let used: std::collections::BTreeSet<String> = sources.iter().flat_map(|s| tr_literals(s)).chain(extra.iter().map(|s| s.to_string())).collect();
    let missing: Vec<&String> = used.iter().filter(|k| !catalog.has(k)).collect();
    let unused: Vec<&str> = catalog.keys().filter(|k| !used.contains(*k)).collect();
    if missing.is_empty() && unused.is_empty() {
        Ok(())
    } else {
        Err(format!("missing zh-Hans entries: {missing:#?}\nunused zh-Hans entries: {unused:#?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locale_tags() {
        for zh in ["zh", "zh-Hans", "zh-Hans-CN", "zh_CN.UTF-8", "zh-CN", "zh-SG"] {
            assert_eq!(Lang::parse(zh), Lang::ZhHans, "{zh}");
        }
        for en in ["en", "en-US", "en_GB.UTF-8", "de-DE", "zh-Hant", "zh-TW", "zh_HK.UTF-8", ""] {
            assert_eq!(Lang::parse(en), Lang::En, "{en}");
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
