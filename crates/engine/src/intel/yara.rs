//! YARA rules: downloaded from public rule repositories and compiled with YARA-X into one file that checks load directly.

use super::{Label, SourceStatus, dir, file_mtime, github_head, github_tarball, write_atomic};
use crate::rules::{Finding, Severity};
use crate::store;
use regex::Regex;
use std::path::Path;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

const COMPILED: &str = "rules.yarac";

pub struct YaraSource {
    pub id: &'static str,
    pub name: Label,
    pub license: Label,
    pub url: &'static str,
    /// (repository, branch); None means a local file
    repo: Option<(&'static str, &'static str)>,
    local: Option<&'static str>,
    /// Which files in the repository are the rules to use
    wanted: fn(&str) -> bool,
    /// Severity of a match: malware family signatures are high; GuardDog flags "suspicious patterns" and counts lower
    severity: Severity,
}

pub const SOURCES: &[YaraSource] = &[
    YaraSource {
        id: "elastic",
        name: Label::Localized(|| tr!("Elastic malware rules")),
        license: Label::Fixed("Elastic License 2.0"),
        url: "https://github.com/elastic/protections-artifacts",
        repo: Some(("elastic/protections-artifacts", "main")),
        local: None,
        wanted: |p| p.starts_with("yara/rules/") && p.ends_with(".yar"),
        severity: Severity::High,
    },
    YaraSource {
        id: "reversinglabs",
        name: Label::Localized(|| tr!("ReversingLabs rules")),
        license: Label::Fixed("MIT"),
        url: "https://github.com/reversinglabs/reversinglabs-yara-rules",
        repo: Some(("reversinglabs/reversinglabs-yara-rules", "develop")),
        local: None,
        wanted: |p| p.starts_with("yara/") && p.ends_with(".yara"),
        severity: Severity::High,
    },
    YaraSource {
        id: "guarddog",
        name: Label::Localized(|| tr!("GuardDog malicious package rules")),
        license: Label::Fixed("Apache-2.0"),
        url: "https://github.com/DataDog/guarddog",
        repo: Some(("DataDog/guarddog", "v3")),
        local: None,
        // capability-* only describes abilities like "uses the network" or "reads files" that normal packages have too; take threat-* only.
        // Even threat-* is "suspicious patterns" rather than malware signatures: measured on real extensions,
        // it would block 20 of 33 normal ones (large bundles such as Claude Code and debugpy).
        // So it only counts as low risk, evidence for the AI to judge in context
        wanted: |p| p.starts_with("guarddog/analyzer/sourcecode/threat-") && p.ends_with(".yar"),
        severity: Severity::Low,
    },
    YaraSource {
        id: "xprotect",
        name: Label::Localized(|| tr!("XProtect rules on this Mac")),
        license: Label::Localized(|| tr!("Apple (used on this Mac only, not redistributed)")),
        url: "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
        repo: None,
        local: Some("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"),
        wanted: |_| true,
        severity: Severity::High,
    },
];

fn source_dir(id: &str) -> std::path::PathBuf {
    dir().join("yara").join(id)
}

/// Downloads one source's rule files into ~/.tsuba/intel/yara/<id>/, saved as is so they're easy to inspect.
pub fn update_source(src: &YaraSource, old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus { id: src.id.into(), name: src.name.to_string(), license: src.license.to_string(), url: src.url.into(), ..Default::default() };
    let target = source_dir(src.id);
    let version = match (src.repo, src.local) {
        (Some((repo, branch)), _) => github_head(repo, branch),
        (None, Some(path)) if Path::new(path).is_file() => Ok(file_mtime(Path::new(path))),
        _ => Err(tr!("This file doesn't exist on this Mac")),
    };
    let version = match version {
        Ok(v) => v,
        Err(e) => {
            s.error = Some(tr!("Couldn't check for updates: {error}", error = e));
            return s;
        }
    };
    if old.is_some_and(|o| o.version == version && o.error.is_none()) && target.is_dir() {
        return old.cloned().unwrap();
    }
    let staging = dir().join("yara").join(format!(".{}.new", src.id));
    let _ = std::fs::remove_dir_all(&staging);
    if let Err(e) = std::fs::create_dir_all(&staging) {
        s.error = Some(e.to_string());
        return s;
    }
    let mut count = 0usize;
    let res = match (src.repo, src.local) {
        (Some((repo, branch)), _) => github_tarball(repo, branch, |path, bytes| {
            if (src.wanted)(path) {
                let flat = path.replace('/', "__");
                if std::fs::write(staging.join(flat), bytes).is_ok() {
                    count += 1;
                }
            }
        }),
        (None, Some(path)) => std::fs::copy(path, staging.join("XProtect.yara")).map(|_| count = 1).map_err(|e| e.to_string()),
        _ => Ok(()),
    };
    if let Err(e) = res {
        s.error = Some(tr!("Download failed: {error}", error = e));
        let _ = std::fs::remove_dir_all(&staging);
        return s;
    }
    let _ = std::fs::remove_dir_all(&target);
    if let Err(e) = std::fs::rename(&staging, &target) {
        s.error = Some(e.to_string());
        return s;
    }
    s.version = version;
    s.count = count;
    s.updated = store::now();
    s
}

static IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^\s*import\s+"[^"]+"\s*$"#).unwrap());
static RULE_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+\w+").unwrap());

/// When a whole file fails to compile, compile it rule by rule and drop only the incompatible ones.
fn add_file(compiler: &mut yara_x::Compiler, text: &str) -> (usize, usize) {
    let total = RULE_START.find_iter(text).count();
    if compiler.add_source(text).is_ok() {
        return (total, 0);
    }
    let imports: String = IMPORT.find_iter(text).map(|m| m.as_str().trim().to_string() + "\n").collect();
    let starts: Vec<usize> = RULE_START.find_iter(text).map(|m| m.start()).collect();
    let (mut ok, mut skipped) = (0, 0);
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(text.len());
        let one = format!("{imports}{}", &text[start..end]);
        if compiler.add_source(one.as_str()).is_ok() {
            ok += 1;
        } else {
            skipped += 1;
        }
    }
    (ok, skipped)
}

/// Compiles every source's rules into one file. One namespace per source, so a match tells whose rule it was.
pub fn compile_all() -> SourceStatus {
    let mut s = SourceStatus { id: "yara".into(), name: super::YARA_COMPILED.0.to_string(), license: super::YARA_COMPILED.1.to_string(), url: String::new(), ..Default::default() };
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    let (mut ok, mut skipped) = (0, 0);
    for src in SOURCES {
        let Ok(rd) = std::fs::read_dir(source_dir(src.id)) else { continue };
        compiler.new_namespace(src.id);
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            let (a, b) = add_file(&mut compiler, &text);
            ok += a;
            skipped += b;
        }
    }
    let rules = compiler.build();
    match rules.serialize() {
        Ok(bytes) => {
            if let Err(e) = write_atomic(COMPILED, &bytes) {
                s.error = Some(e.to_string());
            }
        }
        Err(e) => s.error = Some(tr!("Couldn't save the compiled rules: {error}", error = e)),
    }
    // The version is shown as "N usable, M skipped" when displayed, from these two numbers
    s.count = ok;
    s.skipped = skipped;
    s.updated = store::now();
    s
}

fn rules() -> Option<&'static yara_x::Rules> {
    static RULES: OnceLock<Option<yara_x::Rules>> = OnceLock::new();
    RULES.get_or_init(|| std::fs::read(dir().join(COMPILED)).ok().and_then(|b| yara_x::Rules::deserialize(b).ok())).as_ref()
}

pub fn available() -> bool {
    rules().is_some()
}

/// Scans content with all YARA rules. Does nothing when there are no rules yet (never updated).
pub fn scan(data: &[u8], location: &str) -> Vec<Finding> {
    let Some(rules) = rules() else { return vec![] };
    if data.is_empty() || data.len() > 64 * 1024 * 1024 {
        return vec![];
    }
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(Duration::from_secs(5));
    let Ok(results) = scanner.scan(data) else { return vec![] };
    results
        .matching_rules()
        .take(10)
        .map(|r| {
            let ns = r.namespace();
            let src = SOURCES.iter().find(|s| s.id == ns);
            let desc = r.metadata().find_map(|(k, v)| match (k, v) {
                ("description" | "threat_name" | "malware", yara_x::MetaValue::String(s)) => Some(s.to_string()),
                _ => None,
            });
            let source_name = src.map(|s| s.name.to_string()).unwrap_or_else(|| ns.to_string());
            let rule = r.identifier();
            let (sev, msg) = match (src.map(|s| s.severity), desc) {
                (Some(sev @ (Severity::Low | Severity::Medium)), Some(d)) => (sev, tr!("{source} flags a suspicious pattern {rule}: {description}", source = source_name, rule = rule, description = d)),
                (Some(sev @ (Severity::Low | Severity::Medium)), None) => (sev, tr!("{source} flags a suspicious pattern {rule}", source = source_name, rule = rule)),
                (_, Some(d)) => (Severity::High, tr!("Matches known malware signature {rule} ({source}): {description}", rule = rule, source = source_name, description = d)),
                (_, None) => (Severity::High, tr!("Matches known malware signature {rule} ({source})", rule = rule, source = source_name)),
            };
            let finding = Finding::new(sev, msg, location);
            match src {
                Some(s) => finding.with_source((s.name, s.license)),
                None => finding,
            }
        })
        .collect()
}

/// Scans one file (skipped when unreadable or too large).
pub fn scan_file(path: &Path, location: &str) -> Vec<Finding> {
    if rules().is_none() || path.metadata().map(|m| m.len() > 64 * 1024 * 1024).unwrap_or(true) {
        return vec![];
    }
    std::fs::read(path).map(|b| scan(&b, location)).unwrap_or_default()
}
