//! YARA 规则：从公开规则库下载，用 YARA-X 编译成一个文件，检查时直接加载。

use super::{SourceStatus, dir, file_mtime, github_head, github_tarball, write_atomic};
use crate::rules::{Finding, Severity};
use crate::store;
use regex::Regex;
use std::path::Path;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

const COMPILED: &str = "rules.yarac";

pub struct YaraSource {
    pub id: &'static str,
    pub name: &'static str,
    pub license: &'static str,
    pub url: &'static str,
    /// (仓库, 分支)；None 表示读本机文件
    repo: Option<(&'static str, &'static str)>,
    local: Option<&'static str>,
    /// 仓库里哪些文件是要用的规则
    wanted: fn(&str) -> bool,
    /// 命中时的严重度：恶意软件家族特征算高危；GuardDog 是“可疑写法”，算中危
    severity: Severity,
}

pub const SOURCES: &[YaraSource] = &[
    YaraSource {
        id: "elastic",
        name: "Elastic 恶意软件规则",
        license: "Elastic License 2.0",
        url: "https://github.com/elastic/protections-artifacts",
        repo: Some(("elastic/protections-artifacts", "main")),
        local: None,
        wanted: |p| p.starts_with("yara/rules/") && p.ends_with(".yar"),
        severity: Severity::High,
    },
    YaraSource {
        id: "reversinglabs",
        name: "ReversingLabs 规则",
        license: "MIT",
        url: "https://github.com/reversinglabs/reversinglabs-yara-rules",
        repo: Some(("reversinglabs/reversinglabs-yara-rules", "develop")),
        local: None,
        wanted: |p| p.starts_with("yara/") && p.ends_with(".yara"),
        severity: Severity::High,
    },
    YaraSource {
        id: "guarddog",
        name: "GuardDog 恶意包规则",
        license: "Apache-2.0",
        url: "https://github.com/DataDog/guarddog",
        repo: Some(("DataDog/guarddog", "v3")),
        local: None,
        // capability-* 只是描述“会联网”“会读文件”这类能力，正常包也有，只要 threat-*。
        // 即使是 threat-* 也是“可疑写法”而不是恶意软件特征：在真实扩展上实测，
        // 33 个正常扩展里有 20 个会被它判成拦截（Claude Code、debugpy 等大型打包代码）。
        // 所以只算低风险，作为证据交给 AI 结合上下文判断
        wanted: |p| p.starts_with("guarddog/analyzer/sourcecode/threat-") && p.ends_with(".yar"),
        severity: Severity::Low,
    },
    YaraSource {
        id: "xprotect",
        name: "本机 XProtect 规则",
        license: "Apple（只在本机使用，不分发）",
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

/// 把一个来源的规则文件下载到 ~/.tsuba/intel/yara/<id>/，原样保存，方便查看。
pub fn update_source(src: &YaraSource, old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus { id: src.id.into(), name: src.name.into(), license: src.license.into(), url: src.url.into(), ..Default::default() };
    let target = source_dir(src.id);
    let version = match (src.repo, src.local) {
        (Some((repo, branch)), _) => github_head(repo, branch),
        (None, Some(path)) if Path::new(path).is_file() => Ok(file_mtime(Path::new(path))),
        _ => Err("本机没有这个文件".to_string()),
    };
    let version = match version {
        Ok(v) => v,
        Err(e) => {
            s.error = Some(format!("无法检查更新：{e}"));
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
        s.error = Some(format!("下载失败：{e}"));
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

/// 整个文件编译失败时，拆成一条条规则分别编译，只丢掉不兼容的那几条。
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

/// 把所有来源的规则编译成一个文件。每个来源一个命名空间，命中时能知道是哪家的规则。
pub fn compile_all() -> SourceStatus {
    let mut s = SourceStatus { id: "yara".into(), name: "YARA 规则（编译后）".into(), license: "-".into(), url: String::new(), ..Default::default() };
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
        Err(e) => s.error = Some(format!("保存编译结果失败：{e}")),
    }
    s.count = ok;
    s.version = format!("{ok} 条可用，{skipped} 条与 YARA-X 不兼容已跳过");
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

/// 用全部 YARA 规则扫一段内容。没有规则（还没更新过）时什么都不做。
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
            let source_name = src.map(|s| s.name).unwrap_or(ns);
            let detail = desc.map(|d| format!("：{d}")).unwrap_or_default();
            let (sev, msg) = match src.map(|s| s.severity) {
                Some(sev @ (Severity::Low | Severity::Medium)) => (sev, format!("{source_name}提示可疑写法 {}{detail}", r.identifier())),
                _ => (Severity::High, format!("命中已知恶意软件特征 {}（{source_name}）{detail}", r.identifier())),
            };
            Finding::new(sev, msg, location)
        })
        .collect()
}

/// 扫一个文件（读不了或太大就跳过）。
pub fn scan_file(path: &Path, location: &str) -> Vec<Finding> {
    if rules().is_none() || path.metadata().map(|m| m.len() > 64 * 1024 * 1024).unwrap_or(true) {
        return vec![];
    }
    std::fs::read(path).map(|b| scan(&b, location)).unwrap_or_default()
}
