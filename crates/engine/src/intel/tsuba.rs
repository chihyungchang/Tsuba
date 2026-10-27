//! Tsuba 自己的规则包：tsuba.yar（检测模式）+ tsuba.toml（名单）。
//!
//! 内置一份随程序发布；设置了规则包地址时，每天和其他情报一起更新到 ~/.tsuba/intel/tsuba/。
//! 下载的版本能编译、版本号不比内置的旧才会用，否则退回内置版本。

use super::{SourceStatus, agent, dir};
use crate::rules::{self, Finding, Severity};
use crate::store;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

const BUNDLED_YAR: &str = include_str!("../../rules/tsuba.yar");
const BUNDLED_TOML: &str = include_str!("../../rules/tsuba.toml");

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Lists {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub well_known_hosts: Vec<String>,
    #[serde(default)]
    pub ioc_paths: Vec<String>,
    #[serde(default)]
    pub launch_agent_markers: Vec<String>,
}

struct RuleMeta {
    severity: Severity,
    message: String,
    skip_quoted: bool,
    doc_keep: bool,
}

struct Pack {
    rules: yara_x::Rules,
    meta: HashMap<String, RuleMeta>,
    lists: Lists,
    /// 规则包来源：内置 / 已更新
    origin: &'static str,
}

fn meta_str<'a>(m: &'a [(&'a str, yara_x::MetaValue<'a>)], key: &str) -> Option<&'a str> {
    m.iter().find_map(|(k, v)| match v {
        yara_x::MetaValue::String(s) if *k == key => Some(*s),
        _ => None,
    })
}

fn meta_bool(m: &[(&str, yara_x::MetaValue)], key: &str) -> bool {
    m.iter().any(|(k, v)| *k == key && matches!(v, yara_x::MetaValue::Bool(true)))
}

fn compile(yar: &str, toml_text: &str, origin: &'static str) -> Result<Pack, String> {
    let lists: Lists = toml::from_str(toml_text).map_err(|e| format!("tsuba.toml 格式错误：{e}"))?;
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(yar).map_err(|e| format!("tsuba.yar 编译失败：{e}"))?;
    let rules = compiler.build();
    let mut meta = HashMap::new();
    for r in rules.iter() {
        let m: Vec<(&str, yara_x::MetaValue)> = r.metadata().collect();
        let severity = match meta_str(&m, "severity") {
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            _ => Severity::Low,
        };
        meta.insert(
            r.identifier().to_string(),
            RuleMeta {
                severity,
                message: meta_str(&m, "message").unwrap_or(r.identifier()).to_string(),
                skip_quoted: meta_bool(&m, "skip_quoted"),
                doc_keep: meta_bool(&m, "doc_keep"),
            },
        );
    }
    Ok(Pack { rules, meta, lists, origin })
}

fn pack() -> &'static Pack {
    static PACK: OnceLock<Pack> = OnceLock::new();
    PACK.get_or_init(|| {
        let bundled_version = toml::from_str::<Lists>(BUNDLED_TOML).map(|l| l.version).unwrap_or_default();
        let d = dir().join("tsuba");
        if let (Ok(yar), Ok(t)) = (std::fs::read_to_string(d.join("tsuba.yar")), std::fs::read_to_string(d.join("tsuba.toml")))
            && let Ok(p) = compile(&yar, &t, "已更新")
                && p.lists.version >= bundled_version {
                    return p;
                }
        compile(BUNDLED_YAR, BUNDLED_TOML, "内置").expect("内置规则包必须能编译")
    })
}

pub fn lists() -> &'static Lists {
    &pack().lists
}

/// 这条规则在说明文档里命中时是否保持原有严重度
pub fn doc_keep(rule: &str) -> bool {
    pack().meta.get(rule).is_some_and(|m| m.doc_keep)
}

/// 被引号包住：在引用攻击话术（安全提示、文档），不是在下命令
fn quoted(text: &str, start: usize) -> bool {
    text.get(..start).and_then(|t| t.chars().next_back()).is_some_and(|c| matches!(c, '"' | '“' | '\'' | '‘' | '`' | '「'))
}

pub fn scan(text: &str, location: &str) -> Vec<Finding> {
    let p = pack();
    let mut scanner = yara_x::Scanner::new(&p.rules);
    scanner.set_timeout(Duration::from_secs(5));
    let Ok(results) = scanner.scan(text.as_bytes()) else { return vec![] };
    let mut out = Vec::new();
    for r in results.matching_rules() {
        let Some(m) = p.meta.get(r.identifier()) else { continue };
        let mut ranges: Vec<std::ops::Range<usize>> = r.patterns().flat_map(|pat| pat.matches().map(|x| x.range()).collect::<Vec<_>>()).collect();
        ranges.sort_by_key(|x| x.start);
        let hit = if m.skip_quoted { ranges.into_iter().find(|x| !quoted(text, x.start)) } else { ranges.into_iter().next() };
        let Some(hit) = hit else { continue };
        let mut f = Finding::new(m.severity, m.message.clone(), location).with_snippet(rules::snippet(text, hit.start, hit.end, 120));
        f.rule = r.identifier().to_string();
        out.push(f);
    }
    out
}

/// 规则包更新：设置了地址就下载 tsuba.yar 和 tsuba.toml，编译通过才替换。
pub fn update(url: &str) -> SourceStatus {
    let p = pack();
    let mut s = SourceStatus {
        id: "tsuba".into(),
        name: "Tsuba 规则".into(),
        license: "Apache-2.0".into(),
        url: url.into(),
        count: p.meta.len(),
        version: format!("{}（{}）", p.lists.version, p.origin),
        updated: store::now(),
        ..Default::default()
    };
    if url.is_empty() {
        return s;
    }
    let get = |name: &str| -> Result<String, String> {
        agent(30).get(&format!("{}/{name}", url.trim_end_matches('/'))).call().map_err(|e| e.to_string())?.into_string().map_err(|e| e.to_string())
    };
    let (yar, t) = match (get("tsuba.yar"), get("tsuba.toml")) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            s.error = Some(format!("下载失败：{e}"));
            return s;
        }
    };
    let new = match compile(&yar, &t, "已更新") {
        Ok(n) => n,
        Err(e) => {
            s.error = Some(e);
            return s;
        }
    };
    let d = dir().join("tsuba");
    if let Err(e) = std::fs::create_dir_all(&d).and_then(|_| std::fs::write(d.join("tsuba.yar"), &yar)).and_then(|_| std::fs::write(d.join("tsuba.toml"), &t)) {
        s.error = Some(e.to_string());
        return s;
    }
    s.count = new.meta.len();
    s.version = format!("{}（已更新，下次检查生效）", new.lists.version);
    s
}

/// 内置规则包必须能编译：给测试用
pub fn bundled_ok() -> Result<usize, String> {
    compile(BUNDLED_YAR, BUNDLED_TOML, "内置").map(|p| p.meta.len())
}
