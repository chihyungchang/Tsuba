//! Tsuba 自己的规则包：tsuba.yar（检测模式）+ tsuba.toml（名单）。
//!
//! 内置一份随程序发布；设置了规则包地址时，每天和其他情报一起更新到 ~/.tsuba/intel/tsuba/。
//! 下载的版本要签名对得上、能编译、版本号不比正在用的旧才会用，否则退回内置版本。
//!
//! 更新通道本身就是供应链：谁能改规则包，谁就能让 Tsuba 放行恶意代码（删掉一条规则就够了）。
//! 所以只认用 Tsuba 发布私钥签过名的规则包，下载时和每次加载时都验签；回滚到旧版本也拒绝。

use super::{SourceStatus, agent, dir};
use crate::rules::{self, Finding, Severity};
use crate::store;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

/// 信任的规则包签名公钥（ed25519，十六进制）。换钥匙时新旧并存一段时间。
/// 生成：`tsuba rules keygen <私钥文件>`，把打印出的公钥加到这里；私钥只放在发布规则包的机器上，不进仓库。
/// 列表为空时任何下载的规则包都不会被使用，只用内置规则。
pub const TRUSTED_KEYS: &[&str] = &[];

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
    skip_well_known: bool,
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
                skip_well_known: meta_bool(&m, "skip_well_known"),
            },
        );
    }
    Ok(Pack { rules, meta, lists, origin })
}

/// 签名覆盖的内容：两个文件的 SHA-256，带上格式版本，避免把别的东西的签名拿来冒充。
fn signed_message(yar: &str, toml_text: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    format!("tsuba-rules-v1\n{}\n{}\n", crate::net::hex(&Sha256::digest(yar)), crate::net::hex(&Sha256::digest(toml_text))).into_bytes()
}

/// 用发布私钥（32 字节种子）给规则包签名，返回十六进制签名，写进 tsuba.sig。
pub fn sign(yar: &str, toml_text: &str, secret: &[u8; 32]) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(secret);
    crate::net::hex(&key.sign(&signed_message(yar, toml_text)).to_bytes())
}

/// 私钥种子对应的公钥（十六进制）。
pub fn public_key(secret: &[u8; 32]) -> String {
    crate::net::hex(ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().as_bytes())
}

/// 签名能被其中一把信任的公钥验证通过。
pub fn verify(yar: &str, toml_text: &str, sig_hex: &str, keys: &[&str]) -> Result<(), String> {
    let sig: [u8; 64] = crate::net::unhex(sig_hex).and_then(|b| b.try_into().ok()).ok_or("规则包签名格式不对")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    let msg = signed_message(yar, toml_text);
    let ok = keys.iter().any(|k| {
        crate::net::unhex(k)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
            .is_some_and(|vk| vk.verify_strict(&msg, &sig).is_ok())
    });
    if ok { Ok(()) } else { Err("规则包签名验证失败，没有使用".into()) }
}

fn pack() -> &'static Pack {
    static PACK: OnceLock<Pack> = OnceLock::new();
    PACK.get_or_init(|| {
        let bundled_version = toml::from_str::<Lists>(BUNDLED_TOML).map(|l| l.version).unwrap_or_default();
        let d = dir().join("tsuba");
        let read = |name: &str| std::fs::read_to_string(d.join(name));
        // 本地缓存的规则包每次加载都重新验签：别的程序改了文件也不会被用上
        if let (Ok(yar), Ok(t), Ok(sig)) = (read("tsuba.yar"), read("tsuba.toml"), read("tsuba.sig"))
            && verify(&yar, &t, &sig, TRUSTED_KEYS).is_ok()
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

/// 片段里有网址，而且全是官方安装源（例如 curl https://astral.sh/uv/install.sh | sh）。
/// 没有网址的不算：看不出从哪下载，照常提醒。
fn only_well_known(span: &str) -> bool {
    let urls = crate::detect::urls_in(span);
    !urls.is_empty() && urls.iter().all(|u| crate::net::is_well_known(&crate::net::host_of(u)))
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
        let hit = ranges.into_iter().find(|x| !(m.skip_quoted && quoted(text, x.start)) && !(m.skip_well_known && only_well_known(&text[x.clone()])));
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
    let (yar, t, sig) = match (get("tsuba.yar"), get("tsuba.toml"), get("tsuba.sig")) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            s.error = Some(format!("下载失败：{e}"));
            return s;
        }
    };
    if let Err(e) = verify(&yar, &t, &sig, TRUSTED_KEYS) {
        s.error = Some(e);
        return s;
    }
    let new = match compile(&yar, &t, "已更新") {
        Ok(n) => n,
        Err(e) => {
            s.error = Some(e);
            return s;
        }
    };
    // 防回滚：签过名的旧版本也不接受（旧版本可能缺少后来补上的规则）
    if new.lists.version < p.lists.version {
        s.error = Some(format!("下载到的规则包版本 {} 比正在用的 {} 旧，没有使用", new.lists.version, p.lists.version));
        return s;
    }
    let d = dir().join("tsuba");
    let write = |name: &str, text: &str| std::fs::write(d.join(name), text);
    // 签名最后写：中途失败时留下的是验不过的组合，加载时会退回内置规则
    if let Err(e) = std::fs::create_dir_all(&d)
        .and_then(|_| std::fs::remove_file(d.join("tsuba.sig")).or(Ok(())))
        .and_then(|_| write("tsuba.yar", &yar))
        .and_then(|_| write("tsuba.toml", &t))
        .and_then(|_| write("tsuba.sig", &sig))
    {
        s.error = Some(e.to_string());
        return s;
    }
    s.count = new.meta.len();
    s.version = format!("{}（已更新，下次检查生效）", new.lists.version);
    s
}

/// 发布前检查规则包能编译。
pub fn check_pack(yar: &str, toml_text: &str) -> Result<(), String> {
    compile(yar, toml_text, "已更新").map(|_| ())
}

/// 内置规则包必须能编译：给测试用
pub fn bundled_ok() -> Result<usize, String> {
    compile(BUNDLED_YAR, BUNDLED_TOML, "内置").map(|p| p.meta.len())
}
