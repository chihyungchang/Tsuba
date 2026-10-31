//! Tsuba's own rule pack: tsuba.yar (detection patterns) + tsuba.toml (lists).
//!
//! A copy is bundled with each release; when a rule pack URL is set, it updates daily with the other intel into ~/.tsuba/intel/tsuba/.
//! A download is only used if its signature checks out, it compiles, and its version is no older than the one in use; otherwise the bundled pack is used.
//!
//! The update channel is itself a supply chain: whoever can change the rule pack can make Tsuba allow malicious code (deleting one rule is enough).
//! So only packs signed with Tsuba's release key are accepted, the signature is checked on download and on every load, and rollbacks are refused.

use super::{Origin, SourceStatus, agent, dir};
use crate::rules::{self, Finding, Severity};
use crate::store;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

/// Trusted rule pack signing keys (ed25519, hex). When rotating keys, old and new coexist for a while.
/// Generate with `tsuba rules keygen <secret key file>` and add the printed public key here; the secret key stays on the machine that publishes packs, never in the repo.
/// With an empty list no downloaded pack is ever used, only the bundled rules.
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
    /// The rule pack carries its own translations (`message_zh`, `message_ja`, ...): packs update without a release,
    /// so the app's catalogs can't know new rules. A language a pack doesn't cover falls back to English.
    translations: HashMap<crate::i18n::Lang, String>,
    skip_quoted: bool,
    doc_keep: bool,
    skip_well_known: bool,
}

impl RuleMeta {
    fn localized_message(&self) -> String {
        self.translations.get(&crate::i18n::lang()).cloned().unwrap_or_else(|| self.message.clone())
    }
}

struct Pack {
    rules: yara_x::Rules,
    meta: HashMap<String, RuleMeta>,
    lists: Lists,
    origin: Origin,
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

fn compile(yar: &str, toml_text: &str, origin: Origin) -> Result<Pack, String> {
    let lists: Lists = toml::from_str(toml_text).map_err(|e| tr!("tsuba.toml is malformed: {error}", error = e))?;
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(yar).map_err(|e| tr!("tsuba.yar failed to compile: {error}", error = e))?;
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
                translations: crate::i18n::Lang::ALL[1..]
                    .iter()
                    .filter_map(|lang| meta_str(&m, lang.rule_message_key()).map(|text| (*lang, text.to_string())))
                    .collect(),
                skip_quoted: meta_bool(&m, "skip_quoted"),
                doc_keep: meta_bool(&m, "doc_keep"),
                skip_well_known: meta_bool(&m, "skip_well_known"),
            },
        );
    }
    Ok(Pack { rules, meta, lists, origin })
}

/// What the signature covers: the SHA-256 of both files plus a format version, so a signature over something else can't be passed off as this.
fn signed_message(yar: &str, toml_text: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    format!("tsuba-rules-v1\n{}\n{}\n", crate::net::hex(&Sha256::digest(yar)), crate::net::hex(&Sha256::digest(toml_text))).into_bytes()
}

/// Signs a rule pack with the release key (a 32-byte seed) and returns the hex signature that goes into tsuba.sig.
pub fn sign(yar: &str, toml_text: &str, secret: &[u8; 32]) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(secret);
    crate::net::hex(&key.sign(&signed_message(yar, toml_text)).to_bytes())
}

/// The public key (hex) for a secret key seed.
pub fn public_key(secret: &[u8; 32]) -> String {
    crate::net::hex(ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().as_bytes())
}

/// The signature verifies against one of the trusted public keys.
pub fn verify(yar: &str, toml_text: &str, sig_hex: &str, keys: &[&str]) -> Result<(), String> {
    let sig: [u8; 64] = crate::net::unhex(sig_hex).and_then(|b| b.try_into().ok()).ok_or_else(|| tr!("The rule pack signature is malformed"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    let msg = signed_message(yar, toml_text);
    let ok = keys.iter().any(|k| {
        crate::net::unhex(k)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
            .is_some_and(|vk| vk.verify_strict(&msg, &sig).is_ok())
    });
    if ok { Ok(()) } else { Err(tr!("The rule pack signature didn't verify, so it wasn't used")) }
}

fn pack() -> &'static Pack {
    static PACK: OnceLock<Pack> = OnceLock::new();
    PACK.get_or_init(|| {
        let bundled_version = toml::from_str::<Lists>(BUNDLED_TOML).map(|l| l.version).unwrap_or_default();
        let d = dir().join("tsuba");
        let read = |name: &str| std::fs::read_to_string(d.join(name));
        // The cached pack is re-verified on every load: files changed by another program are never used
        if let (Ok(yar), Ok(t), Ok(sig)) = (read("tsuba.yar"), read("tsuba.toml"), read("tsuba.sig"))
            && verify(&yar, &t, &sig, TRUSTED_KEYS).is_ok()
            && let Ok(p) = compile(&yar, &t, Origin::Updated)
                && p.lists.version >= bundled_version {
                    return p;
                }
        compile(BUNDLED_YAR, BUNDLED_TOML, Origin::Bundled).expect("the bundled rule pack must compile")
    })
}

pub fn lists() -> &'static Lists {
    &pack().lists
}

/// Whether this rule keeps its severity when it matches in documentation
pub fn doc_keep(rule: &str) -> bool {
    pack().meta.get(rule).is_some_and(|m| m.doc_keep)
}

/// Wrapped in quotes: quoting attack wording (a security notice, documentation), not giving a command
fn quoted(text: &str, start: usize) -> bool {
    text.get(..start).and_then(|t| t.chars().next_back()).is_some_and(|c| matches!(c, '"' | '“' | '\'' | '‘' | '`' | '「'))
}

/// The span has URLs and they are all official install sources (for example curl https://astral.sh/uv/install.sh | sh).
/// No URL doesn't count: there's no telling where it downloads from, so warn as usual.
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
        let mut f = Finding::new(m.severity, m.localized_message(), location).with_snippet(rules::snippet(text, hit.start, hit.end, 120)).with_source(super::TSUBA);
        f.rule = r.identifier().to_string();
        out.push(f);
    }
    out
}

/// Rule pack update: when a URL is set, download tsuba.yar and tsuba.toml and replace the pack only if it compiles.
pub fn update(url: &str) -> SourceStatus {
    let p = pack();
    let mut s = SourceStatus {
        id: "tsuba".into(),
        name: super::TSUBA.0.to_string(),
        license: super::TSUBA.1.to_string(),
        url: url.into(),
        count: p.meta.len(),
        version: p.lists.version.clone(),
        origin: p.origin.id().into(),
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
            s.error = Some(tr!("Download failed: {error}", error = e));
            return s;
        }
    };
    if let Err(e) = verify(&yar, &t, &sig, TRUSTED_KEYS) {
        s.error = Some(e);
        return s;
    }
    let new = match compile(&yar, &t, Origin::Pending) {
        Ok(n) => n,
        Err(e) => {
            s.error = Some(e);
            return s;
        }
    };
    // Rollback protection: older versions are refused even when signed (they may lack rules added since)
    if new.lists.version < p.lists.version {
        s.error = Some(tr!("The downloaded rule pack version {downloaded} is older than {current} in use, so it wasn't used", downloaded = new.lists.version, current = p.lists.version));
        return s;
    }
    let d = dir().join("tsuba");
    let write = |name: &str, text: &str| std::fs::write(d.join(name), text);
    // The signature is written last: a failure midway leaves a combination that won't verify, and loading falls back to the bundled rules
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
    s.version = new.lists.version.clone();
    s.origin = new.origin.id().into();
    s
}

/// Checks that a rule pack compiles before publishing it.
pub fn check_pack(yar: &str, toml_text: &str) -> Result<(), String> {
    compile(yar, toml_text, Origin::Updated).map(|_| ())
}

/// The bundled rule pack must compile: for tests
pub fn bundled_ok() -> Result<usize, String> {
    compile(BUNDLED_YAR, BUNDLED_TOML, Origin::Bundled).map(|p| p.meta.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_rule_has_a_message_in_every_language() {
        let pack = compile(BUNDLED_YAR, BUNDLED_TOML, Origin::Bundled).unwrap();
        assert!(!pack.meta.is_empty());
        for (id, m) in &pack.meta {
            assert!(m.message != *id && !m.message.trim().is_empty(), "{id} has no message");
            for lang in &crate::i18n::Lang::ALL[1..] {
                let key = lang.rule_message_key();
                assert!(m.translations.get(lang).is_some_and(|text| !text.trim().is_empty()), "{id} has no {key}");
            }
        }
    }
}
