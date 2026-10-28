//! Threat intel: rules and lists updated regularly from public sources, stored in ~/.tsuba/intel.
//!
//! | Source | Contents | Used for |
//! | --- | --- | --- |
//! | OpenSSF Malicious Packages | Confirmed malicious npm / PyPI packages | Before installing packages, indirect dependencies in lockfiles |
//! | OSV.dev (online) | Same, queried live during a check, fresher than the local list | Before installing packages |
//! | VS Code's official malicious extension list | Malicious extension IDs Microsoft took down | Before installing extensions, extension folder monitoring |
//! | Elastic / ReversingLabs / GuardDog / this Mac's XProtect | YARA rules | Project sources, extensions, installers, remote scripts |
//! | abuse.ch ThreatFox / URLhaus (free Auth-Key required) | Malicious domains, IPs, URLs, sample hashes | Remote script URLs, C2 in code |
//!
//! For now everything is downloaded straight from each source's official address (HTTPS), which suits personal use.
//! Once our server aggregates, signs and distributes the intel, the client adds signature checks here.

pub mod feeds;
pub mod packages;
pub mod tsuba;
pub mod virustotal;
pub mod yara;

use crate::store::{self, Config};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn dir() -> PathBuf {
    store::home().join("intel")
}

/// Text in a credit. Brand names and licence IDs read the same in every language; descriptions are translated when displayed.
#[derive(Clone, Copy, Debug)]
pub enum Label {
    Fixed(&'static str),
    /// A function rather than a string because consts can't call `tr!`, and the language can change while the App runs
    Localized(fn() -> String),
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Label::Fixed(s) => f.write_str(s),
            Label::Localized(text) => f.write_str(&text()),
        }
    }
}

/// An intel source's name and licence. Evidence states who gave the verdict and under what terms; update status uses the same pair.
pub type Credit = (Label, Label);
pub const OSSF: Credit = (Label::Fixed("OpenSSF Malicious Packages"), Label::Fixed("Apache-2.0"));
pub const OSV: Credit = (Label::Fixed("OSV.dev"), Label::Localized(|| tr!("Licence as stated by each entry's original source")));
pub const VSCODE: Credit = (Label::Localized(|| tr!("VS Code malicious extension list")), Label::Fixed("Microsoft"));
pub const ABUSECH: Credit = (Label::Fixed("abuse.ch ThreatFox / URLhaus"), Label::Fixed("CC0"));
pub const VIRUSTOTAL: Credit = (Label::Fixed("VirusTotal"), Label::Localized(|| tr!("Your own API key, hashes only")));
pub const TSUBA: Credit = (Label::Localized(|| tr!("Tsuba rules")), Label::Fixed("Apache-2.0"));
const YARA_COMPILED: Credit = (Label::Localized(|| tr!("YARA rules (compiled)")), Label::Fixed("-"));

fn find_credit(id: &str) -> Option<Credit> {
    match id {
        "tsuba" => Some(TSUBA),
        "ossf" => Some(OSSF),
        "vscode" => Some(VSCODE),
        "abusech" => Some(ABUSECH),
        "yara" => Some(YARA_COMPILED),
        _ => yara::SOURCES.iter().find(|s| s.id == id).map(|s| (s.name, s.license)),
    }
}

/// Where the rule pack in use came from. Stored as an ID and only turned into words when displayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Bundled,
    Updated,
    /// Downloaded and verified, used from the next check on
    Pending,
}

impl Origin {
    pub fn id(self) -> &'static str {
        match self {
            Origin::Bundled => "bundled",
            Origin::Updated => "updated",
            Origin::Pending => "pending",
        }
    }

    fn find(id: &str) -> Option<Origin> {
        [Origin::Bundled, Origin::Updated, Origin::Pending].into_iter().find(|o| o.id() == id)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceStatus {
    pub id: String,
    pub name: String,
    pub license: String,
    pub url: String,
    /// The source's version (git commit, file modification time and so on); unchanged means no new download
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub updated: String,
    /// Number of rules or entries
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub error: Option<String>,
    /// Rule pack only: an `Origin` ID
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    /// Compiled YARA rules only: rules dropped as incompatible with YARA-X
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl SourceStatus {
    /// Turns the stored state into text in the current language. Only ever applied to a copy that is shown, never saved,
    /// so the manifest on disk stays language-neutral.
    fn localize(&mut self) {
        self.migrate_legacy();
        if let Some((name, license)) = find_credit(&self.id) {
            self.name = name.to_string();
            self.license = license.to_string();
        }
        match self.id.as_str() {
            "tsuba" => {
                let version = self.version.clone();
                self.version = match Origin::find(&self.origin) {
                    Some(Origin::Bundled) => tr!("{version} (bundled)", version = version),
                    Some(Origin::Updated) => tr!("{version} (updated)", version = version),
                    Some(Origin::Pending) => tr!("{version} (updated, takes effect from the next check)", version = version),
                    None => version,
                };
            }
            "yara" if self.version.is_empty() => {
                self.version = tr!("{usable} usable, {skipped} skipped as incompatible with YARA-X", usable = self.count, skipped = self.skipped);
            }
            _ => {}
        }
    }

    /// Manifests written before the language switch kept Chinese display text in `version`; recover the state from it.
    fn migrate_legacy(&mut self) {
        match self.id.as_str() {
            "tsuba" if self.origin.is_empty() => {
                if let Some((version, suffix)) = self.version.split_once('（') {
                    let origin = if suffix.starts_with("内置") {
                        Origin::Bundled
                    } else if suffix.starts_with("已更新，") {
                        Origin::Pending
                    } else {
                        Origin::Updated
                    };
                    self.version = version.to_string();
                    self.origin = origin.id().to_string();
                }
            }
            "yara" if self.version.contains("条可用") => {
                // "N 条可用，M 条与 YARA-X 不兼容已跳过"
                let numbers: Vec<usize> = self.version.split(|c: char| !c.is_ascii_digit()).filter_map(|n| n.parse().ok()).collect();
                self.skipped = numbers.get(1).copied().unwrap_or(0);
                self.version.clear();
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub sources: Vec<SourceStatus>,
}

impl Manifest {
    /// The manifest for display, in the current language.
    pub fn load() -> Manifest {
        Manifest::load_stored().localized()
    }

    /// The manifest as stored, for updating and saving back.
    fn load_stored() -> Manifest {
        std::fs::read_to_string(dir().join("manifest.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn localized(mut self) -> Manifest {
        self.sources.iter_mut().for_each(SourceStatus::localize);
        self
    }

    fn save(&self) {
        let _ = std::fs::create_dir_all(dir());
        let _ = std::fs::write(dir().join("manifest.json"), serde_json::to_string_pretty(self).unwrap_or_default());
    }

    pub fn source(&self, id: &str) -> Option<&SourceStatus> {
        self.sources.iter().find(|s| s.id == id)
    }

    fn upsert(&mut self, s: SourceStatus) {
        match self.sources.iter_mut().find(|x| x.id == s.id) {
            Some(x) => *x = s,
            None => self.sources.push(s),
        }
    }
}

/// Time to update once more than max_age has passed since the last update.
pub fn needs_update(max_age: Duration) -> bool {
    let m = Manifest::load_stored();
    let Ok(t) = chrono::NaiveDateTime::parse_from_str(&m.updated, "%Y-%m-%dT%H:%M:%S") else { return true };
    let age = chrono::Local::now().naive_local() - t;
    age.num_seconds() < 0 || age.to_std().map(|a| a > max_age).unwrap_or(true)
}

pub(crate) fn agent(timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(timeout_secs)).redirects(5).user_agent("Tsuba/0.1 (+threat intel update)").build()
}

/// The sha of the latest commit on a GitHub repository branch, to decide whether to download again.
///
/// Uses the git protocol (v2 ls-refs, the same as `git ls-remote`) rather than api.github.com:
/// the anonymous API allows only 60 calls per IP per hour, so a few clicks on "Update Now", or others on the same network, get a 403.
pub(crate) fn github_head(repo: &str, branch: &str) -> Result<String, String> {
    let body = agent(15)
        .post(&format!("https://github.com/{repo}.git/git-upload-pack"))
        .set("Git-Protocol", "version=2")
        .set("Content-Type", "application/x-git-upload-pack-request")
        .send_bytes(&ls_refs_request(branch))
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    find_branch_sha(&body, branch).ok_or_else(|| tr!("{repo} has no {branch} branch", repo = repo, branch = branch))
}

/// git pkt-line: each line starts with a 4-digit hex length (counting those 4 digits); 0001 separates arguments, 0000 ends.
fn ls_refs_request(branch: &str) -> Vec<u8> {
    let pkt = |s: &str| format!("{:04x}{s}", s.len() + 4);
    format!("{}0001{}0000", pkt("command=ls-refs\n"), pkt(&format!("ref-prefix refs/heads/{branch}\n"))).into_bytes()
}

/// Each reply line is "<length><sha> refs/heads/<branch>"; ref-prefix matches prefixes, so compare the full branch name.
fn find_branch_sha(body: &str, branch: &str) -> Option<String> {
    let want = format!("refs/heads/{branch}");
    let mut rest = body;
    while rest.len() >= 4 {
        let len = usize::from_str_radix(&rest[..4], 16).ok()?;
        if len < 4 {
            rest = &rest[4..];
            continue;
        }
        let line = rest.get(4..len)?;
        rest = &rest[len..];
        if let Some((sha, name)) = line.trim_end().split_once(' ')
            && name == want
            && sha.len() == 40
            && sha.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some(sha.to_string());
        }
    }
    None
}

/// Downloads a GitHub repository's tar.gz and calls f(path in repo, contents) for each file. Nothing touches disk; it unpacks while downloading.
pub(crate) fn github_tarball(repo: &str, branch: &str, mut f: impl FnMut(&str, &[u8])) -> Result<(), String> {
    let resp = agent(600)
        .get(&format!("https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}"))
        .call()
        .map_err(|e| e.to_string())?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(resp.into_reader()));
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
        // Drop the tarball's top-level "repo-branch/" folder
        let rel = path.split_once('/').map(|(_, r)| r.to_string()).unwrap_or(path);
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        f(&rel, &buf);
    }
    Ok(())
}

/// Writes a temporary file and then renames it, so a check running mid-update still reads the old file.
pub(crate) fn write_atomic(name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let d = dir();
    std::fs::create_dir_all(&d)?;
    let tmp = d.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, d.join(name))
}

pub(crate) fn exists(name: &str) -> bool {
    dir().join(name).is_file()
}

/// Updates every source. One source failing doesn't affect the others; a failed one keeps its previous data.
/// `progress` shows progress in the App or the terminal.
pub fn update(cfg: &Config, force: bool, mut progress: impl FnMut(&str)) -> Manifest {
    let mut m = Manifest::load_stored();
    let prev = m.clone();
    let mut step = |id: &str, name: &str, f: &dyn Fn(Option<&SourceStatus>) -> SourceStatus, m: &mut Manifest| {
        progress(name);
        let old = if force { None } else { prev.source(id) };
        let mut s = f(old);
        if s.error.is_some() {
            // On failure keep the old count and version, so the App still shows the last successful data
            if let Some(o) = prev.source(id) {
                s.count = o.count;
                s.version = o.version.clone();
                s.origin = o.origin.clone();
                s.updated = o.updated.clone();
            }
        }
        m.upsert(s);
    };
    let rules_url = cfg.intel.rules_url.clone();
    step("tsuba", &TSUBA.0.to_string(), &move |_| tsuba::update(&rules_url), &mut m);
    step("ossf", &OSSF.0.to_string(), &packages::update_ossf, &mut m);
    step("vscode", &VSCODE.0.to_string(), &feeds::update_vscode, &mut m);
    let key = cfg.intel.abusech_key.clone();
    step("abusech", &tr!("abuse.ch malicious addresses"), &move |old| feeds::update_abusech(&key, old), &mut m);
    for src in yara::SOURCES {
        step(src.id, &src.name.to_string(), &|old| yara::update_source(src, old), &mut m);
    }
    progress(&tr!("Compiling YARA rules"));
    let compiled = yara::compile_all();
    m.upsert(compiled);
    m.updated = store::now();
    m.save();
    m.localized()
}

/// A short status for the App.
pub fn status() -> serde_json::Value {
    let m = Manifest::load();
    json!({ "updated": m.updated, "sources": m.sources })
}

pub(crate) fn read_json(name: &str) -> serde_json::Value {
    std::fs::read(dir().join(name)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(serde_json::Value::Null)
}

pub(crate) fn file_mtime(p: &Path) -> String {
    p.metadata()
        .and_then(|m| m.modified())
        .ok()
        .map(|t| chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_refs_request_is_valid_pkt_lines() {
        assert_eq!(ls_refs_request("main"), b"0014command=ls-refs\n0001001fref-prefix refs/heads/main\n0000");
    }

    #[test]
    fn find_branch_sha_skips_branches_sharing_the_prefix() {
        // ref-prefix refs/heads/v3 also returns branches such as v3-dev
        let other = "1111111111111111111111111111111111111111 refs/heads/v3-dev\n";
        let wanted = "884e662df4e83d78d0c90c7f6783d5f332863d3d refs/heads/v3\n";
        let body = format!("{:04x}{other}{:04x}{wanted}0000", other.len() + 4, wanted.len() + 4);
        assert_eq!(find_branch_sha(&body, "v3").as_deref(), Some("884e662df4e83d78d0c90c7f6783d5f332863d3d"));
        assert_eq!(find_branch_sha("0000", "main"), None);
    }

    fn stored(id: &str, version: &str) -> SourceStatus {
        SourceStatus { id: id.into(), name: "stale name".into(), version: version.into(), count: 1200, ..Default::default() }
    }

    #[test]
    fn manifests_from_before_the_language_switch_still_load() {
        let json = r#"{"updated":"2026-10-20T08:00:00","sources":[{"id":"tsuba","name":"Tsuba 规则","license":"Apache-2.0","url":"","version":"2026.10.27（内置）","count":20}]}"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        let s = m.localized().sources.remove(0);
        assert_eq!((s.name.as_str(), s.version.as_str()), ("Tsuba rules", "2026.10.27 (bundled)"));
    }

    #[test]
    fn legacy_display_text_becomes_state() {
        let mut pending = stored("tsuba", "2026.10.28（已更新，下次检查生效）");
        pending.migrate_legacy();
        assert_eq!((pending.version.as_str(), pending.origin.as_str()), ("2026.10.28", "pending"));
        let mut updated = stored("tsuba", "2026.10.28（已更新）");
        updated.migrate_legacy();
        assert_eq!(updated.origin, "updated");
        let mut compiled = stored("yara", "1200 条可用，35 条与 YARA-X 不兼容已跳过");
        compiled.localize();
        assert_eq!(compiled.skipped, 35);
        assert_eq!(compiled.version, "1200 usable, 35 skipped as incompatible with YARA-X");
        assert_eq!(compiled.name, "YARA rules (compiled)");
    }

    #[test]
    fn localizing_is_idempotent_on_stored_state() {
        let mut s = stored("tsuba", "2026.10.28");
        s.origin = Origin::Updated.id().into();
        let saved = serde_json::to_string(&s).unwrap();
        s.localize();
        assert_eq!(s.version, "2026.10.28 (updated)");
        assert!(saved.contains(r#""version":"2026.10.28""#), "the stored manifest stays language-neutral: {saved}");
    }
}
