//! 威胁情报：从公开来源定期更新的规则和名单，存放在 ~/.tsuba/intel。
//!
//! | 来源 | 内容 | 用在哪 |
//! | --- | --- | --- |
//! | OpenSSF Malicious Packages | 已确认的恶意 npm / PyPI 包 | 装包前、lockfile 里的间接依赖 |
//! | OSV.dev（在线） | 同上，检查时实时查询，比本地名单新 | 装包前 |
//! | VS Code 官方恶意扩展名单 | 微软下架的恶意扩展 ID | 装扩展前、扩展目录监控 |
//! | Elastic / ReversingLabs / GuardDog / 本机 XProtect | YARA 规则 | 项目源码、扩展、安装包、远程脚本 |
//! | abuse.ch ThreatFox / URLhaus（需要免费 Auth-Key） | 恶意域名、IP、网址、样本哈希 | 远程脚本地址、代码里的 C2 |
//!
//! 目前直接从各来源的官方地址下载（HTTPS），适合个人使用。
//! 以后由我们的服务端统一汇总、签名后分发时，客户端在这里加签名校验。

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

/// 情报来源的名字和授权。证据里写明“这条结论是谁给的、按什么条款用的”，更新状态里也用同一份。
pub type Credit = (&'static str, &'static str);
pub const OSSF: Credit = ("OpenSSF Malicious Packages", "Apache-2.0");
pub const OSV: Credit = ("OSV.dev", "授权见各条目的原始来源");
pub const VSCODE: Credit = ("VS Code 恶意扩展名单", "Microsoft");
pub const ABUSECH: Credit = ("abuse.ch ThreatFox / URLhaus", "CC0");
pub const VIRUSTOTAL: Credit = ("VirusTotal", "用你自己的 API Key，只查哈希");
pub const TSUBA: Credit = ("Tsuba 规则", "Apache-2.0");

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceStatus {
    pub id: String,
    pub name: String,
    pub license: String,
    pub url: String,
    /// 来源的版本（git 提交、文件修改时间等），没变就不重新下载
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub updated: String,
    /// 规则或条目数量
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub sources: Vec<SourceStatus>,
}

impl Manifest {
    pub fn load() -> Manifest {
        std::fs::read_to_string(dir().join("manifest.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
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

/// 距离上次更新超过 max_age 就该更新了。
pub fn needs_update(max_age: Duration) -> bool {
    let m = Manifest::load();
    let Ok(t) = chrono::NaiveDateTime::parse_from_str(&m.updated, "%Y-%m-%dT%H:%M:%S") else { return true };
    let age = chrono::Local::now().naive_local() - t;
    age.num_seconds() < 0 || age.to_std().map(|a| a > max_age).unwrap_or(true)
}

pub(crate) fn agent(timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(timeout_secs)).redirects(5).user_agent("Tsuba/0.1 (+threat intel update)").build()
}

/// GitHub 仓库某个分支最新提交的 sha，用来判断要不要重新下载。
///
/// 走 git 协议（v2 的 ls-refs，等于 `git ls-remote`），不走 api.github.com：
/// 匿名调 API 每个 IP 每小时只有 60 次，点几次“立即更新”、或同一网络下别人也在用，就会 403。
pub(crate) fn github_head(repo: &str, branch: &str) -> Result<String, String> {
    let body = agent(15)
        .post(&format!("https://github.com/{repo}.git/git-upload-pack"))
        .set("Git-Protocol", "version=2")
        .set("Content-Type", "application/x-git-upload-pack-request")
        .send_bytes(&ls_refs_request(branch))
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    find_branch_sha(&body, branch).ok_or_else(|| format!("{repo} 没有 {branch} 分支"))
}

/// git 的 pkt-line：每行前面是 4 位十六进制长度（含这 4 位本身）；0001 分隔参数，0000 结束。
fn ls_refs_request(branch: &str) -> Vec<u8> {
    let pkt = |s: &str| format!("{:04x}{s}", s.len() + 4);
    format!("{}0001{}0000", pkt("command=ls-refs\n"), pkt(&format!("ref-prefix refs/heads/{branch}\n"))).into_bytes()
}

/// 回包每行是 “<长度><sha> refs/heads/<分支>”；ref-prefix 是前缀匹配，所以要比对完整的分支名。
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

/// 下载一个 GitHub 仓库的 tar.gz，对每个文件调用 f(仓库内路径, 内容)。不落盘，边下边解。
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
        // 去掉 tarball 顶层的 “仓库名-分支/” 目录
        let rel = path.split_once('/').map(|(_, r)| r.to_string()).unwrap_or(path);
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        f(&rel, &buf);
    }
    Ok(())
}

/// 先写临时文件再改名，更新到一半时检查程序读到的还是旧文件。
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

/// 更新全部来源。单个来源失败不影响其他来源，失败的保留上一次的数据。
/// `progress` 用来在界面或终端里显示进度。
pub fn update(cfg: &Config, force: bool, mut progress: impl FnMut(&str)) -> Manifest {
    let mut m = Manifest::load();
    let prev = m.clone();
    let mut step = |id: &str, name: &str, f: &dyn Fn(Option<&SourceStatus>) -> SourceStatus, m: &mut Manifest| {
        progress(name);
        let old = if force { None } else { prev.source(id) };
        let mut s = f(old);
        if s.error.is_some() {
            // 失败时保留旧的数量和版本，界面上仍能看到上一次成功的数据
            if let Some(o) = prev.source(id) {
                s.count = o.count;
                s.version = o.version.clone();
                s.updated = o.updated.clone();
            }
        }
        m.upsert(s);
    };
    let rules_url = cfg.intel.rules_url.clone();
    step("tsuba", "Tsuba 规则", &move |_| tsuba::update(&rules_url), &mut m);
    step("ossf", "OpenSSF 恶意包名单", &packages::update_ossf, &mut m);
    step("vscode", "VS Code 恶意扩展名单", &feeds::update_vscode, &mut m);
    let key = cfg.intel.abusech_key.clone();
    step("abusech", "abuse.ch 恶意地址", &move |old| feeds::update_abusech(&key, old), &mut m);
    for src in yara::SOURCES {
        step(src.id, src.name, &|old| yara::update_source(src, old), &mut m);
    }
    progress("编译 YARA 规则");
    let compiled = yara::compile_all();
    m.upsert(compiled);
    m.updated = store::now();
    m.save();
    m
}

/// 给界面看的简短状态。
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
        // ref-prefix refs/heads/v3 也会返回 v3-dev 这类分支
        let other = "1111111111111111111111111111111111111111 refs/heads/v3-dev\n";
        let wanted = "884e662df4e83d78d0c90c7f6783d5f332863d3d refs/heads/v3\n";
        let body = format!("{:04x}{other}{:04x}{wanted}0000", other.len() + 4, wanted.len() + 4);
        assert_eq!(find_branch_sha(&body, "v3").as_deref(), Some("884e662df4e83d78d0c90c7f6783d5f332863d3d"));
        assert_eq!(find_branch_sha("0000", "main"), None);
    }
}
