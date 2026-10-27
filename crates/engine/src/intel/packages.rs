//! 恶意包名单：OpenSSF Malicious Packages（本地索引）+ OSV.dev（在线实时查询）。

use super::{SourceStatus, exists, github_head, github_tarball, read_json, write_atomic};
use crate::store;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

const REPO: &str = "ossf/malicious-packages";
const FILE: &str = "packages.json";

/// 支持的生态，键是 OSV 里的写法
pub const ECOSYSTEMS: &[(&str, &str)] = &[("npm", "npm"), ("pypi", "PyPI")];

/// 一个恶意包条目
#[derive(Clone, Debug)]
pub struct Hit {
    pub id: String,
    pub summary: String,
    /// None 表示所有版本都是恶意的
    pub versions: Option<Vec<String>>,
}

/// OSV 里一个 affected 条目覆盖哪些版本。ranges 里 introduced 为 0 且没有 fixed，就是全部版本。
fn affected_versions(a: &Value) -> Option<Vec<String>> {
    let all = a["ranges"].as_array().into_iter().flatten().any(|r| {
        let events = r["events"].as_array().cloned().unwrap_or_default();
        events.iter().any(|e| e["introduced"] == "0") && !events.iter().any(|e| e.get("fixed").is_some() || e.get("last_affected").is_some())
    });
    if all {
        return None;
    }
    let v: Vec<String> = a["versions"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
    if v.is_empty() { None } else { Some(v) }
}

pub fn update_ossf(old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus {
        id: "ossf".into(),
        name: "OpenSSF Malicious Packages".into(),
        license: "Apache-2.0".into(),
        url: "https://github.com/ossf/malicious-packages".into(),
        ..Default::default()
    };
    let head = match github_head(REPO, "main") {
        Ok(h) => h,
        Err(e) => {
            s.error = Some(format!("无法检查更新：{e}"));
            return s;
        }
    };
    if old.is_some_and(|o| o.version == head && o.error.is_none()) && exists(FILE) {
        return old.cloned().unwrap();
    }
    // 生态 → 包名 → 条目列表
    let mut index: HashMap<&str, Map<String, Value>> = HashMap::new();
    let mut count = 0usize;
    let res = github_tarball(REPO, "main", |path, bytes| {
        let Some(rest) = path.strip_prefix("osv/malicious/") else { return };
        let Some((eco, _)) = rest.split_once('/') else { return };
        let Some(&(key, osv_name)) = ECOSYSTEMS.iter().find(|(k, _)| *k == eco) else { return };
        if !path.ends_with(".json") {
            return;
        }
        let Ok(v) = serde_json::from_slice::<Value>(bytes) else { return };
        let id = v["id"].as_str().unwrap_or("").to_string();
        let summary: String = v["summary"].as_str().or(v["details"].as_str()).unwrap_or("").chars().take(160).collect();
        for a in v["affected"].as_array().into_iter().flatten() {
            if a["package"]["ecosystem"] != osv_name {
                continue;
            }
            let Some(name) = a["package"]["name"].as_str() else { continue };
            let name = if key == "pypi" { normalize_pypi(name) } else { name.to_string() };
            let entry = json!({ "id": id, "summary": summary, "versions": affected_versions(a) });
            index.entry(key).or_default().entry(name).or_insert_with(|| json!([])).as_array_mut().unwrap().push(entry);
            count += 1;
        }
    });
    if let Err(e) = res {
        s.error = Some(format!("下载失败：{e}"));
        return s;
    }
    let data: Map<String, Value> = index.into_iter().map(|(k, v)| (k.to_string(), Value::Object(v))).collect();
    if let Err(e) = write_atomic(FILE, serde_json::to_string(&data).unwrap_or_default().as_bytes()) {
        s.error = Some(e.to_string());
        return s;
    }
    s.version = head;
    s.count = count;
    s.updated = store::now();
    s
}

/// PyPI 包名大小写、下划线、点都等价
fn normalize_pypi(name: &str) -> String {
    name.to_lowercase().replace(['_', '.'], "-")
}

fn index() -> &'static Value {
    static INDEX: OnceLock<Value> = OnceLock::new();
    INDEX.get_or_init(|| read_json(FILE))
}

/// 在本地名单里查一个包。给了版本时只在这个版本被列为恶意时命中；没给版本时只要包名在名单里就命中。
pub fn lookup(ecosystem: &str, name: &str, version: Option<&str>) -> Option<Hit> {
    let name = if ecosystem == "pypi" { normalize_pypi(name) } else { name.to_string() };
    let entries = index()[ecosystem][&name].as_array()?;
    entries.iter().find_map(|e| {
        let versions: Option<Vec<String>> = e["versions"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect());
        let hit = match (&versions, version) {
            (None, _) | (Some(_), None) => true,
            (Some(vs), Some(v)) => vs.iter().any(|x| x == v),
        };
        hit.then(|| Hit { id: e["id"].as_str().unwrap_or("").into(), summary: e["summary"].as_str().unwrap_or("").into(), versions })
    })
}

/// 在线查 OSV.dev：只看恶意包（MAL- 开头）。查不到网络时返回空，不影响检查。
/// 返回：包名 → 命中的编号
pub fn osv_query(ecosystem: &str, items: &[(String, Option<String>)]) -> HashMap<String, Vec<String>> {
    let osv_eco = ECOSYSTEMS.iter().find(|(k, _)| *k == ecosystem).map(|(_, v)| *v).unwrap_or(ecosystem);
    let mut out = HashMap::new();
    for chunk in items.chunks(500) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|(n, v)| {
                let mut q = json!({ "package": { "name": n, "ecosystem": osv_eco } });
                if let Some(v) = v {
                    q["version"] = json!(v);
                }
                q
            })
            .collect();
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(6)).build();
        let Ok(resp) = agent.post("https://api.osv.dev/v1/querybatch").send_json(json!({ "queries": queries })) else { return out };
        let Ok(body) = resp.into_json::<Value>() else { return out };
        for (i, r) in body["results"].as_array().into_iter().flatten().enumerate() {
            let ids: Vec<String> = r["vulns"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str()).filter(|id| id.starts_with("MAL-")).map(String::from).collect();
            if !ids.is_empty()
                && let Some((n, _)) = chunk.get(i) {
                    out.insert(n.clone(), ids);
                }
        }
    }
    out
}
