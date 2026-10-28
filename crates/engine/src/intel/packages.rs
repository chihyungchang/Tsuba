//! Malicious package lists: OpenSSF Malicious Packages (local index) + OSV.dev (live online lookups).

use super::{SourceStatus, exists, github_head, github_tarball, read_json, write_atomic};
use crate::store;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

const REPO: &str = "ossf/malicious-packages";
const FILE: &str = "packages.json";

/// Supported ecosystems: (our key, OSV's spelling)
pub const ECOSYSTEMS: &[(&str, &str)] = &[("npm", "npm"), ("pypi", "PyPI")];

/// One malicious package entry
#[derive(Clone, Debug)]
pub struct Hit {
    pub id: String,
    pub summary: String,
    /// None means every version is malicious
    pub versions: Option<Vec<String>>,
}

/// Which versions an OSV affected entry covers. introduced 0 with no fixed in ranges means every version.
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
        name: super::OSSF.0.to_string(),
        license: super::OSSF.1.to_string(),
        url: "https://github.com/ossf/malicious-packages".into(),
        ..Default::default()
    };
    let head = match github_head(REPO, "main") {
        Ok(h) => h,
        Err(e) => {
            s.error = Some(tr!("Couldn't check for updates: {error}", error = e));
            return s;
        }
    };
    if old.is_some_and(|o| o.version == head && o.error.is_none()) && exists(FILE) {
        return old.cloned().unwrap();
    }
    // ecosystem → package name → entries
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
        s.error = Some(tr!("Download failed: {error}", error = e));
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

/// PyPI package names treat case, underscores and dots as equivalent
fn normalize_pypi(name: &str) -> String {
    name.to_lowercase().replace(['_', '.'], "-")
}

fn index() -> &'static Value {
    static INDEX: OnceLock<Value> = OnceLock::new();
    INDEX.get_or_init(|| read_json(FILE))
}

/// Looks a package up in the local list. With a version it matches only if that version is listed as malicious; without one, the name being listed is enough.
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

/// Queries OSV.dev online, malicious packages only (IDs starting with MAL-). Returns nothing without a network so the check isn't affected.
/// Returns: package name → matching IDs
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
