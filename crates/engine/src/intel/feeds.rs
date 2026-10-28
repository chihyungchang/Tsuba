//! List intel: VS Code's official malicious extension list and abuse.ch malicious addresses.

use super::{SourceStatus, agent, read_json, write_atomic};
use crate::store;
use serde_json::{Map, Value, json};
use std::sync::OnceLock;

const VSCODE_FILE: &str = "vscode_malicious.json";
const IOC_FILE: &str = "iocs.json";
const UNNAMED_MALWARE: &str = "unnamed_malware";
const UNNAMED_URL: &str = "unnamed_url";

/// The list VS Code itself uses to disable malicious extensions
pub fn update_vscode(_old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus {
        id: "vscode".into(),
        name: super::VSCODE.0.to_string(),
        license: super::VSCODE.1.to_string(),
        url: "https://main.vscode-cdn.net/extensions/marketplace.json".into(),
        ..Default::default()
    };
    let body: Value = match agent(30).get(&s.url).call().map_err(|e| e.to_string()).and_then(|r| r.into_json().map_err(|e| e.to_string())) {
        Ok(v) => v,
        Err(e) => {
            s.error = Some(tr!("Download failed: {error}", error = e));
            return s;
        }
    };
    // Entries may be strings or {"id": ...}
    let ids: Vec<String> = body["malicious"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().or(v["id"].as_str()).map(|s| s.to_lowercase()))
        .collect();
    if let Err(e) = write_atomic(VSCODE_FILE, serde_json::to_string(&ids).unwrap_or_default().as_bytes()) {
        s.error = Some(e.to_string());
        return s;
    }
    s.count = ids.len();
    s.version = format!("{}", ids.len());
    s.updated = store::now();
    s
}

/// Whether an extension ID (publisher.name) is on the official malicious list
pub fn vscode_malicious(id: &str) -> bool {
    static LIST: OnceLock<Vec<String>> = OnceLock::new();
    let list = LIST.get_or_init(|| serde_json::from_value(read_json(VSCODE_FILE)).unwrap_or_default());
    let id = id.to_lowercase();
    list.contains(&id)
}

/// abuse.ch ThreatFox (C2 IPs, domains, sample hashes) and URLhaus (URLs that deliver malware).
/// Since 2025 this needs a free Auth-Key: https://auth.abuse.ch/
pub fn update_abusech(key: &str, _old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus {
        id: "abusech".into(),
        name: super::ABUSECH.0.to_string(),
        license: super::ABUSECH.1.to_string(),
        url: "https://abuse.ch".into(),
        ..Default::default()
    };
    if key.is_empty() {
        s.error = Some(tr!("Skipped: no Auth-Key set (add a free abuse.ch Auth-Key in Settings to turn it on)"));
        return s;
    }
    let mut iocs: Map<String, Value> = ["domains", "ips", "urls", "sha256"].iter().map(|k| (k.to_string(), json!({}))).collect();
    let mut add = |kind: &str, value: String, label: &str| {
        if let Some(m) = iocs.get_mut(kind).and_then(|v| v.as_object_mut()) {
            m.entry(value).or_insert_with(|| json!(label));
        }
    };

    let tf = agent(60).post("https://threatfox-api.abuse.ch/api/v1/").set("Auth-Key", key).send_json(json!({ "query": "get_iocs", "days": 7 }));
    match tf.map_err(|e| e.to_string()).and_then(|r| r.into_json::<Value>().map_err(|e| e.to_string())) {
        Ok(body) if body["query_status"] == "ok" => {
            for d in body["data"].as_array().into_iter().flatten() {
                let ioc = d["ioc"].as_str().unwrap_or("").to_lowercase();
                let label = d["malware_printable"].as_str().unwrap_or(UNNAMED_MALWARE);
                match d["ioc_type"].as_str().unwrap_or("") {
                    "domain" => add("domains", ioc, label),
                    "ip:port" => add("ips", ioc.split(':').next().unwrap_or("").to_string(), label),
                    "url" => add("urls", ioc, label),
                    "sha256_hash" => add("sha256", ioc, label),
                    _ => {}
                }
            }
        }
        Ok(body) => {
            s.error = Some(tr!("ThreatFox returned {status}", status = body["query_status"]));
            return s;
        }
        Err(e) => {
            s.error = Some(tr!("ThreatFox download failed: {error}", error = e));
            return s;
        }
    }

    let uh = agent(60).get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/").set("Auth-Key", key).call();
    if let Ok(body) = uh.map_err(|e| e.to_string()).and_then(|r| r.into_json::<Value>().map_err(|e| e.to_string())) {
        for u in body["urls"].as_array().into_iter().flatten() {
            let label = u["threat"].as_str().unwrap_or(UNNAMED_URL);
            if let Some(url) = u["url"].as_str() {
                add("urls", url.to_lowercase(), label);
            }
            if let Some(host) = u["host"].as_str() {
                let host = host.to_lowercase();
                let kind = if crate::net::is_ip(&host) { "ips" } else { "domains" };
                add(kind, host, label);
            }
        }
    }

    s.count = iocs.values().map(|v| v.as_object().map_or(0, |m| m.len())).sum();
    if let Err(e) = write_atomic(IOC_FILE, serde_json::to_string(&iocs).unwrap_or_default().as_bytes()) {
        s.error = Some(e.to_string());
        return s;
    }
    s.updated = store::now();
    s.version = s.updated.clone();
    s
}

fn iocs() -> &'static Value {
    static IOCS: OnceLock<Value> = OnceLock::new();
    IOCS.get_or_init(|| read_json(IOC_FILE))
}

/// Looks up whether a domain, IP, URL or sha256 is on the abuse.ch lists and returns the malware family name.
pub fn ioc(kind: &str, value: &str) -> Option<String> {
    let label = iocs()[kind][value.to_lowercase()].as_str()?;
    // Entries without a family name are stored with a placeholder (in Chinese by older versions) and named in the current language here
    Some(match label {
        UNNAMED_MALWARE | "恶意软件" => tr!("malware"),
        UNNAMED_URL | "恶意网址" => tr!("malicious URL"),
        family => family.to_string(),
    })
}
