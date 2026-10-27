//! 名单类情报：VS Code 官方恶意扩展名单、abuse.ch 恶意地址。

use super::{SourceStatus, agent, read_json, write_atomic};
use crate::store;
use serde_json::{Map, Value, json};
use std::sync::OnceLock;

const VSCODE_FILE: &str = "vscode_malicious.json";
const IOC_FILE: &str = "iocs.json";

/// VS Code 自己用来禁用恶意扩展的名单
pub fn update_vscode(_old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus {
        id: "vscode".into(),
        name: "VS Code 恶意扩展名单".into(),
        license: "Microsoft".into(),
        url: "https://main.vscode-cdn.net/extensions/marketplace.json".into(),
        ..Default::default()
    };
    let body: Value = match agent(30).get(&s.url).call().map_err(|e| e.to_string()).and_then(|r| r.into_json().map_err(|e| e.to_string())) {
        Ok(v) => v,
        Err(e) => {
            s.error = Some(format!("下载失败：{e}"));
            return s;
        }
    };
    // 条目可能是字符串，也可能是 {"id": ...}
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

/// 扩展 ID（publisher.name）是否在官方恶意名单里
pub fn vscode_malicious(id: &str) -> bool {
    static LIST: OnceLock<Vec<String>> = OnceLock::new();
    let list = LIST.get_or_init(|| serde_json::from_value(read_json(VSCODE_FILE)).unwrap_or_default());
    let id = id.to_lowercase();
    list.contains(&id)
}

/// abuse.ch 的 ThreatFox（C2 的 IP、域名、样本哈希）和 URLhaus（投递恶意软件的网址）。
/// 2025 年起需要免费注册的 Auth-Key：https://auth.abuse.ch/
pub fn update_abusech(key: &str, _old: Option<&SourceStatus>) -> SourceStatus {
    let mut s = SourceStatus {
        id: "abusech".into(),
        name: "abuse.ch ThreatFox / URLhaus".into(),
        license: "CC0".into(),
        url: "https://abuse.ch".into(),
        ..Default::default()
    };
    if key.is_empty() {
        s.error = Some("未设置 Auth-Key，已跳过（在设置里填写免费的 abuse.ch Auth-Key 后启用）".into());
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
                let label = d["malware_printable"].as_str().unwrap_or("恶意软件");
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
            s.error = Some(format!("ThreatFox 返回 {}", body["query_status"]));
            return s;
        }
        Err(e) => {
            s.error = Some(format!("ThreatFox 下载失败：{e}"));
            return s;
        }
    }

    let uh = agent(60).get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/").set("Auth-Key", key).call();
    if let Ok(body) = uh.map_err(|e| e.to_string()).and_then(|r| r.into_json::<Value>().map_err(|e| e.to_string())) {
        for u in body["urls"].as_array().into_iter().flatten() {
            let label = u["threat"].as_str().unwrap_or("恶意网址");
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

/// 查一个域名、IP、网址或 sha256 是否在 abuse.ch 名单里，返回恶意软件家族名。
pub fn ioc(kind: &str, value: &str) -> Option<String> {
    iocs()[kind][value.to_lowercase()].as_str().map(String::from)
}
