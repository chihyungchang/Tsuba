//! Online evidence: downloads remote scripts (read, never run), looks up domain registration dates and npm package info.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

const UA: &str = "Tsuba/0.1 (+security pre-execution check)";

fn agent(timeout: f64) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs_f64(timeout)).redirects(5).build()
}

pub fn days_since(iso: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(iso).ok().map(|t| (Utc::now() - t.with_timezone(&Utc)).num_days())
}

/// GETs a URL, reading at most max_bytes. The content is never run.
pub fn fetch(url: &str, max_bytes: usize, timeout: f64) -> Map<String, Value> {
    let mut info = Map::new();
    info.insert("url".into(), json!(url));
    let resp = match agent(timeout).get(url).set("User-Agent", "curl/8.7.1").call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            info.insert("error".into(), json!(format!("HTTP {code}")));
            return info;
        }
        Err(e) => {
            info.insert("error".into(), json!(e.to_string()));
            return info;
        }
    };
    info.insert("final_url".into(), json!(resp.get_url()));
    info.insert("status".into(), json!(resp.status()));
    info.insert("content_type".into(), json!(resp.header("Content-Type").unwrap_or("")));
    let mut body = Vec::new();
    if let Err(e) = resp.into_reader().take(max_bytes as u64 + 1).read_to_end(&mut body) {
        info.insert("error".into(), json!(e.to_string()));
        return info;
    }
    info.insert("truncated".into(), json!(body.len() > max_bytes));
    body.truncate(max_bytes);
    info.insert("sha256".into(), json!(hex(&Sha256::digest(&body))));
    info.insert("size".into(), json!(body.len()));
    info.insert("text".into(), json!(String::from_utf8_lossy(&body)));
    info
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex decoding; None when the format is wrong.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    hostport.split(':').next().unwrap_or("").to_lowercase()
}

pub fn is_ip(host: &str) -> bool {
    !host.is_empty() && host.chars().all(|c| c.is_ascii_digit() || c == '.')
}

pub fn registered_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    let n = parts.len();
    if n >= 3 && matches!(parts[n - 2], "co" | "com" | "net" | "org" | "gov" | "edu") && parts[n - 1].len() == 2 {
        return parts[n - 3..].join(".");
    }
    parts[n.saturating_sub(2)..].join(".")
}

/// Common official sources of install scripts (the list is in the rule pack's tsuba.toml)
pub fn is_well_known(host: &str) -> bool {
    let list = &crate::intel::tsuba::lists().well_known_hosts;
    let reg = registered_domain(host);
    list.iter().any(|h| h == host || *h == reg)
}

/// How many days ago the domain was registered, via RDAP; None when unknown.
pub fn domain_age_days(host: &str) -> Option<i64> {
    if host.is_empty() || is_ip(host) {
        return None;
    }
    let url = format!("https://rdap.org/domain/{}", registered_domain(host));
    let data: Value = agent(5.0)
        .get(&url)
        .set("User-Agent", UA)
        .set("Accept", "application/rdap+json")
        .call()
        .ok()?
        .into_json()
        .ok()?;
    data["events"].as_array()?.iter().find_map(|ev| {
        (ev["eventAction"] == "registration").then(|| ev["eventDate"].as_str().and_then(days_since)).flatten()
    })
}

/// Splits `pkg@1.2.3` or `@scope/pkg@^1` into package name and version.
pub fn split_spec(spec: &str) -> (String, Option<String>) {
    let at = if let Some(rest) = spec.strip_prefix('@') { rest.find('@').map(|i| i + 1) } else { spec.find('@') };
    match at {
        Some(i) => (spec[..i].to_string(), Some(spec[i + 1..].to_string()).filter(|v| !v.is_empty())),
        None => (spec.to_string(), None),
    }
}

fn install_scripts(ver: &Value) -> Value {
    let mut out = Map::new();
    if let Some(s) = ver["scripts"].as_object() {
        for k in ["preinstall", "install", "postinstall"] {
            if let Some(v) = s.get(k) {
                out.insert(k.into(), v.clone());
            }
        }
    }
    Value::Object(out)
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Whether `npm_package_info` found that the package doesn't exist on npm (a typo, dependency confusion or a squatted name).
/// A structured flag, so callers never compare the localized error text.
pub fn is_missing_package(info: &Map<String, Value>) -> bool {
    info.get("not_found").and_then(Value::as_bool).unwrap_or(false)
}

/// Queries the npm registry: creation date, publish date of the version to install, install scripts, maintainer count.
pub fn npm_package_info(spec: &str) -> Map<String, Value> {
    let (name, version) = split_spec(spec);
    let mut info = Map::new();
    info.insert("spec".into(), json!(spec));
    info.insert("name".into(), json!(name));
    if name.is_empty()
        || name.starts_with(['.', '/'])
        || name.starts_with("git+")
        || name.starts_with("http")
        || (name.contains('/') && !name.starts_with('@'))
    {
        info.insert("note".into(), json!(tr!("A local path, Git or URL dependency, which can't be looked up in the registry")));
        return info;
    }
    let url = format!("https://registry.npmjs.org/{}", name.replace('/', "%2F"));
    let raw = match agent(8.0).get(&url).set("User-Agent", UA).set("Accept", "application/json").call() {
        Ok(r) => {
            let mut buf = Vec::new();
            let _ = r.into_reader().take(1_500_001).read_to_end(&mut buf);
            buf
        }
        Err(ureq::Error::Status(404, _)) => {
            info.insert("not_found".into(), json!(true));
            info.insert("error".into(), json!(tr!("This package doesn't exist on npm")));
            return info;
        }
        Err(ureq::Error::Status(code, _)) => {
            info.insert("error".into(), json!(format!("HTTP {code}")));
            return info;
        }
        Err(e) => {
            info.insert("error".into(), json!(e.to_string()));
            return info;
        }
    };
    if raw.len() > 1_500_000 {
        // Metadata over 1.5 MB means a great many versions, an established package; only read the latest version
        info.insert("established".into(), json!(true));
        let ver: Value = match agent(8.0).get(&format!("{url}/latest")).set("User-Agent", UA).call().map(|r| r.into_json()) {
            Ok(Ok(v)) => v,
            _ => {
                info.insert("error".into(), json!(tr!("Couldn't read the latest version's info")));
                return info;
            }
        };
        info.insert("latest".into(), ver["version"].clone());
        info.insert("install_scripts".into(), install_scripts(&ver));
        info.insert("description".into(), json!(trunc(ver["description"].as_str().unwrap_or(""), 200)));
        return info;
    }
    let data: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => {
            info.insert("error".into(), json!(tr!("Couldn't parse the registry's response")));
            return info;
        }
    };
    let latest = data["dist-tags"]["latest"].as_str().unwrap_or("").to_string();
    // Look at the exact version when one is given, otherwise at latest
    let target = version.filter(|v| data["versions"].get(v).is_some()).unwrap_or_else(|| latest.clone());
    let ver = &data["versions"][&target];
    let times = &data["time"];
    let repo = match &ver["repository"] {
        Value::Object(o) => o.get("url").cloned().unwrap_or(Value::Null),
        v => v.clone(),
    };
    let deps: Vec<&String> = ver["dependencies"].as_object().map(|o| o.keys().take(40).collect()).unwrap_or_default();
    info.insert("latest".into(), json!(latest));
    info.insert("version".into(), json!(target));
    info.insert("created".into(), times["created"].clone());
    info.insert("version_published".into(), times[&target].clone());
    info.insert("version_count".into(), json!(data["versions"].as_object().map_or(0, |o| o.len())));
    info.insert("maintainers".into(), json!(data["maintainers"].as_array().map_or(0, |a| a.len())));
    info.insert("repository".into(), repo);
    info.insert("install_scripts".into(), install_scripts(ver));
    info.insert("dependencies".into(), json!(deps));
    info.insert("description".into(), json!(trunc(ver["description"].as_str().unwrap_or(""), 200)));
    for key in ["created", "version_published"] {
        if let Some(d) = info.get(key).and_then(|v| v.as_str()).and_then(days_since) {
            info.insert(format!("{key}_days_ago"), json!(d));
        }
    }
    info
}
