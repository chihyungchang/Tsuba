//! VirusTotal: looks up a file's SHA-256 to get the verdicts of 70+ antivirus engines.
//!
//! Only the hash is sent, never the file (uploads are shared with VirusTotal's paying customers and could leak code or private data).
//! Needs the user's own API key. The free public API allows 4 lookups a minute and 500 a day, and its terms forbid use in commercial products.

use crate::rules::{Finding, Severity};
use serde_json::{Value, json};
use std::time::Duration;

/// At most this many hashes per check (the free quota is 4 a minute)
const MAX_LOOKUPS: usize = 4;

/// Every sha256 in the evidence (downloaded installers, apps inside disk images, remote scripts…)
fn collect_hashes(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                if k == "sha256" {
                    if let Some(h) = x.as_str().filter(|h| h.len() == 64)
                        && !out.iter().any(|y| y == h) {
                            out.push(h.to_string());
                        }
                } else {
                    collect_hashes(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_hashes(x, out)),
        _ => {}
    }
}

enum Lookup {
    Found(Value),
    Unknown,
    Stop(String),
}

fn lookup(key: &str, hash: &str) -> Lookup {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build();
    match agent.get(&format!("https://www.virustotal.com/api/v3/files/{hash}")).set("x-apikey", key).call() {
        Ok(r) => r.into_json::<Value>().map(|v| Lookup::Found(v["data"]["attributes"].clone())).unwrap_or(Lookup::Unknown),
        Err(ureq::Error::Status(404, _)) => Lookup::Unknown,
        Err(ureq::Error::Status(401 | 403, _)) => Lookup::Stop(tr!("The VirusTotal API key is invalid")),
        Err(ureq::Error::Status(429, _)) => Lookup::Stop(tr!("Too many VirusTotal lookups (the free quota is 4 a minute)")),
        Err(e) => Lookup::Stop(tr!("Couldn't connect to VirusTotal: {error}", error = e)),
    }
}

/// Looks up the file hashes in the evidence and adds the verdicts to the evidence and findings. Does nothing without a key.
pub fn enrich(key: &str, evidence: &mut Value, findings: &mut Vec<Finding>) {
    if key.is_empty() {
        return;
    }
    let mut hashes = Vec::new();
    collect_hashes(evidence, &mut hashes);
    let mut results = Vec::new();
    for h in hashes.into_iter().take(MAX_LOOKUPS) {
        let short = &h[..12];
        let link = format!("https://www.virustotal.com/gui/file/{h}");
        match lookup(key, &h) {
            Lookup::Found(a) => {
                let stats = &a["last_analysis_stats"];
                let n = |k: &str| stats[k].as_i64().unwrap_or(0);
                let (bad, sus) = (n("malicious"), n("suspicious"));
                let total = bad + sus + n("undetected") + n("harmless");
                let label = a["popular_threat_classification"]["suggested_threat_label"].as_str().unwrap_or("");
                let name = a["meaningful_name"].as_str().unwrap_or(short);
                let detail = if label.is_empty() { String::new() } else { tr!(" ({label})", label = label) };
                let f = match bad {
                    b if b >= 3 => Finding::new(Severity::High, tr!("VirusTotal: {bad}/{total} antivirus engines consider {name} malicious{detail}", bad = b, total = total, name = name, detail = detail), &link).with_source(super::VIRUSTOTAL),
                    b if b >= 1 || sus >= 3 => Finding::new(Severity::Medium, tr!("VirusTotal: {bad} engines flag it as malicious and {suspicious} as suspicious (of {total}): {name}{detail}", bad = b, suspicious = sus, total = total, name = name, detail = detail), &link).with_source(super::VIRUSTOTAL),
                    _ => Finding::new(Severity::Low, tr!("VirusTotal: none of {total} engines flag it (that doesn't prove it's safe; new samples often go undetected): {name}", total = total, name = name), &link).with_source(super::VIRUSTOTAL),
                };
                findings.push(f);
                results.push(json!({ "sha256": h, "stats": stats, "label": label, "name": name, "first_seen": a["first_submission_date"] }));
            }
            Lookup::Unknown => {
                findings.push(Finding::new(Severity::Low, tr!("Nobody has seen this file on VirusTotal before ({hash}…); it's a new sample", hash = short), &link).with_source(super::VIRUSTOTAL));
                results.push(json!({ "sha256": h, "unknown": true }));
            }
            Lookup::Stop(e) => {
                results.push(json!({ "error": e }));
                break;
            }
        }
    }
    if !results.is_empty() {
        evidence["virustotal"] = json!(results);
        evidence["findings"] = json!(findings);
    }
}
