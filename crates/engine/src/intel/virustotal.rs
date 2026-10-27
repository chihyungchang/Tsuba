//! VirusTotal：用文件的 SHA-256 查询 70 多家杀毒引擎的结论。
//!
//! 只发送哈希，不上传文件（上传的文件会共享给 VirusTotal 的付费用户，可能泄露代码或隐私）。
//! 需要用户自己的 API Key。免费的公开 API 每分钟 4 次、每天 500 次，条款不允许用在商业产品里。

use crate::rules::{Finding, Severity};
use serde_json::{Value, json};
use std::time::Duration;

/// 一次检查最多查几个哈希（免费额度每分钟 4 次）
const MAX_LOOKUPS: usize = 4;

/// 证据里出现的所有 sha256（下载的安装包、镜像里的程序、远程脚本……）
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
        Err(ureq::Error::Status(401 | 403, _)) => Lookup::Stop("VirusTotal API Key 无效".into()),
        Err(ureq::Error::Status(429, _)) => Lookup::Stop("VirusTotal 查询太频繁（免费额度每分钟 4 次）".into()),
        Err(e) => Lookup::Stop(format!("无法连接 VirusTotal：{e}")),
    }
}

/// 查证据里的文件哈希，把结论加进证据和规则命中里。没有 Key 时什么都不做。
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
                let detail = if label.is_empty() { String::new() } else { format!("（{label}）") };
                let f = match bad {
                    b if b >= 3 => Finding::new(Severity::High, format!("VirusTotal：{b}/{total} 个杀毒引擎认为 {name} 是恶意的{detail}"), &link),
                    b if b >= 1 || sus >= 3 => Finding::new(Severity::Medium, format!("VirusTotal：{b} 个引擎报毒、{sus} 个认为可疑（共 {total} 个）：{name}{detail}"), &link),
                    _ => Finding::new(Severity::Low, format!("VirusTotal：{total} 个引擎都没有报毒（不代表一定安全，新样本常常查不出来）：{name}"), &link),
                };
                findings.push(f);
                results.push(json!({ "sha256": h, "stats": stats, "label": label, "name": name, "first_seen": a["first_submission_date"] }));
            }
            Lookup::Unknown => {
                findings.push(Finding::new(Severity::Low, format!("VirusTotal 上没有人见过这个文件（{short}…），是新样本"), &link));
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
