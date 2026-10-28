//! Local storage: config, check history and fingerprints of allowed projects. Everything lives in ~/.tsuba and is never uploaded.

use crate::Report;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;

pub fn home() -> PathBuf {
    match std::env::var_os("TSUBA_HOME") {
        Some(p) => PathBuf::from(p),
        None => crate::home_dir().join(".tsuba"),
    }
}

pub fn now() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

pub fn load_json(name: &str) -> Value {
    std::fs::read_to_string(home().join(name)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

/// Writes a temporary file and renames it, so a reader never sees half a file when the App and the terminal write at once.
pub fn save_json(name: &str, data: &Value) {
    let _ = write_private(name, serde_json::to_string_pretty(data).unwrap_or_default().as_bytes());
}

fn write_private(name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = home();
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!(".{name}.{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    std::fs::rename(tmp, dir.join(name))
}

/// Which model does the AI review.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Calls the local Claude Code (claude -p) with the account it is signed in to; no API key needed. Suited to personal use
    #[default]
    ClaudeCli,
    /// Anthropic Claude API
    Claude,
    /// Any service compatible with the OpenAI Chat Completions API: Ollama, LM Studio, llama.cpp, vLLM, and cloud models
    OpenaiCompatible,
    /// Offline rules only
    Offline,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaudeConfig {
    pub api_key: String,
    pub model: String,
    pub effort: String,
    /// Location of the claude command; found automatically when empty
    pub cli_path: String,
}

impl Default for ClaudeConfig {
    fn default() -> Self {
        ClaudeConfig { api_key: String::new(), model: "claude-opus-5-5".into(), effort: "low".into(), cli_path: String::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenAiCompatConfig {
    /// For example Ollama's http://127.0.0.1:11434/v1
    pub base_url: String,
    pub model: String,
    /// Local services usually don't need one
    pub api_key: String,
    /// Provider chosen in the UI: openai / gemini / deepseek / qwen / ollama / lmstudio / custom
    pub preset: String,
    /// Whether to trust it like a frontier model: a trusted model can lower an offline Block to Warn, and can Block on its own
    pub trusted: bool,
}

impl OpenAiCompatConfig {
    /// Local models are slow and have short contexts, so they get shorter evidence and a longer timeout.
    pub fn is_local(&self) -> bool {
        matches!(self.preset.as_str(), "ollama" | "lmstudio")
            || self.base_url.contains("://127.0.0.1")
            || self.base_url.contains("://localhost")
    }
}

impl Default for OpenAiCompatConfig {
    fn default() -> Self {
        OpenAiCompatConfig {
            base_url: "http://127.0.0.1:11434/v1".into(),
            model: String::new(),
            api_key: String::new(),
            preset: "ollama".into(),
            trusted: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct IntelConfig {
    /// Update threat intel automatically every day
    pub auto_update: bool,
    /// Free abuse.ch Auth-Key; without it ThreatFox / URLhaus aren't used
    pub abusech_key: String,
    /// Query OSV.dev online when checking npm / PyPI packages
    pub online_lookup: bool,
    /// Download location of the Tsuba rule pack (a directory holding tsuba.yar and tsuba.toml). Empty uses only the built-in rules
    pub rules_url: String,
    /// The user's own VirusTotal API key. Only file hashes are looked up; files are never uploaded
    pub virustotal_key: String,
}

impl Default for IntelConfig {
    fn default() -> Self {
        IntelConfig { auto_update: true, abusech_key: String::new(), online_lookup: true, rules_url: String::new(), virustotal_key: String::new() }
    }
}

/// Scheduled scan: periodically rescans Downloads and code folders with the latest rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub scheduled: bool,
    /// Folders to scan; may start with ~/
    pub folders: Vec<String>,
    pub interval_days: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig { scheduled: true, folders: vec!["~/Downloads".into()], interval_days: 7 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub provider: Provider,
    pub claude: ClaudeConfig,
    pub openai_compatible: OpenAiCompatConfig,
    pub watch_downloads: bool,
    pub watch_extensions: bool,
    /// Move an extension to quarantine automatically when it is judged Block
    pub auto_quarantine: bool,
    /// Watch AI coding tools for new MCP servers, skills and plugin hooks
    pub watch_ai_tools: bool,
    pub intel: IntelConfig,
    pub scan: ScanConfig,
    /// The language chosen in the App: empty follows the system, otherwise "en" or "zh-Hans". Stored here rather than
    /// only in the window, so the terminal check and AI answers in every process match the App.
    pub language: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            provider: Provider::ClaudeCli,
            claude: ClaudeConfig::default(),
            openai_compatible: OpenAiCompatConfig::default(),
            watch_downloads: true,
            watch_extensions: true,
            auto_quarantine: true,
            watch_ai_tools: true,
            intel: IntelConfig::default(),
            scan: ScanConfig::default(),
            language: String::new(),
        }
    }
}

impl Config {
    pub fn load() -> Config {
        let mut c: Config = serde_json::from_value(load_json("config.json")).unwrap_or_default();
        if c.claude.api_key.is_empty() {
            c.claude.api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
        }
        if std::env::var_os("TSUBA_OFFLINE").is_some() {
            c.provider = Provider::Offline;
        }
        c
    }

    /// The language to use: the App's choice, or the system language when it follows the system.
    pub fn lang(&self) -> crate::i18n::Lang {
        if self.language.is_empty() { crate::i18n::system_lang() } else { crate::i18n::Lang::parse(&self.language) }
    }

    /// A config that uses only local rules and lists: no network, no model, a verdict in under a second.
    /// Background batch checks and the first step of "offline verdict first, AI review after" use it.
    pub fn offline_only(&self) -> Config {
        let mut c = Config { provider: Provider::Offline, ..self.clone() };
        c.intel.online_lookup = false;
        c.intel.virustotal_key.clear();
        c
    }

    /// The config file holds API keys, so only the owner may read it.
    pub fn save(&self) -> std::io::Result<()> {
        write_private("config.json", serde_json::to_string_pretty(self).unwrap_or_default().as_bytes())
    }
}

/// One entry in the check history. Persisted in history.jsonl: older entries hold text in the language they were written in
/// (Chinese before English was added), so text fields are shown as stored, never matched on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub time: String,
    /// terminal / paste / download / extension / scan
    pub source: String,
    pub title: String,
    #[serde(default)]
    pub cwd: String,
    pub report: Report,
    /// What the user or the program did last: executed / cancelled / quarantined / notified
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub quarantine_id: Option<String>,
}

impl LogEntry {
    pub fn new(source: &str, title: &str, cwd: &str, report: Report) -> LogEntry {
        LogEntry {
            id: format!("{}-{}", chrono::Utc::now().timestamp_millis(), std::process::id()),
            time: now(),
            source: source.into(),
            title: title.into(),
            cwd: cwd.into(),
            report,
            action: String::new(),
            quarantine_id: None,
        }
    }
}

pub fn append_log(entry: &LogEntry) {
    let dir = home();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("history.jsonl")) {
        let _ = writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default());
    }
}

/// Recent entries, newest first. An id written several times (offline verdict first, AI verdict later) keeps only the last one.
pub fn read_log(limit: usize) -> Vec<LogEntry> {
    let text = std::fs::read_to_string(home().join("history.jsonl")).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    text.lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<LogEntry>(l).ok())
        .filter(|e| seen.insert(e.id.clone()))
        .take(limit)
        .collect()
}

pub fn clear_log() {
    let _ = std::fs::remove_file(home().join("history.jsonl"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_without_language_keeps_other_settings() {
        // Configs saved before the language setting existed must load unchanged and follow the system language
        let c: Config = serde_json::from_str(r#"{"watch_downloads":false}"#).unwrap();
        assert!(!c.watch_downloads && c.language.is_empty());
        let c: Config = serde_json::from_str(r#"{"language":"zh-Hans"}"#).unwrap();
        assert_eq!(c.lang(), crate::i18n::Lang::ZhHans);
    }
}
