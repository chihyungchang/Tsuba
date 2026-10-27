//! 本机存储：配置、检查记录、已放行的项目指纹。全部放在 ~/.tsuba，不上传。

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

/// 先写临时文件再改名，避免 App 和终端同时写时读到半个文件。
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

/// 用哪个模型做 AI 判断。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// 调用本机的 Claude Code（claude -p），用它登录的账号，不需要 API Key。适合个人使用
    #[default]
    ClaudeCli,
    /// Anthropic Claude API
    Claude,
    /// 任何兼容 OpenAI Chat Completions 接口的服务：Ollama、LM Studio、llama.cpp、vLLM，以及各家云端模型
    OpenaiCompatible,
    /// 只用离线规则
    Offline,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaudeConfig {
    pub api_key: String,
    pub model: String,
    pub effort: String,
    /// claude 命令的位置，留空时自动查找
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
    /// 例如 Ollama 的 http://127.0.0.1:11434/v1
    pub base_url: String,
    pub model: String,
    /// 本地服务一般不需要
    pub api_key: String,
    /// 界面上选的服务商：openai / gemini / deepseek / qwen / ollama / lmstudio / custom
    pub preset: String,
    /// 是否当作前沿模型信任：信任的模型可以把离线规则的“拦截”降为“提醒”，也可以独立给出“拦截”
    pub trusted: bool,
}

impl OpenAiCompatConfig {
    /// 本地模型推理慢、上下文短，要用更短的证据和更长的超时。
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
pub struct Config {
    pub provider: Provider,
    pub claude: ClaudeConfig,
    pub openai_compatible: OpenAiCompatConfig,
    pub watch_downloads: bool,
    pub watch_extensions: bool,
    /// 扩展被判为“拦截”时自动移入隔离区
    pub auto_quarantine: bool,
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

    /// 配置文件里有 API Key，权限设成只有自己能读。
    pub fn save(&self) -> std::io::Result<()> {
        write_private("config.json", serde_json::to_string_pretty(self).unwrap_or_default().as_bytes())
    }
}

/// 检查记录的一条。
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
    /// 用户或程序最后做了什么：executed / cancelled / quarantined / notified
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

/// 最近的记录，新的在前。
pub fn read_log(limit: usize) -> Vec<LogEntry> {
    let text = std::fs::read_to_string(home().join("history.jsonl")).unwrap_or_default();
    text.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(limit).collect()
}

pub fn clear_log() {
    let _ = std::fs::remove_file(home().join("history.jsonl"));
}
