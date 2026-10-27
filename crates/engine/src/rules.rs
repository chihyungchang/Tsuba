//! 离线规则：不联网、不调用模型也能给出的判断。
//!
//! 规则来自真实攻击样本的共性（Contagious Interview / BeaverTail / OtterCookie / InvisibleFerret /
//! GlassWorm 等），命中不等于恶意，只作为证据交给模型或在离线时打分。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn score(self) -> u32 {
        match self {
            Severity::High => 40,
            Severity::Medium => 15,
            Severity::Low => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
    #[serde(rename = "where", default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snippet: String,
}

impl Finding {
    pub fn new(severity: Severity, message: impl Into<String>, location: impl Into<String>) -> Self {
        Finding { severity, message: message.into(), location: location.into(), snippet: String::new() }
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = snippet.into();
        self
    }
}

use Severity::{High, Low, Medium};

// (严重度, 说明, 正则)
static CONTENT_RULES: LazyLock<Vec<(Severity, &'static str, Regex)>> = LazyLock::new(|| {
    let r = |s: &str| Regex::new(s).expect("规则正则无效");
    vec![
        (High, "解码后动态执行代码（eval/Function + base64），常见于混淆的投毒代码",
         r(r"(?:eval|Function)\s*\([^)]{0,200}(?:atob|base64|fromCharCode|Buffer\.from)")),
        (High, "读取浏览器密码库或加密钱包数据",
         // 只认浏览器目录下的这几个文件名，普通英文里的 “local state” 不算
         r(r#"(?:Chrome|Chromium|Brave-Browser|Microsoft Edge|Opera|Vivaldi|Arc/User Data)[^"'`\n]{0,60}/(?:Login Data|Local State|Web Data|Cookies)\b|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|ejbalbakoplchlghecdalmeeeajnimhm|\.config/solana|Exodus/exodus\.wallet|Library/Keychains/"#)),
        (High, "删除 macOS 隔离标记（绕过 Gatekeeper 安全检查）",
         r(r"(?i)xattr\s+(?:-\w*[dc]\w*\s+)+(?:com\.apple\.quarantine)?|removexattr.{0,40}quarantine")),
        (High, "在用户目录的隐藏文件夹里安装 Node 依赖或运行脚本（攻击者常用 ~/.node_modules、~/.task 等藏身）",
         r(r#"(?:homedir\(\)|~|\$HOME)["'`,\s+]*/?\.(?:node_modules|task|n2|npl|vscode-server|sysinfo)\b"#)),
        (Medium, "脚本里又下载并执行了别的脚本（多阶段投递）",
         r(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|(?:curl|wget)\b[^\n]*-o\s*\S+\s*(?:&&|;)\s*(?:chmod|bash|sh|\./)")),
        (Medium, "下载独立的 Node.js 运行时（为了脱离系统环境运行恶意 JS）",
         r(r"nodejs\.org/dist/")),
        (Medium, "调用系统命令执行（child_process）",
         r(r#"require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]"#)),
        (Medium, "大量 _0x 形式的混淆变量名",
         r(r"(?s)(?:_0x[0-9a-f]{4,}.*){8}")),
        (Medium, "写入开机自启（LaunchAgents / crontab）",
         r(r"LaunchAgents|LaunchDaemons|crontab\s+-")),
        (Medium, "解码 base64 后直接交给 shell 执行",
         r(r"base64\s+(?:-\w*[dD]\w*|--decode)\b[^;&\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
        (Medium, "代码里有疑似写给 AI 审查员的话（提示注入），正常代码不会这样写",
         r(r"(?i)ignore (?:all |any )?(?:previous|prior|above) instructions|(?:AI|LLM) (?:reviewer|auditor|scanner|security (?:reviewer|scanner))s?\b|AI 审查|请(?:直接)?放行|(?:mark|classify|treat|report) (?:this|it) as (?:safe|benign|clean)|this (?:code|file|package|script|extension) is (?:safe|benign|not malicious)")),
        (Low, "使用 sudo 提权", r(r"(?:^|\s)sudo\s")),
    ]
});

pub const CHILD_PROCESS_MSG: &str = "调用系统命令执行（child_process）";

static SOCKET_IO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"socket\.io-client").unwrap());
static HOST_INFO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:hostname|homedir|userInfo|platform)\(").unwrap());
static IP_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:https?|wss?)://([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}").unwrap());
// 一行超长且中间有大段空白：把代码藏到编辑器右侧看不见的位置
static HIDDEN_OFFSCREEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\S[ \t]{150,}\S").unwrap());

pub fn scan_text(text: &str, location: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (sev, msg, rx) in CONTENT_RULES.iter() {
        if let Some(m) = rx.find(text) {
            findings.push(Finding::new(*sev, *msg, location).with_snippet(snippet(text, m.start(), m.end(), 120)));
        }
    }
    if let Some(f) = public_ip_url(text, location) {
        findings.push(f);
    }
    if let Some(f) = socket_with_host_info(text, location) {
        findings.push(f);
    }
    if let Some(f) = hidden_offscreen(text, location) {
        findings.push(f);
    }
    findings.extend(invisible_unicode(text, location));
    findings
}

/// 直接连接硬编码的公网 IP 加端口。内网和本机地址（测试、代理配置里很常见）不算。
fn public_ip_url(text: &str, location: &str) -> Option<Finding> {
    IP_URL.captures_iter(text).find_map(|c| {
        let a: u32 = c[1].parse().ok()?;
        let b: u32 = c[2].parse().ok()?;
        let private = matches!(a, 0 | 10 | 127) || (a == 172 && (16..32).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254);
        let m = c.get(0)?;
        (!private).then(|| {
            Finding::new(High, "直接连接硬编码的 IP 地址加端口（C2 服务器的典型特征）", location).with_snippet(snippet(text, m.start(), m.end(), 120))
        })
    })
}

/// 把代码藏到编辑器右侧：一行开头是看得见的正常代码，接着一大段空白，空白后面才是真正的代码。
/// 压缩过的代码一行就有几万字符，中间偶尔有长串空白（字符串常量里的缩进），所以要求空白出现在一屏之内。
fn hidden_offscreen(text: &str, location: &str) -> Option<Finding> {
    for line in text.lines() {
        if line.len() <= 300 {
            continue;
        }
        let Some(m) = HIDDEN_OFFSCREEN.find(line) else { continue };
        let left = collapse(&line[..m.start() + 1]);
        let right = collapse(&line[m.end() - 1..]);
        if line[..m.start()].chars().count() > 200 || left.is_empty() || right.chars().count() < 20 {
            continue;
        }
        let gap = line[m.start()..m.end()].chars().count() - 2;
        let left: String = left.chars().rev().take(60).collect::<Vec<_>>().into_iter().rev().collect();
        let right: String = right.chars().take(200).collect();
        return Some(
            Finding::new(High, "代码被大量空白推到屏幕右侧之外，人眼看不到（典型的隐藏投毒手法）", location)
                .with_snippet(format!("{left} ⟨{gap} 个空格⟩ {right}")),
        );
    }
    None
}

/// 收集主机信息后用 socket.io 外连。两者相距 2000 字节以内才算。
fn socket_with_host_info(text: &str, location: &str) -> Option<Finding> {
    for m in SOCKET_IO.find_iter(text) {
        let lo = floor_char(text, m.start().saturating_sub(2000));
        let hi = ceil_char(text, (m.end() + 2000).min(text.len()));
        if let Some(h) = HOST_INFO.find(&text[lo..hi]) {
            let (s, e) = (lo + h.start(), lo + h.end());
            return Some(
                Finding::new(Medium, "收集主机信息后用 socket 外连", location)
                    .with_snippet(snippet(text, s.min(m.start()), e.max(m.end()).min(s.min(m.start()) + 300), 60)),
            );
        }
    }
    None
}

/// 不可见 Unicode 字符：GlassWorm 等扩展投毒把代码编码成变体选择符，编辑器里完全看不见；
/// 双向控制字符可以让代码“显示的样子”和“执行的样子”不一致（Trojan Source）。
fn invisible_unicode(text: &str, location: &str) -> Vec<Finding> {
    let is_hidden = |c: char| {
        matches!(c as u32,
            0xFE00..=0xFE0F | 0xE0100..=0xE01EF | 0xE0000..=0xE007F | 0x200B..=0x200D | 0x2060..=0x2064)
    };
    let (mut run, mut max_run, mut run_at, mut bidi) = (0usize, 0usize, 0usize, 0usize);
    let mut start = 0usize;
    for (i, c) in text.char_indices() {
        if is_hidden(c) {
            if run == 0 {
                start = i;
            }
            run += 1;
            if run > max_run {
                max_run = run;
                run_at = start;
            }
        } else {
            run = 0;
        }
        if matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069) {
            bidi += 1;
        }
    }
    let mut out = Vec::new();
    // emoji 里也会有单个变体选择符，连续出现十几个以上才可疑
    if max_run >= 16 {
        let before = collapse(&text[floor_char(text, run_at.saturating_sub(80))..run_at]);
        out.push(
            Finding::new(High, format!("代码里藏着一串连续 {max_run} 个不可见的 Unicode 字符，可能把恶意代码编码在里面（GlassWorm 手法）"), location)
                .with_snippet(format!("{before}⟨{max_run} 个不可见字符⟩")),
        );
    }
    if bidi > 0 {
        out.push(Finding::new(Low, format!("代码里有 {bidi} 个双向文本控制字符，显示出来的代码可能和实际执行的不一致"), location));
    }
    out
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn floor_char(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

pub fn snippet(text: &str, start: usize, end: usize, pad: usize) -> String {
    let lo = floor_char(text, start.saturating_sub(pad));
    let hi = ceil_char(text, (end + pad).min(text.len()));
    collapse(&text[lo..hi]).chars().take(400).collect()
}

/// 同一条规则在很多文件里命中只算一次，否则大项目会因为文件多而被“刷分”。
pub fn score(findings: &[Finding]) -> u32 {
    let mut seen = std::collections::HashSet::new();
    findings.iter().filter(|f| seen.insert((f.severity, f.message.as_str()))).map(|f| f.severity.score()).sum::<u32>().min(100)
}

pub fn offline_verdict(findings: &[Finding]) -> Verdict {
    if findings.iter().any(|f| f.severity == High) {
        return Verdict::Block;
    }
    // 只有低风险命中时不打扰：正常的工具几乎都会调用系统命令、自动激活
    let has_medium = findings.iter().any(|f| f.severity == Medium);
    match score(findings) {
        s if s >= 30 => Verdict::Block,
        _ if has_medium => Verdict::Warn,
        _ => Verdict::Allow,
    }
}
