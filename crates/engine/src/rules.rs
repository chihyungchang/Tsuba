//! 离线规则：不联网、不调用模型也能给出的判断。
//!
//! 具体的检测模式不写在代码里，放在规则包 crates/engine/rules/tsuba.yar（见 intel::tsuba），可以单独更新。
//! 这里只保留结构性的判断：不可见字符、把代码推到屏幕右侧、直连公网 IP，以及结论怎么算。

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
    /// 命中的规则 ID（来自规则包时才有）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule: String,
    #[serde(rename = "where", default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snippet: String,
    /// 结论来自哪份情报、按什么授权使用（“OpenSSF Malicious Packages · Apache-2.0”），本地规则的结构性判断没有
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

impl Finding {
    pub fn new(severity: Severity, message: impl Into<String>, location: impl Into<String>) -> Self {
        Finding { severity, message: message.into(), rule: String::new(), location: location.into(), snippet: String::new(), source: String::new() }
    }

    /// 写明这条证据来自哪份情报
    pub fn with_source(mut self, (name, license): crate::intel::Credit) -> Self {
        self.source = format!("{name} · {license}");
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = snippet.into();
        self
    }
}

use Severity::{High, Low, Medium};

/// 规则包里“调用系统命令”这条规则：在扩展和 skill 里很常见，单独出现时降为低风险
pub const CHILD_PROCESS_RULE: &str = "tsuba_child_process";

static IP_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:https?|wss?)://([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}").unwrap());
// 一行超长且中间有大段空白：把代码藏到编辑器右侧看不见的位置
static HIDDEN_OFFSCREEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\S[ \t]{150,}\S").unwrap());

pub fn scan_text(text: &str, location: &str) -> Vec<Finding> {
    let mut findings = crate::intel::tsuba::scan(text, location);
    if let Some(f) = public_ip_url(text, location) {
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
        // Markdown 表格会用大量空格对齐列，不算
        if line.trim_start().starts_with('|') {
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
/// 说明文档里的命中降一级：文档里写 `curl | bash` 安装步骤、举 webhook 例子都很正常。
/// 不可见字符、要求对用户隐瞒、写给 AI 审查员的话不降级，这些在文档里同样可疑。
pub fn soften_for_docs(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let keep = f.message.contains("不可见") || crate::intel::tsuba::doc_keep(&f.rule);
        if !keep {
            f.severity = match f.severity {
                High => Medium,
                _ => Low,
            };
        }
    }
}

pub fn is_doc(path: &str) -> bool {
    let p = path.to_lowercase();
    [".md", ".txt", ".mdx", ".rst"].iter().any(|e| p.ends_with(e))
}

pub fn score(findings: &[Finding]) -> u32 {
    let mut seen = std::collections::HashSet::new();
    findings.iter().filter(|f| seen.insert((f.severity, f.message.as_str()))).map(|f| f.severity.score()).sum::<u32>().min(100)
}

pub fn offline_verdict(findings: &[Finding]) -> Verdict {
    if findings.iter().any(|f| f.severity == High) {
        return Verdict::Block;
    }
    // 低风险命中只作为证据，不参与判断：正常的工具几乎都会调用系统命令、自动激活，
    // 大型打包代码也会命中很多条 GuardDog 的“可疑写法”规则
    let mediums: Vec<Finding> = findings.iter().filter(|f| f.severity == Medium).cloned().collect();
    match score(&mediums) {
        s if s >= 30 => Verdict::Block,
        s if s > 0 => Verdict::Warn,
        _ => Verdict::Allow,
    }
}
