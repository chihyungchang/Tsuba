//! Offline rules: verdicts that need neither the network nor a model.
//!
//! Detection patterns live in the rule pack crates/engine/rules/tsuba.yar (see intel::tsuba), not in code, so they update on their own.
//! Only structural checks stay here: invisible characters, code pushed off screen, hard-coded public IPs, and how a verdict is scored.

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
    /// ID of the rule that matched (rule pack rules and structural findings)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule: String,
    #[serde(rename = "where", default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snippet: String,
    /// Which intel source the finding came from and under what licence ("OpenSSF Malicious Packages · Apache-2.0"); empty for structural checks
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

impl Finding {
    pub fn new(severity: Severity, message: impl Into<String>, location: impl Into<String>) -> Self {
        Finding { severity, message: message.into(), rule: String::new(), location: location.into(), snippet: String::new(), source: String::new() }
    }

    /// Records which intel source this evidence came from
    pub fn with_source(mut self, (name, license): crate::intel::Credit) -> Self {
        self.source = format!("{name} · {license}");
        self
    }

    /// Structural findings get a fixed ID so code can recognise them without matching user-facing text.
    pub fn with_rule(mut self, rule: &str) -> Self {
        self.rule = rule.to_string();
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = snippet.into();
        self
    }
}

use Severity::{High, Low, Medium};

/// The rule pack's "runs system commands" rule: common in extensions and skills, so on its own it drops to low risk
pub const CHILD_PROCESS_RULE: &str = "tsuba_child_process";

static IP_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:https?|wss?)://([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}").unwrap());
// A very long line with a big run of whitespace: code hidden past the right edge of the editor
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

/// Connects straight to a hard-coded public IP and port. Private and loopback addresses (common in tests and proxy configs) don't count.
fn public_ip_url(text: &str, location: &str) -> Option<Finding> {
    IP_URL.captures_iter(text).find_map(|c| {
        let a: u32 = c[1].parse().ok()?;
        let b: u32 = c[2].parse().ok()?;
        let private = matches!(a, 0 | 10 | 127) || (a == 172 && (16..32).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254);
        let m = c.get(0)?;
        (!private).then(|| {
            Finding::new(High, tr!("Connects straight to a hard-coded IP address and port (typical of a C2 server)"), location).with_snippet(snippet(text, m.start(), m.end(), 120))
        })
    })
}

/// Code hidden past the right edge: a line starts with visible, normal code, then a long run of whitespace, then the real code.
/// Minified code has lines tens of thousands of characters long with the odd long run of spaces (indentation inside string constants), so the gap must start within one screen.
fn hidden_offscreen(text: &str, location: &str) -> Option<Finding> {
    for line in text.lines() {
        if line.len() <= 300 {
            continue;
        }
        // Markdown tables pad columns with lots of spaces; they don't count
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
            Finding::new(High, tr!("Code is pushed off the right edge of the screen by whitespace, out of sight (a typical way to hide a poisoned payload)"), location)
                .with_snippet(format!("{left} {} {right}", tr!("⟨{gap} spaces⟩", gap = gap))),
        );
    }
    None
}

pub const INVISIBLE_UNICODE: &str = "invisible_unicode";

/// Invisible Unicode characters: extension poisoning such as GlassWorm encodes code as variation selectors that editors don't show at all;
/// bidirectional control characters make the code that is displayed differ from the code that runs (Trojan Source).
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
    // Emoji contain single variation selectors too; only a run of more than a dozen is suspicious
    if max_run >= 16 {
        let before = collapse(&text[floor_char(text, run_at.saturating_sub(80))..run_at]);
        out.push(
            Finding::new(High, tr!("The code hides a run of {count} invisible Unicode characters that may encode malicious code (the GlassWorm technique)", count = max_run), location)
                .with_rule(INVISIBLE_UNICODE)
                .with_snippet(format!("{before}{}", tr!("⟨{count} invisible characters⟩", count = max_run))),
        );
    }
    if bidi > 0 {
        out.push(Finding::new(Low, tr!("The code has {count} bidirectional text control characters, so what is displayed may differ from what runs", count = bidi), location));
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

/// A rule that matches in many files counts once, or a large project would rack up a score just by having many files.
/// Matches in documentation drop one level: install steps with `curl | bash` and webhook examples are normal in docs.
/// Invisible characters, instructions to hide things from the user and messages aimed at an AI reviewer don't drop: they are just as suspicious in docs.
pub fn soften_for_docs(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let keep = f.rule == INVISIBLE_UNICODE || crate::intel::tsuba::doc_keep(&f.rule);
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
    // Low-risk matches are evidence only and don't affect the verdict: normal tools almost all run system commands and activate automatically,
    // and large bundled code matches many of GuardDog's "suspicious pattern" rules
    let mediums: Vec<Finding> = findings.iter().filter(|f| f.severity == Medium).cloned().collect();
    match score(&mediums) {
        s if s >= 30 => Verdict::Block,
        s if s > 0 => Verdict::Warn,
        _ => Verdict::Allow,
    }
}
