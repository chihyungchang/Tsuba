//! 样本集验收（PRD 第 4 节）：在一批已知结果的样本上量检出率和误报率。
//!
//! 样本目录的结构：
//!   <目录>/malicious/   恶意样本，每个文件或子目录算一个（项目、扩展、安装包、脚本）
//!   <目录>/benign/      正常样本：热门包、热门扩展、真实用户的日常项目
//!
//! 只用离线规则和本机名单：结果可复现，不受网络和模型波动影响，也不把样本发出去。
//! 按时间切分（较早样本调规则、较新样本验收）靠把两批样本放进不同的目录分别跑。

use crate::rules::{Finding, Verdict};
use crate::store::Config;
use serde::Serialize;
use std::path::Path;

/// PRD 第 4 节的验收线
pub const MIN_DETECTION: f64 = 0.80;
pub const MAX_BENIGN_BLOCK: f64 = 0.01;
pub const MAX_BENIGN_WARN: f64 = 0.05;

#[derive(Clone, Debug, Serialize)]
pub struct SampleResult {
    pub name: String,
    pub malicious: bool,
    pub verdict: Verdict,
    /// 最严重的那条证据，方便看漏报和误报的原因
    pub top_finding: Option<Finding>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Evaluation {
    pub samples: Vec<SampleResult>,
    pub malicious: usize,
    pub detected: usize,
    pub benign: usize,
    pub benign_blocked: usize,
    pub benign_warned: usize,
}

fn ratio(n: usize, d: usize) -> f64 {
    if d == 0 { 0.0 } else { n as f64 / d as f64 }
}

impl Evaluation {
    /// 判为“提醒”或“拦截”的恶意样本比例
    pub fn detection_rate(&self) -> f64 {
        ratio(self.detected, self.malicious)
    }
    pub fn benign_block_rate(&self) -> f64 {
        ratio(self.benign_blocked, self.benign)
    }
    pub fn benign_warn_rate(&self) -> f64 {
        ratio(self.benign_warned, self.benign)
    }
    /// 达到验收线。没有样本的那一半不算达标，免得空目录“全部通过”。
    pub fn passes(&self) -> bool {
        self.malicious > 0
            && self.benign > 0
            && self.detection_rate() >= MIN_DETECTION
            && self.benign_block_rate() < MAX_BENIGN_BLOCK
            && self.benign_warn_rate() < MAX_BENIGN_WARN
    }
    pub fn missed(&self) -> impl Iterator<Item = &SampleResult> {
        self.samples.iter().filter(|s| s.malicious && s.verdict == Verdict::Allow)
    }
    pub fn false_positives(&self) -> impl Iterator<Item = &SampleResult> {
        self.samples.iter().filter(|s| !s.malicious && s.verdict != Verdict::Allow)
    }
}

fn samples_in(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| !p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'))).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// 跑一遍样本集。progress 收到正在检查的样本名。
pub fn run(cfg: &Config, root: &Path, mut progress: impl FnMut(&str)) -> Evaluation {
    let cfg = cfg.offline_only();
    let mut ev = Evaluation::default();
    for (sub, malicious) in [("malicious", true), ("benign", false)] {
        for p in samples_in(&root.join(sub)) {
            let name = format!("{sub}/{}", p.file_name().unwrap_or_default().to_string_lossy());
            progress(&name);
            // 白名单不参与验收：直接走规则
            let (_, _, report) = crate::evaluate_path_untrusted(&cfg, &p);
            let verdict = report.verdict;
            if malicious {
                ev.malicious += 1;
                ev.detected += (verdict != Verdict::Allow) as usize;
            } else {
                ev.benign += 1;
                ev.benign_blocked += (verdict == Verdict::Block) as usize;
                ev.benign_warned += (verdict == Verdict::Warn) as usize;
            }
            let top_finding = report.findings.into_iter().max_by_key(|f| f.severity);
            ev.samples.push(SampleResult { name, malicious, verdict, top_finding });
        }
    }
    ev
}
