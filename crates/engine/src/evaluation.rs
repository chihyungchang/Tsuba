//! Sample set evaluation (PRD section 4): measures detection and false positive rates on samples with known outcomes.
//!
//! Sample directory layout:
//!   <dir>/malicious/   malicious samples; each file or subdirectory is one (project, extension, installer, script)
//!   <dir>/benign/      benign samples: popular packages, popular extensions, real users' everyday projects
//!
//! Only offline rules and local lists are used: results are reproducible, unaffected by network or model variance, and no
//! sample is sent anywhere. A time split (tune rules on older samples, evaluate on newer ones) is done by putting the two
//! batches in different directories and running each.

use crate::rules::{Finding, Verdict};
use crate::store::Config;
use serde::Serialize;
use std::path::Path;

/// Acceptance thresholds from PRD section 4
pub const MIN_DETECTION: f64 = 0.80;
pub const MAX_BENIGN_BLOCK: f64 = 0.01;
pub const MAX_BENIGN_WARN: f64 = 0.05;

#[derive(Clone, Debug, Serialize)]
pub struct SampleResult {
    pub name: String,
    pub malicious: bool,
    pub verdict: Verdict,
    /// The most severe finding, to see why a sample was missed or flagged
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
    /// Share of malicious samples judged Warn or Block
    pub fn detection_rate(&self) -> f64 {
        ratio(self.detected, self.malicious)
    }
    pub fn benign_block_rate(&self) -> f64 {
        ratio(self.benign_blocked, self.benign)
    }
    pub fn benign_warn_rate(&self) -> f64 {
        ratio(self.benign_warned, self.benign)
    }
    /// Meets the thresholds. A half with no samples doesn't pass, so an empty directory can't "pass everything".
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

/// Runs the sample set. `progress` receives the name of the sample being checked.
pub fn run(cfg: &Config, root: &Path, mut progress: impl FnMut(&str)) -> Evaluation {
    let cfg = cfg.offline_only();
    let mut ev = Evaluation::default();
    for (sub, malicious) in [("malicious", true), ("benign", false)] {
        for p in samples_in(&root.join(sub)) {
            let name = format!("{sub}/{}", p.file_name().unwrap_or_default().to_string_lossy());
            progress(&name);
            // The allowlist plays no part in evaluation: go straight to the rules
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
