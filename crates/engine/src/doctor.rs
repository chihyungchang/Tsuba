//! Health Check: looks for traces of known infections on this Mac. The list of traces is in the rule pack's tsuba.toml.

use crate::home_dir;
use crate::rules::{Finding, Severity};

pub fn run() -> Vec<Finding> {
    let home = home_dir();
    let mut findings = Vec::new();
    let lists = crate::intel::tsuba::lists();
    for p in &lists.ioc_paths {
        let full = home.join(p);
        if full.exists() {
            findings.push(Finding::new(Severity::High, tr!("Found a folder or file that known attack groups commonly drop on infected Macs"), full.to_string_lossy()));
        }
    }
    if let Ok(rd) = std::fs::read_dir(home.join("Library/LaunchAgents")) {
        for p in rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "plist")) {
            let text = crate::read_limited(&p, 200_000);
            if let Some(s) = lists.launch_agent_markers.iter().find(|s| text.contains(s.as_str())) {
                findings.push(
                    Finding::new(Severity::Medium, tr!("A launch agent that starts at login runs a suspicious command"), p.to_string_lossy()).with_snippet(tr!("Contains \"{text}\"", text = s.trim())),
                );
            }
        }
    }
    findings
}

/// What to do when the Health Check finds something
pub fn advice() -> String {
    tr!("Disconnect from the network, back up the evidence, then delete the files above. On another, clean device, change your passwords and move your crypto wallet funds.")
}
