//! 体检：检查本机是否已有已知的感染痕迹。

use crate::home_dir;
use crate::rules::{Finding, Severity};

/// 已公开的 Contagious Interview / BeaverTail / InvisibleFerret / OtterCookie 落地痕迹
const IOC_PATHS: &[&str] = &[
    ".node_modules", ".task", ".n2", ".n3", ".npl", ".pyp", ".sysinfo",
    "Library/LaunchAgents/com.avatar.update.wake.plist", ".config/.node",
];

const SUSPICIOUS_IN_LAUNCH_AGENT: &[&str] = &["/.node_modules", "/.task", "node ", "python3 -c", "curl ", "base64 "];

pub fn run() -> Vec<Finding> {
    let home = home_dir();
    let mut findings = Vec::new();
    for p in IOC_PATHS {
        let full = home.join(p);
        if full.exists() {
            findings.push(Finding::new(Severity::High, "发现已知攻击组织常用的落地目录或文件", full.to_string_lossy()));
        }
    }
    if let Ok(rd) = std::fs::read_dir(home.join("Library/LaunchAgents")) {
        for p in rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "plist")) {
            let text = crate::read_limited(&p, 200_000);
            if let Some(s) = SUSPICIOUS_IN_LAUNCH_AGENT.iter().find(|s| text.contains(**s)) {
                findings.push(
                    Finding::new(Severity::Medium, "开机自启项里引用了可疑命令", p.to_string_lossy()).with_snippet(format!("包含 “{}”", s.trim())),
                );
            }
        }
    }
    findings
}

pub const ADVICE: &str = "断网，备份证据后删除上述文件，并在另一台干净设备上修改密码、转移加密钱包资产。";
