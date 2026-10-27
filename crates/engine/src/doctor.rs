//! 体检：检查本机是否已有已知的感染痕迹。痕迹清单在规则包 tsuba.toml 里。

use crate::home_dir;
use crate::rules::{Finding, Severity};

pub fn run() -> Vec<Finding> {
    let home = home_dir();
    let mut findings = Vec::new();
    let lists = crate::intel::tsuba::lists();
    for p in &lists.ioc_paths {
        let full = home.join(p);
        if full.exists() {
            findings.push(Finding::new(Severity::High, "发现已知攻击组织常用的落地目录或文件", full.to_string_lossy()));
        }
    }
    if let Ok(rd) = std::fs::read_dir(home.join("Library/LaunchAgents")) {
        for p in rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "plist")) {
            let text = crate::read_limited(&p, 200_000);
            if let Some(s) = lists.launch_agent_markers.iter().find(|s| text.contains(s.as_str())) {
                findings.push(
                    Finding::new(Severity::Medium, "开机自启项里引用了可疑命令", p.to_string_lossy()).with_snippet(format!("包含 “{}”", s.trim())),
                );
            }
        }
    }
    findings
}

pub const ADVICE: &str = "断网，备份证据后删除上述文件，并在另一台干净设备上修改密码、转移加密钱包资产。";
