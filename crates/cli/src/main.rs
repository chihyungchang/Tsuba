//! Tsuba 终端检查程序，随 App 安装，由 zsh 钩子调用。
//!
//! tsuba check [--yes] [--json] [--pasted] -- <命令>   执行前检查；退出码 0 = 可以执行，1 = 取消
//! tsuba check --paste -- <文本>                       粘贴时的快速提醒，不联网，总是返回 0
//! tsuba scan <路径> [--json]                          检查安装包、扩展、项目目录或脚本文件
//! tsuba doctor                                        检查本机是否已有已知的感染痕迹
//! tsuba intel update [--force] | status               更新 / 查看威胁情报（开源规则和名单）
//! tsuba ai [--all] [--json]                           检查本机 AI 工具的 MCP server、skill 和插件 hooks
//! tsuba sandbox <脚本文件>                             把脚本放进沙箱试运行，看它实际做了什么（不联真实外网）

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tsuba_engine::detect::{self, Kind};
use tsuba_engine::rules::{Finding, Severity, Verdict};
use tsuba_engine::store::{self, Config, LogEntry};
use tsuba_engine::{Report, collect, doctor};

struct Style {
    red: &'static str,
    yel: &'static str,
    grn: &'static str,
    dim: &'static str,
    bold: &'static str,
    rst: &'static str,
}

fn style() -> Style {
    if unsafe { libc::isatty(2) } == 1 {
        Style { red: "\x1b[31m", yel: "\x1b[33m", grn: "\x1b[32m", dim: "\x1b[2m", bold: "\x1b[1m", rst: "\x1b[0m" }
    } else {
        Style { red: "", yel: "", grn: "", dim: "", bold: "", rst: "" }
    }
}

fn print_findings(s: &Style, findings: &[Finding]) {
    let shown: Vec<&Finding> = findings.iter().filter(|f| f.severity >= Severity::Medium).take(8).collect();
    if shown.is_empty() {
        return;
    }
    eprintln!("  {}证据：{}", s.dim, s.rst);
    for f in shown {
        let mark = if f.severity == Severity::High { format!("{}高", s.red) } else { format!("{}中", s.yel) };
        let loc = if f.location.is_empty() { String::new() } else { format!(" {}[{}]{}", s.dim, f.location, s.rst) };
        eprintln!("   {mark}{} {}{loc}", s.rst, f.message);
        if !f.snippet.is_empty() {
            eprintln!("      {}{}{}", s.dim, f.snippet.chars().take(160).collect::<String>(), s.rst);
        }
    }
}

fn print_report(r: &Report, title: &str) {
    let s = style();
    let (color, label) = match r.verdict {
        Verdict::Allow => (s.grn, "✓ 放行"),
        Verdict::Warn => (s.yel, "⚠ 需要注意"),
        Verdict::Block => (s.red, "✗ 建议拦截"),
    };
    let title = if title.is_empty() { String::new() } else { format!("  {}{title}{}", s.dim, s.rst) };
    eprintln!("\n{}{color}Tsuba {label}{}{title}", s.bold, s.rst);
    if !r.summary.is_empty() {
        eprintln!("  {}", r.summary);
    }
    for reason in &r.reasons {
        eprintln!("  • {reason}");
    }
    if r.verdict != Verdict::Allow || r.source == "offline" {
        print_findings(&s, &r.findings);
    }
    if !r.advice.is_empty() && r.verdict != Verdict::Allow {
        eprintln!("  {}建议：{}{}", s.bold, s.rst, r.advice);
    }
    if r.verdict != Verdict::Allow {
        eprintln!("  {}完整记录可以在 Tsuba 菜单栏 → 检查记录 里查看{}", s.dim, s.rst);
    }
}

/// 直接从终端读一行。zsh 行编辑器运行时终端处于原始模式，读之前临时切回普通模式。
fn ask(prompt: &str) -> String {
    let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else { return String::new() };
    use std::os::fd::AsRawFd;
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let have_old = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if have_old {
        let mut new = old;
        new.c_iflag |= libc::ICRNL;
        new.c_lflag |= libc::ICANON | libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &new) };
    }
    let mut w = &tty;
    let _ = w.write_all(prompt.as_bytes());
    let mut line = String::new();
    let _ = BufReader::new(&tty).read_line(&mut line);
    if have_old {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    }
    line.trim().to_string()
}

/// 只有“运行已有项目”“用编辑器打开项目”会被记住；第一次检查通过后，项目没变化就不再打扰。
fn project_of(t: &detect::Target, cwd: &Path) -> Option<PathBuf> {
    match t.kind {
        Kind::ProjectRun => collect::find_project_root(cwd),
        Kind::EditorOpen => cwd.join(t.str("path")).canonicalize().ok(),
        _ => None,
    }
}

fn cmd_check(args: &[String]) -> i32 {
    let flag = |f: &str| args.iter().take_while(|a| *a != "--").any(|a| a == f);
    let cmd = match args.iter().position(|a| a == "--") {
        Some(i) => args[i + 1..].join(" "),
        None => args.iter().filter(|a| !a.starts_with("--")).cloned().collect::<Vec<_>>().join(" "),
    };
    let cmd = cmd.trim();
    // App 菜单栏里点了“暂停守护”
    if cmd.is_empty() || std::env::var_os("TSUBA_DISABLE").is_some() || store::home().join("paused").exists() {
        return 0;
    }
    let s = style();

    if flag("--paste") {
        let findings = tsuba_engine::quick_check(cmd);
        if findings.iter().any(|f| f.severity >= Severity::Medium) {
            eprintln!("\n{}{}Tsuba ⚠ 你刚粘贴的命令有风险{}", s.bold, s.yel, s.rst);
            for f in findings.iter().filter(|f| f.severity >= Severity::Medium).take(5) {
                eprintln!("  • {}", f.message);
            }
            eprintln!("  {}如果是网页、聊天或“面试官”让你粘贴的，先别按回车。按回车时 Tsuba 会做完整检查。{}", s.dim, s.rst);
        }
        return 0;
    }

    let targets = detect::detect(cmd);
    if targets.is_empty() {
        return 0;
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let mut approved = store::load_json("approved.json");
    if !approved.is_object() {
        approved = json!({});
    }
    let projects: Vec<Option<PathBuf>> = targets.iter().map(|t| project_of(t, &cwd)).collect();
    if projects.iter().all(|p| p.is_some()) {
        let all_known = projects.iter().flatten().all(|root| approved[root.to_string_lossy().as_ref()].as_str() == Some(&collect::project_fingerprint(root)));
        if all_known {
            return 0;
        }
    }

    let kinds: Vec<String> = targets.iter().map(|t| serde_json::to_value(t.kind).unwrap().as_str().unwrap_or("").to_string()).collect();
    eprintln!("{}Tsuba 正在检查：{} …{}", s.dim, kinds.join(", "), s.rst);
    let cfg = Config::load();
    let pasted = flag("--pasted");
    let (evidence, report) = tsuba_engine::evaluate_command(&cfg, cmd, &cwd, &targets, pasted);
    if flag("--json") {
        println!("{}", serde_json::to_string_pretty(&json!({ "evidence": evidence, "report": report })).unwrap_or_default());
    }
    print_report(&report, "");

    let yes = flag("--yes");
    let go = match report.verdict {
        Verdict::Allow => true,
        _ if yes => true,
        Verdict::Warn => matches!(ask(&format!("{}仍然执行？[y/N] {}", s.yel, s.rst)).to_lowercase().as_str(), "y" | "yes"),
        Verdict::Block => ask(&format!("{}输入 run 强制执行，直接回车取消：{}", s.red, s.rst)) == "run",
    };

    let mut entry = LogEntry::new(if pasted { "paste" } else { "terminal" }, cmd, &cwd.to_string_lossy(), report.clone());
    entry.action = if go { "executed" } else { "cancelled" }.into();
    store::append_log(&entry);

    if !go {
        eprintln!("{}已取消执行。{}", s.dim, s.rst);
        return 1;
    }
    // --yes 是自动放行，不算用户确认过，不记住
    if report.verdict == Verdict::Allow || !yes {
        for t in evidence["targets"].as_array().into_iter().flatten() {
            if let (Some(root), Some(fp)) = (t["project"]["root"].as_str(), t["fingerprint"].as_str()) {
                approved[root] = Value::String(fp.to_string());
            }
        }
        store::save_json("approved.json", &approved);
    }
    0
}

fn cmd_scan(args: &[String]) -> i32 {
    let Some(raw) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("用法：tsuba scan <路径>");
        return 2;
    };
    let path = std::path::absolute(raw).unwrap_or_else(|_| PathBuf::from(raw));
    if !path.exists() {
        eprintln!("找不到：{}", path.display());
        return 2;
    }
    let cfg = Config::load();
    let (_, evidence, report) = tsuba_engine::evaluate_path(&cfg, &path);
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&json!({ "evidence": evidence, "report": report })).unwrap_or_default());
    }
    print_report(&report, &path.to_string_lossy());
    let mut entry = LogEntry::new("scan", &path.to_string_lossy(), "", report.clone());
    entry.action = "scanned".into();
    store::append_log(&entry);
    match report.verdict {
        Verdict::Allow => 0,
        Verdict::Warn => 1,
        Verdict::Block => 2,
    }
}

fn cmd_doctor() -> i32 {
    let s = style();
    let findings = doctor::run();
    if findings.is_empty() {
        eprintln!("{}✓ 没有发现已知的感染痕迹{}", s.grn, s.rst);
        return 0;
    }
    eprintln!("{}{}发现可疑痕迹：{}", s.red, s.bold, s.rst);
    for f in &findings {
        let extra = if f.snippet.is_empty() { String::new() } else { format!("（{}）", f.snippet) };
        eprintln!("  • {}：{}{extra}", f.message, f.location);
    }
    eprintln!("建议：{}", doctor::ADVICE);
    2
}

fn cmd_intel(args: &[String]) -> i32 {
    let s = style();
    let show = |m: &tsuba_engine::intel::Manifest| {
        for src in &m.sources {
            let state = match &src.error {
                Some(e) => format!("{}✗ {e}{}", s.yel, s.rst),
                None => format!("{}✓{} {} 条", s.grn, s.rst, src.count),
            };
            eprintln!("  {:<28} {state}  {}{}{}", src.name, s.dim, src.version.chars().take(40).collect::<String>(), s.rst);
        }
        eprintln!("  {}更新时间：{}{}", s.dim, if m.updated.is_empty() { "从未" } else { &m.updated }, s.rst);
    };
    match args.first().map(String::as_str) {
        Some("update") => {
            let cfg = Config::load();
            let m = tsuba_engine::intel::update(&cfg, args.iter().any(|a| a == "--force"), |step| eprintln!("{}更新 {step} …{}", s.dim, s.rst));
            show(&m);
            0
        }
        Some("status") | None => {
            show(&tsuba_engine::intel::Manifest::load());
            0
        }
        _ => {
            eprintln!("用法：tsuba intel update [--force] | tsuba intel status");
            2
        }
    }
}

fn cmd_ai(args: &[String]) -> i32 {
    let s = style();
    let cfg = Config::load();
    let items = tsuba_engine::agents::scan_all(cfg.intel.online_lookup);
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&items).unwrap_or_default());
    }
    let count = |k: &str| items.iter().filter(|i| i.kind == k).count();
    eprintln!("检查了 {} 个 MCP server、{} 个 skill、{} 个插件 hooks 配置", count("mcp"), count("skill"), count("hooks"));
    let all = args.iter().any(|a| a == "--all");
    let mut worst = Verdict::Allow;
    for i in items.iter().filter(|i| all || i.verdict != Verdict::Allow) {
        worst = worst.max(i.verdict);
        let (c, label) = match i.verdict {
            Verdict::Allow => (s.grn, "✓"),
            Verdict::Warn => (s.yel, "⚠"),
            Verdict::Block => (s.red, "✗"),
        };
        eprintln!("\n{c}{label}{} {}{}{}  {}{}{}", s.rst, s.bold, i.title, s.rst, s.dim, i.detail, s.rst);
        print_findings(&s, &i.findings);
    }
    if worst == Verdict::Allow {
        eprintln!("{}✓ 没有发现有风险的 AI 工具配置{}", s.grn, s.rst);
    }
    match worst {
        Verdict::Allow => 0,
        Verdict::Warn => 1,
        Verdict::Block => 2,
    }
}

fn cmd_sandbox(args: &[String]) -> i32 {
    let s = style();
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("用法：tsuba sandbox <脚本文件>");
        return 2;
    };
    if !tsuba_engine::sandbox::available() {
        eprintln!("当前系统没有 sandbox-exec，无法使用沙箱");
        return 2;
    }
    let script = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("读不到 {path}：{e}");
            return 2;
        }
    };
    eprintln!("{}在沙箱里运行 {path}（最多 60 秒，不会联真实外网）…{}", s.dim, s.rst);
    let b = match tsuba_engine::sandbox::run_script(&script, "/bin/bash", std::time::Duration::from_secs(60)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("沙箱运行失败：{e}");
            return 2;
        }
    };
    eprintln!("\n{}运行 {:.1} 秒{}，退出码 {:?}{}", s.dim, b.seconds, if b.timed_out { "（超时被终止）" } else { "" }, b.exit_code, s.rst);
    if !b.network.is_empty() {
        eprintln!("  {}网络请求：{}", s.bold, s.rst);
        for ev in &b.network {
            let leak = if ev.leaked.is_empty() { String::new() } else { format!("  {}← 发出了诱饵数据 {}{}", s.red, ev.leaked.join("、"), s.rst) };
            eprintln!("   • {} {}{}{leak}", ev.target, s.dim, ev.request);
        }
    }
    if !b.new_files.is_empty() {
        eprintln!("  {}新建的文件：{}", s.bold, s.rst);
        for f in &b.new_files {
            eprintln!("   • {f}");
        }
    }
    let findings = tsuba_engine::sandbox::findings(&b);
    let verdict = tsuba_engine::rules::offline_verdict(&findings);
    print_report(
        &Report { verdict, summary: "以下是沙箱里观察到的行为（没看到坏行为不代表一定安全）".into(), reasons: vec![], advice: String::new(), source: "sandbox".into(), model: String::new(), findings },
        path,
    );
    match verdict {
        Verdict::Allow => 0,
        Verdict::Warn => 1,
        Verdict::Block => 2,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("check") => cmd_check(&args[1..]),
        Some("scan") => cmd_scan(&args[1..]),
        Some("doctor") => cmd_doctor(),
        Some("intel") => cmd_intel(&args[1..]),
        Some("ai") => cmd_ai(&args[1..]),
        Some("sandbox") => cmd_sandbox(&args[1..]),
        Some("--version" | "version") => {
            println!("tsuba {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            eprintln!("用法：tsuba check -- <命令> | tsuba scan <路径> | tsuba doctor");
            2
        }
    };
    std::process::exit(code);
}
