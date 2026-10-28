//! Tsuba 终端检查程序，随 App 安装，由 zsh 钩子调用。
//!
//! tsuba check [--yes] [--json] [--pasted] -- <命令>   执行前检查；退出码 0 = 可以执行，1 = 取消
//! tsuba check --paste -- <文本>                       粘贴时的快速提醒，不联网，总是返回 0
//! tsuba scan <路径> [--json]                          检查安装包、扩展、项目目录或脚本文件；普通文件夹逐个扫里面的安装包、脚本和项目
//! tsuba eval <样本目录> [--json]                       在样本集上量检出率和误报率（目录下分 malicious/ 和 benign/）
//! tsuba rules keygen <私钥文件> | sign --key <私钥文件> <规则目录> | verify <规则目录>
//!                                                     发布规则包：生成签名钥匙、签名、发布前核对
//! tsuba after-clone -- <命令>                         git clone 之后由 zsh 钩子调用，检查新仓库里打开就会执行的入口
//! tsuba doctor                                        检查本机是否已有已知的感染痕迹
//! tsuba intel update [--force] | status               更新 / 查看威胁情报（开源规则和名单）
//! tsuba ai [--all] [--json]                           检查本机 AI 工具的 MCP server、skill 和插件 hooks
//! tsuba sandbox <脚本文件 | 项目目录> [--install]       把脚本或项目放进沙箱试运行，看它实际做了什么（不联真实外网）；
//!                                                     --install 试装项目依赖，看安装脚本做了什么（只放行 npm 官方源）
//! tsuba mcp                                           只读 MCP 工具，让 Claude Code 等查询检查记录（claude mcp add tsuba -- tsuba mcp）

/// User-facing text in the CLI: `tr!("Found {n} files", n = count)`. Defined before the modules so they can use it.
macro_rules! tr {
    ($($args:tt)*) => { tsuba_engine::tr_in!(crate::ZH_HANS, $($args)*) };
}

mod mcp;

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tsuba_engine::detect::{self, Kind};
use tsuba_engine::rules::{Finding, Severity, Verdict};
use tsuba_engine::store::{self, Config, LogEntry};
use tsuba_engine::{Report, collect, doctor, scan, trust};

static ZH_HANS: tsuba_engine::i18n::Catalog = tsuba_engine::i18n::Catalog::new(|| tsuba_engine::i18n::parse_catalog(include_str!("../locales/zh-Hans.json")));

/// `--lang en|zh-Hans` anywhere on the command line wins; otherwise the system language. Removes the flag from args.
fn take_lang(args: &mut Vec<String>) -> tsuba_engine::i18n::Lang {
    use tsuba_engine::i18n::{Lang, system_lang};
    if let Some(i) = args.iter().position(|a| a == "--lang" || a.starts_with("--lang=")) {
        // after `--` everything belongs to the checked command, not to us
        if args.iter().position(|a| a == "--").is_none_or(|end| i < end) {
            let flag = args.remove(i);
            let value = match flag.strip_prefix("--lang=") {
                Some(v) => v.to_string(),
                None if i < args.len() => args.remove(i),
                None => String::new(),
            };
            return Lang::parse(&value);
        }
    }
    system_lang()
}

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
        let mut loc = if f.location.is_empty() { String::new() } else { format!(" {}[{}]{}", s.dim, f.location, s.rst) };
        if !f.source.is_empty() {
            loc.push_str(&format!(" {}来源：{}{}", s.dim, f.source, s.rst));
        }
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
        // 检查通过后自动记住的，或者用户在 App 里标记为安全的；代码一变就重新检查
        let all_known = projects
            .iter()
            .flatten()
            .all(|root| approved[root.to_string_lossy().as_ref()].as_str() == Some(&collect::project_fingerprint(root)) || trust::is_trusted_path(root));
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
    // 拿不准时，可以先放进沙箱试运行，看它实际做什么再决定
    let sbx = if yes || report.verdict == Verdict::Allow { None } else { sandbox_target(&evidence) };
    let go = match report.verdict {
        Verdict::Allow => true,
        _ if yes => true,
        Verdict::Warn if sbx.is_some() => confirm_with_sandbox(&s, &sbx.unwrap(), false),
        Verdict::Warn => matches!(ask(&format!("{}仍然执行？[y/N] {}", s.yel, s.rst)).to_lowercase().as_str(), "y" | "yes"),
        Verdict::Block if sbx.is_some() => confirm_with_sandbox(&s, &sbx.unwrap(), true),
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
    // TOCTOU 防护：远程脚本确认执行时，跑 Tsuba 已经下载检查过的那一份，
    // 不让 shell 重新 curl（否则服务器可以第二次下发不一样的恶意内容）
    if !pasted && !yes && let Some(exec) = pinned_exec(cmd, &evidence) {
        // 这一行被 zsh 钩子读走，改成直接运行已固定的脚本
        println!("TSUBA_EXEC:{exec}");
    }
    0
}

/// 远程脚本确认执行时，把已检查过的脚本固定到本地文件，返回“解释器 '文件路径'”。
/// 只在能确定解释器的干净形式下这么做；复杂形式返回 None，shell 照常执行（风险见文档）。
fn pinned_exec(cmd: &str, evidence: &Value) -> Option<String> {
    let interp = detect::vetted_interpreter(cmd)?;
    let text = evidence["targets"].as_array()?.iter().find_map(|t| {
        (t["kind"] == "remote_script").then(|| t["fetched"][0]["text"].as_str()).flatten()
    })?;
    // fetched[0].text 在证据里被截断到 40000 字；截断过就不固定（宁可让 shell 重跑，也不执行残缺脚本）
    if evidence["targets"][0]["fetched"][0]["truncated"] == true {
        return None;
    }
    let dir = store::home().join("pending");
    std::fs::create_dir_all(&dir).ok()?;
    // 清掉旧的固定文件
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for p in rd.flatten().map(|e| e.path()) {
            let old = p.metadata().and_then(|m| m.modified()).map(|t| t.elapsed().map(|d| d.as_secs() > 3600).unwrap_or(true)).unwrap_or(true);
            if old {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    let path = dir.join(format!("{}.sh", std::process::id()));
    write_private(&path, text.as_bytes())?;
    Some(format!("{interp} {}", shell_quote(&path.to_string_lossy())))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn write_private(path: &Path, bytes: &[u8]) -> Option<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).ok()?;
    f.write_all(bytes).ok()?;
    Some(())
}

/// 普通文件夹（不是项目、扩展或 .app）按文件夹扫描，逐个检查里面的东西。
fn is_plain_folder(p: &Path) -> bool {
    p.is_dir()
        && !p.join("package.json").is_file()
        && !p.join(".vscode/tasks.json").is_file()
        && !tsuba_engine::extension::looks_like_extension(p)
        && p.extension().is_none_or(|e| e != "app")
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
    if is_plain_folder(&path) {
        return scan_plain_folder(&cfg, &path, args.iter().any(|a| a == "--json"));
    }
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

fn scan_plain_folder(cfg: &Config, path: &Path, as_json: bool) -> i32 {
    let s = style();
    let r = scan::scan_folder(cfg, path, |p| eprint!("\r\x1b[2K{}检查 {}{}", s.dim, p.chars().rev().take(70).collect::<Vec<_>>().into_iter().rev().collect::<String>(), s.rst));
    eprint!("\r\x1b[2K");
    if as_json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    }
    eprintln!(
        "{}检查了 {} 个，{} 个没变化沿用上次结果{}{}",
        s.dim,
        r.checked,
        r.unchanged,
        if r.truncated { "；东西太多，只扫了前一部分" } else { "" },
        s.rst
    );
    if r.hits.is_empty() {
        eprintln!("{}✓ 没有发现问题{}", s.grn, s.rst);
        return 0;
    }
    for hit in &r.hits {
        let (color, label) = if hit.verdict == Verdict::Block { (s.red, "✗") } else { (s.yel, "⚠") };
        eprintln!("\n{color}{label} {}{}  {}{}{}", s.bold, hit.path, s.rst, s.dim, hit.summary);
        eprint!("{}", s.rst);
        print_findings(&s, &hit.findings);
    }
    eprintln!("\n{}需要 AI 进一步判断的，可以单独运行 tsuba scan <路径>。{}", s.dim, s.rst);
    if r.hits.iter().any(|h| h.verdict == Verdict::Block) { 2 } else { 1 }
}

/// git clone 之后马上检查新仓库：VS Code 打开即执行的任务、自带的 AI 工具配置、隐藏代码。
/// 先用离线规则，不打扰；发现问题才调用 AI 给出完整解释。克隆已经完成，这里只提醒、不拦截。
fn cmd_after_clone(args: &[String]) -> i32 {
    let cmd = match args.iter().position(|a| a == "--") {
        Some(i) => args[i + 1..].join(" "),
        None => args.join(" "),
    };
    if std::env::var_os("TSUBA_DISABLE").is_some() || store::home().join("paused").exists() {
        return 0;
    }
    let s = style();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let cfg = Config::load();
    for dir in detect::clone_dirs(&cmd) {
        let root = cwd.join(&dir);
        if !root.is_dir() || trust::is_trusted_path(&root) {
            continue;
        }
        let (_, _, quick) = tsuba_engine::evaluate_path(&cfg.offline_only(), &root);
        if quick.verdict == Verdict::Allow {
            eprintln!("{}Tsuba ✓ 已检查 {dir}：没有发现打开就会执行的代码{}", s.dim, s.rst);
            continue;
        }
        let (_, _, report) = tsuba_engine::evaluate_path(&cfg, &root);
        print_report(&report, &root.to_string_lossy());
        if report.verdict != Verdict::Allow {
            eprintln!("{}在弄清楚之前，先不要用 VS Code、Cursor 或 AI 编程工具打开它；一定要看，用 VS Code 的受限模式（Restricted Mode）打开。{}", s.yel, s.rst);
        }
        let mut entry = LogEntry::new("terminal", &format!("{cmd}（克隆后检查 {dir}）"), &cwd.to_string_lossy(), report);
        entry.action = "notified".into();
        store::append_log(&entry);
    }
    0
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

/// 沙箱能跑的目标：已下载检查过的远程脚本，或一个待运行的项目目录。
enum SandboxTarget {
    Script(String),
    Project(PathBuf),
    /// 在项目里 npm install：试装依赖，看安装脚本做了什么
    Install(PathBuf),
}

fn sandbox_target(evidence: &Value) -> Option<SandboxTarget> {
    if !tsuba_engine::sandbox::available() {
        return None;
    }
    for t in evidence["targets"].as_array()?.iter() {
        match t["kind"].as_str() {
            Some("remote_script") if t["fetched"][0]["truncated"] != true => {
                if let Some(text) = t["fetched"][0]["text"].as_str() {
                    return Some(SandboxTarget::Script(text.into()));
                }
            }
            Some("project_run") => {
                if let Some(root) = t["project"]["root"].as_str() {
                    return Some(SandboxTarget::Project(PathBuf::from(root)));
                }
            }
            Some("pkg_install") => {
                if let Some(root) = t["project"]["root"].as_str() {
                    return Some(SandboxTarget::Install(PathBuf::from(root)));
                }
            }
            _ => {}
        }
    }
    None
}

/// 在沙箱里运行脚本并打印行为，返回观察到的行为。失败返回 None。
fn run_sandbox(s: &Style, script: &str, title: &str) -> Option<tsuba_engine::sandbox::Behavior> {
    eprintln!("{}在沙箱里运行 {title}（最多 60 秒，不会联真实外网）…{}", s.dim, s.rst);
    let b = match tsuba_engine::sandbox::run_script(script, "/bin/bash", std::time::Duration::from_secs(60)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("沙箱运行失败：{e}");
            return None;
        }
    };
    print_behavior(s, &b, title);
    Some(b)
}

/// 打印一次沙箱运行的行为和证据。
fn print_behavior(s: &Style, b: &tsuba_engine::sandbox::Behavior, title: &str) {
    eprintln!("\n{}运行 {:.1} 秒{}，退出码 {:?}{}", s.dim, b.seconds, if b.timed_out { "（超时被终止）" } else { "" }, b.exit_code, s.rst);
    if !b.network.is_empty() {
        eprintln!("  {}网络请求：{}", s.bold, s.rst);
        for ev in &b.network {
            let mut leak = if ev.leaked.is_empty() { String::new() } else { format!("  {}← 发出了诱饵数据 {}{}", s.red, ev.leaked.iter().map(|m| tsuba_engine::sandbox::decoy_label(m)).collect::<Vec<_>>().join("、"), s.rst) };
            if !ev.secrets.is_empty() {
                leak.push_str(&format!("  {}← 请求里带着疑似 {}{}", s.red, ev.secrets.join("、"), s.rst));
            }
            let note = if ev.forwarded { "（npm 官方源，已放行）" } else { "" };
            eprintln!("   • {} {}{}{note}{}{leak}", ev.target, s.dim, ev.request, s.rst);
        }
    }
    // 没跑起来时（缺 node、依赖装不上）把输出末尾给用户看，不然“没看到坏行为”会被误读成安全
    if b.exit_code.is_some_and(|c| c != 0) && !b.output.trim().is_empty() {
        let lines: Vec<&str> = b.output.trim_end().lines().collect();
        eprintln!("  {}程序没有正常结束，输出的最后几行：{}", s.bold, s.rst);
        for l in &lines[lines.len().saturating_sub(6)..] {
            eprintln!("   {}{l}{}", s.dim, s.rst);
        }
    }
    if !b.new_files.is_empty() {
        eprintln!("  {}新建的文件：{}", s.bold, s.rst);
        for f in &b.new_files {
            eprintln!("   • {f}");
        }
    }
    if !b.denied.is_empty() {
        eprintln!("  {}被沙箱挡下的操作：{}", s.bold, s.rst);
        for d in b.denied.iter().take(12) {
            eprintln!("   • {} {}{}{} {}", d.process, s.dim, d.operation, s.rst, d.target);
        }
        if b.denied.len() > 12 {
            eprintln!("   {}…还有 {} 条{}", s.dim, b.denied.len() - 12, s.rst);
        }
    }
    let findings = tsuba_engine::sandbox::findings(b);
    print_report(
        &Report { verdict: tsuba_engine::rules::offline_verdict(&findings), summary: "以下是沙箱里观察到的行为（没看到坏行为不代表一定安全）".into(), reasons: vec![], advice: String::new(), source: "sandbox".into(), model: String::new(), findings },
        title,
    );
}

/// “提醒 / 拦截”时先问要不要沙箱试运行，再做最终决定。block 为 true 时最终要输入 run 才执行。
fn confirm_with_sandbox(s: &Style, target: &SandboxTarget, block: bool) -> bool {
    let prompt = if block {
        format!("{}[s]沙箱试运行 / 输入 run 强制执行 / 直接回车取消：{}", s.red, s.rst)
    } else {
        format!("{}[s]沙箱试运行 / [y]仍然执行 / 直接回车取消：{}", s.yel, s.rst)
    };
    let ans = ask(&prompt).to_lowercase();
    if ans == "s" {
        let timeout = std::time::Duration::from_secs(60);
        match target {
            SandboxTarget::Script(script) => {
                run_sandbox(s, script, "远程脚本");
            }
            SandboxTarget::Project(dir) => {
                let argv = tsuba_engine::sandbox::project_start_argv(dir);
                eprintln!("{}在沙箱里运行 {}（最多 60 秒，不联真实外网）…{}", s.dim, argv.join(" "), s.rst);
                match tsuba_engine::sandbox::run_project(dir, &argv, timeout) {
                    Ok(b) => print_behavior(s, &b, &dir.to_string_lossy()),
                    Err(e) => eprintln!("沙箱运行失败：{e}"),
                }
            }
            SandboxTarget::Install(dir) => {
                if let Some(b) = run_install_sandbox(s, dir) {
                    print_behavior(s, &b, &dir.to_string_lossy());
                }
            }
        }
        // 看完行为再做最终决定
        return if block {
            ask(&format!("{}输入 run 强制执行，直接回车取消：{}", s.red, s.rst)) == "run"
        } else {
            matches!(ask(&format!("{}仍然执行？[y/N] {}", s.yel, s.rst)).to_lowercase().as_str(), "y" | "yes")
        };
    }
    if block { ans == "run" } else { matches!(ans.as_str(), "y" | "yes") }
}

const INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

fn run_install_sandbox(s: &Style, dir: &Path) -> Option<tsuba_engine::sandbox::Behavior> {
    eprintln!("{}在沙箱里试装依赖（{}，最多 90 秒，只放行 npm 官方源）…{}", s.dim, tsuba_engine::sandbox::install_argv().join(" "), s.rst);
    match tsuba_engine::sandbox::run_install(dir, INSTALL_TIMEOUT) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("沙箱运行失败：{e}");
            None
        }
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
    let timeout = std::time::Duration::from_secs(60);
    let p = Path::new(path);
    let b = if p.is_dir() && args.iter().any(|a| a == "--install") {
        match run_install_sandbox(&s, p) {
            Some(b) => {
                print_behavior(&s, &b, path);
                b
            }
            None => return 2,
        }
    } else if p.is_dir() {
        // 项目目录：在沙箱里跑它的启动命令
        let argv = tsuba_engine::sandbox::project_start_argv(p);
        eprintln!("{}在沙箱里运行 {} {}（最多 60 秒，不联真实外网）…{}", s.dim, argv.join(" "), path, s.rst);
        match tsuba_engine::sandbox::run_project(p, &argv, timeout) {
            Ok(b) => {
                print_behavior(&s, &b, path);
                b
            }
            Err(e) => {
                eprintln!("沙箱运行失败：{e}");
                return 2;
            }
        }
    } else {
        let script = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("读不到 {path}：{e}");
                return 2;
            }
        };
        match run_sandbox(&s, &script, path) {
            Some(b) => b,
            None => return 2,
        }
    };
    let findings = tsuba_engine::sandbox::findings(&b);
    let verdict = tsuba_engine::rules::offline_verdict(&findings);
    match verdict {
        Verdict::Allow => 0,
        Verdict::Warn => 1,
        Verdict::Block => 2,
    }
}

/// 样本集验收：按 PRD 第 4 节的验收线打分，没达标时退出码 1，方便放进 CI。
fn cmd_eval(args: &[String]) -> i32 {
    use tsuba_engine::evaluation::{self, MAX_BENIGN_BLOCK, MAX_BENIGN_WARN, MIN_DETECTION};
    let Some(raw) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("用法：tsuba eval <样本目录>（目录下放 malicious/ 和 benign/ 两个子目录，每个文件或子目录算一个样本）");
        return 2;
    };
    let root = Path::new(raw);
    if !root.join("malicious").is_dir() && !root.join("benign").is_dir() {
        eprintln!("{} 下面没有 malicious/ 或 benign/ 子目录", root.display());
        return 2;
    }
    let s = style();
    let ev = evaluation::run(&Config::load(), root, |name| eprint!("\r\x1b[2K{}检查 {name}{}", s.dim, s.rst));
    eprint!("\r\x1b[2K");
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&ev).unwrap_or_default());
    }
    let pct = |x: f64| format!("{:.1}%", x * 100.0);
    let mark = |ok: bool| if ok { format!("{}✓{}", s.grn, s.rst) } else { format!("{}✗{}", s.red, s.rst) };
    eprintln!("{}样本集验收（只用离线规则）{}", s.bold, s.rst);
    eprintln!(
        "  {} 检出率        {} / {} = {}   （目标 ≥ {}）",
        mark(ev.malicious > 0 && ev.detection_rate() >= MIN_DETECTION),
        ev.detected,
        ev.malicious,
        pct(ev.detection_rate()),
        pct(MIN_DETECTION)
    );
    eprintln!(
        "  {} 正常样本被拦截 {} / {} = {}   （目标 < {}）",
        mark(ev.benign > 0 && ev.benign_block_rate() < MAX_BENIGN_BLOCK),
        ev.benign_blocked,
        ev.benign,
        pct(ev.benign_block_rate()),
        pct(MAX_BENIGN_BLOCK)
    );
    eprintln!(
        "  {} 正常样本被提醒 {} / {} = {}   （目标 < {}）",
        mark(ev.benign > 0 && ev.benign_warn_rate() < MAX_BENIGN_WARN),
        ev.benign_warned,
        ev.benign,
        pct(ev.benign_warn_rate()),
        pct(MAX_BENIGN_WARN)
    );
    let show = |title: &str, items: Vec<&evaluation::SampleResult>| {
        if items.is_empty() {
            return;
        }
        eprintln!("\n{}{title}{}", s.bold, s.rst);
        for x in items {
            let why = x.top_finding.as_ref().map(|f| format!("{} [{}]", f.message, f.location)).unwrap_or_default();
            eprintln!("  • {}  {}{why}{}", x.name, s.dim, s.rst);
        }
    };
    show("漏报：", ev.missed().collect());
    show("误报：", ev.false_positives().collect());
    if ev.passes() { 0 } else { 1 }
}

/// 规则包签名（给发布规则包的人用）。私钥文件是 32 字节种子的十六进制，只放在发布机器上。
fn cmd_rules(args: &[String]) -> i32 {
    use tsuba_engine::intel::tsuba as pack;
    let read_secret = |path: &str| -> Result<[u8; 32], String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("读不到私钥 {path}：{e}"))?;
        tsuba_engine::net::unhex(&text).and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{path} 不是有效的私钥"))
    };
    let read_pack = |dir: &str| -> Result<(String, String), String> {
        let d = Path::new(dir);
        let r = |n: &str| std::fs::read_to_string(d.join(n)).map_err(|e| format!("读不到 {}：{e}", d.join(n).display()));
        Ok((r("tsuba.yar")?, r("tsuba.toml")?))
    };
    // 位置参数：去掉 --xxx 选项和 --key 后面的值
    let key_value = args.iter().position(|a| a == "--key").map(|i| i + 1);
    let pos: Vec<&String> = args.iter().enumerate().skip(1).filter(|(i, a)| !a.starts_with("--") && Some(*i) != key_value).map(|(_, a)| a).collect();
    let result = match (args.first().map(String::as_str), pos.as_slice()) {
        (Some("keygen"), [out]) => (|| {
            if Path::new(out.as_str()).exists() {
                return Err(format!("{out} 已经存在，没有覆盖"));
            }
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed)).map_err(|e| e.to_string())?;
            write_private(Path::new(out.as_str()), tsuba_engine::net::hex(&seed).as_bytes()).ok_or("写不进私钥文件")?;
            println!("{}", pack::public_key(&seed));
            eprintln!("私钥已写入 {out}（只有你能读）。把上面的公钥加进 crates/engine/src/intel/tsuba.rs 的 TRUSTED_KEYS。");
            Ok(())
        })(),
        (Some("sign"), [dir]) => (|| {
            let key = args.iter().position(|a| a == "--key").and_then(|i| args.get(i + 1)).ok_or("缺少 --key <私钥文件>")?;
            let secret = read_secret(key)?;
            let (yar, t) = read_pack(dir)?;
            pack::check_pack(&yar, &t)?;
            std::fs::write(Path::new(dir.as_str()).join("tsuba.sig"), pack::sign(&yar, &t, &secret)).map_err(|e| e.to_string())?;
            eprintln!("已签名：{dir}/tsuba.sig（公钥 {}）", pack::public_key(&secret));
            Ok(())
        })(),
        (Some("verify"), [dir]) => (|| {
            let (yar, t) = read_pack(dir)?;
            let sig = std::fs::read_to_string(Path::new(dir.as_str()).join("tsuba.sig")).map_err(|e| format!("读不到 tsuba.sig：{e}"))?;
            pack::check_pack(&yar, &t)?;
            pack::verify(&yar, &t, &sig, pack::TRUSTED_KEYS)?;
            eprintln!("✓ 签名有效，规则包能编译");
            Ok(())
        })(),
        _ => Err("用法：tsuba rules keygen <私钥文件> | tsuba rules sign --key <私钥文件> <规则目录> | tsuba rules verify <规则目录>".to_string()),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// MCP 的 stdio 传输：一行一条 JSON-RPC 消息。标准输出只能写协议消息，其他提示都走标准错误。
fn cmd_mcp() -> i32 {
    let history = |n: usize| tsuba_engine::store::read_log(n);
    let quarantine = tsuba_engine::quarantine::list;
    let src = mcp::Sources { history: &history, quarantine: &quarantine };
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => mcp::handle(&req, &src),
            Err(_) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "不是合法的 JSON" } })),
        };
        if let Some(reply) = reply {
            let mut out = stdout.lock();
            if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    }
    0
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    tsuba_engine::i18n::set_lang(take_lang(&mut args));
    let code = match args.first().map(String::as_str) {
        Some("check") => cmd_check(&args[1..]),
        Some("scan") => cmd_scan(&args[1..]),
        Some("after-clone") => cmd_after_clone(&args[1..]),
        Some("eval") => cmd_eval(&args[1..]),
        Some("rules") => cmd_rules(&args[1..]),
        Some("doctor") => cmd_doctor(),
        Some("intel") => cmd_intel(&args[1..]),
        Some("ai") => cmd_ai(&args[1..]),
        Some("sandbox") => cmd_sandbox(&args[1..]),
        Some("mcp") => cmd_mcp(),
        Some("--version" | "version") => {
            println!("tsuba {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            eprintln!("{}", tr!("Usage: tsuba check -- <command> | tsuba scan <path> | tsuba doctor | tsuba mcp (read-only MCP tools for Claude Code and others) [--lang en|zh-Hans]"));
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zh_hans_catalog_matches_sources() {
        let sources = tsuba_engine::i18n::read_sources(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
        if let Err(e) = tsuba_engine::i18n::check_catalog(&ZH_HANS, &sources, &[]) {
            panic!("{e}");
        }
    }

    #[test]
    fn lang_flag_stops_at_double_dash() {
        let mut args: Vec<String> = ["check", "--", "ls", "--lang", "en"].map(String::from).to_vec();
        take_lang(&mut args);
        assert_eq!(args.len(), 5);
        let mut args: Vec<String> = ["--lang=zh-Hans", "scan", "x"].map(String::from).to_vec();
        assert_eq!(take_lang(&mut args), tsuba_engine::i18n::Lang::ZhHans);
        assert_eq!(args, ["scan", "x"]);
    }
}
