//! Tsuba's terminal checker. Installed with the App and called by the zsh hook.
//!
//! tsuba check [--yes] [--json] [--pasted] -- <command>   Check before running; exit 0 = go ahead, 1 = cancelled
//! tsuba check --paste -- <text>                          Quick warning on paste; offline, always exits 0
//! tsuba scan <path> [--json]                             Check an installer, extension, project folder or script; a plain
//!                                                        folder is scanned item by item for installers, scripts and projects
//! tsuba eval <sample dir> [--json]                       Measure detection and false positive rates on a sample set
//!                                                        (with malicious/ and benign/ subfolders)
//! tsuba rules keygen <key file> | sign --key <key file> <rules dir> | verify <rules dir>
//!                                                        Publish a rule pack: create a signing key, sign, verify before release
//! tsuba after-clone -- <command>                         Called by the zsh hook after git clone; checks entry points in the
//!                                                        new repository that run as soon as it is opened
//! tsuba doctor                                           Look for known signs of infection on this Mac
//! tsuba intel update [--force] | status                  Update / show threat intel (open source rules and lists)
//! tsuba ai [--all] [--json]                              Check MCP servers, skills and plugin hooks of local AI tools
//! tsuba sandbox <script file | project dir> [--install]  Try a script or project in the sandbox to see what it actually does
//!                                                        (no real internet access); --install tries installing the project's
//!                                                        dependencies to see what install scripts do (only the npm registry is reachable)
//! tsuba mcp                                              Read-only MCP tools so Claude Code and others can query check history
//!                                                        (claude mcp add tsuba -- tsuba mcp)
//!
//! Every command also takes `--lang en|zh-Hans`.

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

/// `--lang en|zh-Hans` anywhere on the command line wins; otherwise the language chosen in the App, which falls back to
/// the system language. Removes the flag from args.
fn take_lang(args: &mut Vec<String>) -> tsuba_engine::i18n::Lang {
    use tsuba_engine::i18n::Lang;
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
    Config::load().lang()
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
    eprintln!("  {}{}{}", s.dim, tr!("Evidence:"), s.rst);
    for f in shown {
        let mark = if f.severity == Severity::High { format!("{}{}", s.red, tr!("High")) } else { format!("{}{}", s.yel, tr!("Medium")) };
        let mut loc = if f.location.is_empty() { String::new() } else { format!(" {}[{}]{}", s.dim, f.location, s.rst) };
        if !f.source.is_empty() {
            loc.push_str(&format!(" {}{}{}", s.dim, tr!("Source: {source}", source = f.source), s.rst));
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
        Verdict::Allow => (s.grn, tr!("✓ Allowed")),
        Verdict::Warn => (s.yel, tr!("⚠ Needs attention")),
        Verdict::Block => (s.red, tr!("✗ Block recommended")),
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
        eprintln!("  {}", tr!("{bold}What to do:{reset} {advice}", bold = s.bold, reset = s.rst, advice = r.advice));
    }
    if r.verdict != Verdict::Allow {
        eprintln!("  {}{}{}", s.dim, tr!("See the full record in the Tsuba menu bar → Check History"), s.rst);
    }
}

/// Reads one line straight from the terminal. The zsh line editor keeps the terminal in raw mode, so switch to cooked mode while reading.
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

/// Only "run an existing project" and "open a project in an editor" are remembered: once a check passes, an unchanged project is not checked again.
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
    // "Pause Protection" was clicked in the menu bar
    if cmd.is_empty() || std::env::var_os("TSUBA_DISABLE").is_some() || store::home().join("paused").exists() {
        return 0;
    }
    let s = style();

    if flag("--paste") {
        let findings = tsuba_engine::quick_check(cmd);
        if findings.iter().any(|f| f.severity >= Severity::Medium) {
            eprintln!("\n{}{}{}{}", s.bold, s.yel, tr!("Tsuba ⚠ The command you just pasted looks risky"), s.rst);
            for f in findings.iter().filter(|f| f.severity >= Severity::Medium).take(5) {
                eprintln!("  • {}", f.message);
            }
            eprintln!("  {}{}{}", s.dim, tr!("If a web page, a chat or an \"interviewer\" told you to paste it, don't press Return yet. Tsuba runs a full check when you press Return."), s.rst);
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
        // Remembered after passing a check, or marked safe in the App; checked again as soon as the code changes
        let all_known = projects
            .iter()
            .flatten()
            .all(|root| approved[root.to_string_lossy().as_ref()].as_str() == Some(&collect::project_fingerprint(root)) || trust::is_trusted_path(root));
        if all_known {
            return 0;
        }
    }

    let kinds: Vec<String> = targets.iter().map(|t| serde_json::to_value(t.kind).unwrap().as_str().unwrap_or("").to_string()).collect();
    eprintln!("{}{}{}", s.dim, tr!("Tsuba is checking: {kinds} …", kinds = kinds.join(", ")), s.rst);
    let cfg = Config::load();
    let pasted = flag("--pasted");
    let (evidence, report) = tsuba_engine::evaluate_command(&cfg, cmd, &cwd, &targets, pasted);
    if flag("--json") {
        println!("{}", serde_json::to_string_pretty(&json!({ "evidence": evidence, "report": report })).unwrap_or_default());
    }
    print_report(&report, "");

    let yes = flag("--yes");
    // When unsure, the user can try it in the sandbox first and decide after seeing what it does
    let sbx = if yes || report.verdict == Verdict::Allow { None } else { sandbox_target(&evidence) };
    let go = match report.verdict {
        Verdict::Allow => true,
        _ if yes => true,
        Verdict::Warn if sbx.is_some() => confirm_with_sandbox(&s, &sbx.unwrap(), false),
        Verdict::Warn => matches!(ask(&format!("{}{}{}", s.yel, tr!("Run anyway? [y/N] "), s.rst)).to_lowercase().as_str(), "y" | "yes"),
        Verdict::Block if sbx.is_some() => confirm_with_sandbox(&s, &sbx.unwrap(), true),
        Verdict::Block => ask(&format!("{}{}{}", s.red, tr!("Type run to run it anyway, or press Return to cancel: "), s.rst)) == "run",
    };

    let mut entry = LogEntry::new(if pasted { "paste" } else { "terminal" }, cmd, &cwd.to_string_lossy(), report.clone());
    entry.action = if go { "executed" } else { "cancelled" }.into();
    store::append_log(&entry);

    if !go {
        eprintln!("{}{}{}", s.dim, tr!("Cancelled."), s.rst);
        return 1;
    }
    // --yes is an automatic allow, not a user's confirmation, so it is not remembered
    if report.verdict == Verdict::Allow || !yes {
        for t in evidence["targets"].as_array().into_iter().flatten() {
            if let (Some(root), Some(fp)) = (t["project"]["root"].as_str(), t["fingerprint"].as_str()) {
                approved[root] = Value::String(fp.to_string());
            }
        }
        store::save_json("approved.json", &approved);
    }
    // TOCTOU guard: when a remote script is confirmed, run the copy Tsuba already downloaded and checked
    // instead of letting the shell curl it again (the server could serve different, malicious content the second time)
    if !pasted && !yes && let Some(exec) = pinned_exec(cmd, &evidence) {
        // The zsh hook reads this line and runs the pinned script instead
        println!("TSUBA_EXEC:{exec}");
    }
    0
}

/// When a remote script is confirmed, pins the checked script to a local file and returns "interpreter 'file path'".
/// Only done for clean forms where the interpreter is certain; complex forms return None and the shell runs as usual (risk documented).
fn pinned_exec(cmd: &str, evidence: &Value) -> Option<String> {
    let interp = detect::vetted_interpreter(cmd)?;
    let text = evidence["targets"].as_array()?.iter().find_map(|t| {
        (t["kind"] == "remote_script").then(|| t["fetched"][0]["text"].as_str()).flatten()
    })?;
    // fetched[0].text is truncated to 40000 chars in the evidence; never pin a truncated copy (rather let the shell fetch again than run half a script)
    if evidence["targets"][0]["fetched"][0]["truncated"] == true {
        return None;
    }
    let dir = store::home().join("pending");
    std::fs::create_dir_all(&dir).ok()?;
    // Remove old pinned files
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

/// A plain folder (not a project, extension or .app) is scanned as a folder, item by item.
fn is_plain_folder(p: &Path) -> bool {
    p.is_dir()
        && !p.join("package.json").is_file()
        && !p.join(".vscode/tasks.json").is_file()
        && !tsuba_engine::extension::looks_like_extension(p)
        && p.extension().is_none_or(|e| e != "app")
}

fn cmd_scan(args: &[String]) -> i32 {
    let Some(raw) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("{}", tr!("Usage: tsuba scan <path>"));
        return 2;
    };
    let path = std::path::absolute(raw).unwrap_or_else(|_| PathBuf::from(raw));
    if !path.exists() {
        eprintln!("{}", tr!("Not found: {path}", path = path.display()));
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
    let r = scan::scan_folder(cfg, path, |p| eprint!("\r\x1b[2K{}{}{}", s.dim, tr!("Checking {path}", path = p.chars().rev().take(70).collect::<Vec<_>>().into_iter().rev().collect::<String>()), s.rst));
    eprint!("\r\x1b[2K");
    if as_json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    }
    eprintln!(
        "{}{}{}{}",
        s.dim,
        tr!("Checked {checked}, {unchanged} unchanged since the last scan (reused their results)", checked = r.checked, unchanged = r.unchanged),
        if r.truncated { tr!("; too many items, only the first part was scanned") } else { String::new() },
        s.rst
    );
    if r.hits.is_empty() {
        eprintln!("{}{}{}", s.grn, tr!("✓ No problems found"), s.rst);
        return 0;
    }
    for hit in &r.hits {
        let (color, label) = if hit.verdict == Verdict::Block { (s.red, "✗") } else { (s.yel, "⚠") };
        eprintln!("\n{color}{label} {}{}  {}{}{}", s.bold, hit.path, s.rst, s.dim, hit.summary);
        eprint!("{}", s.rst);
        print_findings(&s, &hit.findings);
    }
    eprintln!("\n{}{}{}", s.dim, tr!("For an AI review of one of these, run tsuba scan <path> on it."), s.rst);
    if r.hits.iter().any(|h| h.verdict == Verdict::Block) { 2 } else { 1 }
}

/// Checks a new repository right after git clone: VS Code tasks that run on open, bundled AI tool configs, hidden code.
/// Offline rules first so nothing gets in the way; the AI is only asked when something turns up. The clone already
/// happened, so this only warns and never blocks.
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
            eprintln!("{}{}{}", s.dim, tr!("Tsuba ✓ Checked {dir}: no code that runs as soon as it is opened", dir = dir), s.rst);
            continue;
        }
        let (_, _, report) = tsuba_engine::evaluate_path(&cfg, &root);
        print_report(&report, &root.to_string_lossy());
        if report.verdict != Verdict::Allow {
            eprintln!("{}{}{}", s.yel, tr!("Until you know what it is, don't open it in VS Code, Cursor or an AI coding tool. If you must look, open it in VS Code's Restricted Mode."), s.rst);
        }
        let mut entry = LogEntry::new("terminal", &tr!("{command} (checked {dir} after cloning)", command = cmd, dir = dir), &cwd.to_string_lossy(), report);
        entry.action = "notified".into();
        store::append_log(&entry);
    }
    0
}

fn cmd_doctor() -> i32 {
    let s = style();
    let findings = doctor::run();
    if findings.is_empty() {
        eprintln!("{}{}{}", s.grn, tr!("✓ No known signs of infection found"), s.rst);
        return 0;
    }
    eprintln!("{}{}{}{}", s.red, s.bold, tr!("Suspicious traces found:"), s.rst);
    for f in &findings {
        let extra = if f.snippet.is_empty() { String::new() } else { tr!(" ({snippet})", snippet = f.snippet) };
        eprintln!("  • {}{extra}", tr!("{message}: {location}", message = f.message, location = f.location));
    }
    eprintln!("{}", tr!("{bold}What to do:{reset} {advice}", bold = s.bold, reset = s.rst, advice = doctor::advice()));
    2
}

fn cmd_intel(args: &[String]) -> i32 {
    let s = style();
    let show = |m: &tsuba_engine::intel::Manifest| {
        for src in &m.sources {
            let state = match &src.error {
                Some(e) => format!("{}✗ {e}{}", s.yel, s.rst),
                None => format!("{}✓{} {}", s.grn, s.rst, tr!("{count} entries", count = src.count)),
            };
            eprintln!("  {:<28} {state}  {}{}{}", src.name, s.dim, src.version.chars().take(40).collect::<String>(), s.rst);
        }
        let updated = if m.updated.is_empty() { tr!("never") } else { m.updated.clone() };
        eprintln!("  {}{}{}", s.dim, tr!("Updated: {time}", time = updated), s.rst);
    };
    match args.first().map(String::as_str) {
        Some("update") => {
            let cfg = Config::load();
            let m = tsuba_engine::intel::update(&cfg, args.iter().any(|a| a == "--force"), |step| eprintln!("{}{}{}", s.dim, tr!("Updating {step} …", step = step), s.rst));
            show(&m);
            0
        }
        Some("status") | None => {
            show(&tsuba_engine::intel::Manifest::load());
            0
        }
        _ => {
            eprintln!("{}", tr!("Usage: tsuba intel update [--force] | tsuba intel status"));
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
    eprintln!("{}", tr!("Checked {mcp} MCP servers, {skills} skills and {hooks} plugin hooks configs", mcp = count("mcp"), skills = count("skill"), hooks = count("hooks")));
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
        eprintln!("{}{}{}", s.grn, tr!("✓ No risky AI tool configuration found"), s.rst);
    }
    match worst {
        Verdict::Allow => 0,
        Verdict::Warn => 1,
        Verdict::Block => 2,
    }
}

/// What the sandbox can run: a remote script already downloaded and checked, or a project folder about to run.
enum SandboxTarget {
    Script(String),
    Project(PathBuf),
    /// npm install in a project: try installing dependencies to see what install scripts do
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

/// Runs a script in the sandbox, prints and returns the observed behavior. None on failure.
fn run_sandbox(s: &Style, script: &str, title: &str) -> Option<tsuba_engine::sandbox::Behavior> {
    eprintln!("{}{}{}", s.dim, tr!("Running {title} in the sandbox (up to 60 seconds, no real internet access) …", title = title), s.rst);
    let b = match tsuba_engine::sandbox::run_script(script, "/bin/bash", std::time::Duration::from_secs(60)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", tr!("Sandbox run failed: {error}", error = e));
            return None;
        }
    };
    print_behavior(s, &b, title);
    Some(b)
}

/// Prints the behavior and evidence of one sandbox run.
fn print_behavior(s: &Style, b: &tsuba_engine::sandbox::Behavior, title: &str) {
    let timed_out = if b.timed_out { tr!(" (stopped at the time limit)") } else { String::new() };
    let ran = tr!("Ran for {seconds} s{timed_out}, exit code {code}", seconds = format!("{:.1}", b.seconds), timed_out = timed_out, code = format!("{:?}", b.exit_code));
    eprintln!("\n{}{ran}{}", s.dim, s.rst);
    if !b.network.is_empty() {
        eprintln!("  {}{}{}", s.bold, tr!("Network requests:"), s.rst);
        let separator = tr!(", ");
        for ev in &b.network {
            let mut leak = if ev.leaked.is_empty() {
                String::new()
            } else {
                let decoys = ev.leaked.iter().map(|m| tsuba_engine::sandbox::decoy_label(m).to_string()).collect::<Vec<_>>().join(&separator);
                format!("  {}{}{}", s.red, tr!("← sent decoy data: {decoys}", decoys = decoys), s.rst)
            };
            if !ev.secrets.is_empty() {
                leak.push_str(&format!("  {}{}{}", s.red, tr!("← the request seems to carry: {secrets}", secrets = ev.secrets.iter().map(|k| tsuba_engine::sandbox::secret_label(k)).collect::<Vec<_>>().join(&separator)), s.rst));
            }
            let note = if ev.forwarded { tr!(" (official npm registry, allowed)") } else { String::new() };
            eprintln!("   • {} {}{}{note}{}{leak}", ev.target, s.dim, ev.request, s.rst);
        }
    }
    // When it didn't really run (no node, dependencies failed to install) show the end of the output,
    // otherwise "no bad behavior seen" would be misread as safe
    if b.exit_code.is_some_and(|c| c != 0) && !b.output.trim().is_empty() {
        let lines: Vec<&str> = b.output.trim_end().lines().collect();
        eprintln!("  {}{}{}", s.bold, tr!("The program didn't exit normally. Last lines of its output:"), s.rst);
        for l in &lines[lines.len().saturating_sub(6)..] {
            eprintln!("   {}{l}{}", s.dim, s.rst);
        }
    }
    if !b.new_files.is_empty() {
        eprintln!("  {}{}{}", s.bold, tr!("New files:"), s.rst);
        for f in &b.new_files {
            eprintln!("   • {f}");
        }
    }
    if !b.denied.is_empty() {
        eprintln!("  {}{}{}", s.bold, tr!("Operations blocked by the sandbox:"), s.rst);
        for d in b.denied.iter().take(12) {
            eprintln!("   • {} {}{}{} {}", d.process, s.dim, d.operation, s.rst, d.target);
        }
        if b.denied.len() > 12 {
            eprintln!("   {}{}{}", s.dim, tr!("… and {count} more", count = b.denied.len() - 12), s.rst);
        }
    }
    let findings = tsuba_engine::sandbox::findings(b);
    print_report(
        &Report { verdict: tsuba_engine::rules::offline_verdict(&findings), summary: tr!("This is what the sandbox observed (seeing nothing bad doesn't mean it is safe)"), reasons: vec![], advice: String::new(), source: "sandbox".into(), model: String::new(), findings },
        title,
    );
}

/// On Warn or Block, offer a sandbox trial before the final decision. With block set, running still requires typing run.
fn confirm_with_sandbox(s: &Style, target: &SandboxTarget, block: bool) -> bool {
    let prompt = if block {
        format!("{}{}{}", s.red, tr!("[s] Try in the sandbox / type run to run it anyway / Return to cancel: "), s.rst)
    } else {
        format!("{}{}{}", s.yel, tr!("[s] Try in the sandbox / [y] Run anyway / Return to cancel: "), s.rst)
    };
    let ans = ask(&prompt).to_lowercase();
    if ans == "s" {
        let timeout = std::time::Duration::from_secs(60);
        match target {
            SandboxTarget::Script(script) => {
                run_sandbox(s, script, &tr!("the remote script"));
            }
            SandboxTarget::Project(dir) => {
                let argv = tsuba_engine::sandbox::project_start_argv(dir);
                eprintln!("{}{}{}", s.dim, tr!("Running {title} in the sandbox (up to 60 seconds, no real internet access) …", title = argv.join(" ")), s.rst);
                match tsuba_engine::sandbox::run_project(dir, &argv, timeout) {
                    Ok(b) => print_behavior(s, &b, &dir.to_string_lossy()),
                    Err(e) => eprintln!("{}", tr!("Sandbox run failed: {error}", error = e)),
                }
            }
            SandboxTarget::Install(dir) => {
                if let Some(b) = run_install_sandbox(s, dir) {
                    print_behavior(s, &b, &dir.to_string_lossy());
                }
            }
        }
        // Decide after seeing the behavior
        return if block {
            ask(&format!("{}{}{}", s.red, tr!("Type run to run it anyway, or press Return to cancel: "), s.rst)) == "run"
        } else {
            matches!(ask(&format!("{}{}{}", s.yel, tr!("Run anyway? [y/N] "), s.rst)).to_lowercase().as_str(), "y" | "yes")
        };
    }
    if block { ans == "run" } else { matches!(ans.as_str(), "y" | "yes") }
}

const INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

fn run_install_sandbox(s: &Style, dir: &Path) -> Option<tsuba_engine::sandbox::Behavior> {
    eprintln!("{}{}{}", s.dim, tr!("Trying the dependency install in the sandbox ({command}, up to 90 seconds, only the official npm registry is reachable) …", command = tsuba_engine::sandbox::install_argv().join(" ")), s.rst);
    match tsuba_engine::sandbox::run_install(dir, INSTALL_TIMEOUT) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("{}", tr!("Sandbox run failed: {error}", error = e));
            None
        }
    }
}

fn cmd_sandbox(args: &[String]) -> i32 {
    let s = style();
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("{}", tr!("Usage: tsuba sandbox <script file | project folder> [--install]"));
        return 2;
    };
    if !tsuba_engine::sandbox::available() {
        eprintln!("{}", tr!("This system has no sandbox-exec, so the sandbox isn't available"));
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
        // A project folder: run its start command in the sandbox
        let argv = tsuba_engine::sandbox::project_start_argv(p);
        eprintln!("{}{}{}", s.dim, tr!("Running {title} in the sandbox (up to 60 seconds, no real internet access) …", title = format!("{} {path}", argv.join(" "))), s.rst);
        match tsuba_engine::sandbox::run_project(p, &argv, timeout) {
            Ok(b) => {
                print_behavior(&s, &b, path);
                b
            }
            Err(e) => {
                eprintln!("{}", tr!("Sandbox run failed: {error}", error = e));
                return 2;
            }
        }
    } else {
        let script = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{}", tr!("Can't read {path}: {error}", path = path, error = e));
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

/// Sample set evaluation against the acceptance thresholds in PRD section 4; exits 1 when they are not met, so it can run in CI.
fn cmd_eval(args: &[String]) -> i32 {
    use tsuba_engine::evaluation::{self, MAX_BENIGN_BLOCK, MAX_BENIGN_WARN, MIN_DETECTION};
    let Some(raw) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("{}", tr!("Usage: tsuba eval <sample folder> (with malicious/ and benign/ subfolders; each file or subfolder is one sample)"));
        return 2;
    };
    let root = Path::new(raw);
    if !root.join("malicious").is_dir() && !root.join("benign").is_dir() {
        eprintln!("{}", tr!("{dir} has no malicious/ or benign/ subfolder", dir = root.display()));
        return 2;
    }
    let s = style();
    let ev = evaluation::run(&Config::load(), root, |name| eprint!("\r\x1b[2K{}{}{}", s.dim, tr!("Checking {path}", path = name), s.rst));
    eprint!("\r\x1b[2K");
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&ev).unwrap_or_default());
    }
    let pct = |x: f64| format!("{:.1}%", x * 100.0);
    let mark = |ok: bool| if ok { format!("{}✓{}", s.grn, s.rst) } else { format!("{}✗{}", s.red, s.rst) };
    eprintln!("{}{}{}", s.bold, tr!("Sample set evaluation (offline rules only)"), s.rst);
    eprintln!(
        "  {}",
        tr!("{mark} Detected        {hits} / {total} = {rate}   (target ≥ {target})", mark = mark(ev.malicious > 0 && ev.detection_rate() >= MIN_DETECTION), hits = ev.detected, total = ev.malicious, rate = pct(ev.detection_rate()), target = pct(MIN_DETECTION))
    );
    eprintln!(
        "  {}",
        tr!("{mark} Benign blocked  {hits} / {total} = {rate}   (target < {target})", mark = mark(ev.benign > 0 && ev.benign_block_rate() < MAX_BENIGN_BLOCK), hits = ev.benign_blocked, total = ev.benign, rate = pct(ev.benign_block_rate()), target = pct(MAX_BENIGN_BLOCK))
    );
    eprintln!(
        "  {}",
        tr!("{mark} Benign warned   {hits} / {total} = {rate}   (target < {target})", mark = mark(ev.benign > 0 && ev.benign_warn_rate() < MAX_BENIGN_WARN), hits = ev.benign_warned, total = ev.benign, rate = pct(ev.benign_warn_rate()), target = pct(MAX_BENIGN_WARN))
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
    show(&tr!("Missed:"), ev.missed().collect());
    show(&tr!("False positives:"), ev.false_positives().collect());
    if ev.passes() { 0 } else { 1 }
}

/// Rule pack signing, for whoever publishes rule packs. The key file holds a 32-byte seed in hex and lives only on the release machine.
fn cmd_rules(args: &[String]) -> i32 {
    use tsuba_engine::intel::tsuba as pack;
    let read_secret = |path: &str| -> Result<[u8; 32], String> {
        let text = std::fs::read_to_string(path).map_err(|e| tr!("Can't read the private key {path}: {error}", path = path, error = e))?;
        tsuba_engine::net::unhex(&text).and_then(|b| b.try_into().ok()).ok_or_else(|| tr!("{path} is not a valid private key", path = path))
    };
    let read_pack = |dir: &str| -> Result<(String, String), String> {
        let d = Path::new(dir);
        let r = |n: &str| std::fs::read_to_string(d.join(n)).map_err(|e| tr!("Can't read {path}: {error}", path = d.join(n).display(), error = e));
        Ok((r("tsuba.yar")?, r("tsuba.toml")?))
    };
    // Positional arguments: drop --options and the value after --key
    let key_value = args.iter().position(|a| a == "--key").map(|i| i + 1);
    let pos: Vec<&String> = args.iter().enumerate().skip(1).filter(|(i, a)| !a.starts_with("--") && Some(*i) != key_value).map(|(_, a)| a).collect();
    let result = match (args.first().map(String::as_str), pos.as_slice()) {
        (Some("keygen"), [out]) => (|| {
            if Path::new(out.as_str()).exists() {
                return Err(tr!("{path} already exists; not overwritten", path = out));
            }
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed)).map_err(|e| e.to_string())?;
            write_private(Path::new(out.as_str()), tsuba_engine::net::hex(&seed).as_bytes()).ok_or_else(|| tr!("Couldn't write the private key file"))?;
            println!("{}", pack::public_key(&seed));
            eprintln!("{}", tr!("Private key written to {path} (readable only by you). Add the public key above to TRUSTED_KEYS in crates/engine/src/intel/tsuba.rs.", path = out));
            Ok(())
        })(),
        (Some("sign"), [dir]) => (|| {
            let key = args.iter().position(|a| a == "--key").and_then(|i| args.get(i + 1)).ok_or_else(|| tr!("Missing --key <private key file>"))?;
            let secret = read_secret(key)?;
            let (yar, t) = read_pack(dir)?;
            pack::check_pack(&yar, &t)?;
            std::fs::write(Path::new(dir.as_str()).join("tsuba.sig"), pack::sign(&yar, &t, &secret)).map_err(|e| e.to_string())?;
            eprintln!("{}", tr!("Signed: {dir}/tsuba.sig (public key {key})", dir = dir, key = pack::public_key(&secret)));
            Ok(())
        })(),
        (Some("verify"), [dir]) => (|| {
            let (yar, t) = read_pack(dir)?;
            let sig = std::fs::read_to_string(Path::new(dir.as_str()).join("tsuba.sig")).map_err(|e| tr!("Can't read {path}: {error}", path = "tsuba.sig", error = e))?;
            pack::check_pack(&yar, &t)?;
            pack::verify(&yar, &t, &sig, pack::TRUSTED_KEYS)?;
            eprintln!("{}", tr!("✓ The signature is valid and the rule pack compiles"));
            Ok(())
        })(),
        _ => Err(tr!("Usage: tsuba rules keygen <private key file> | tsuba rules sign --key <private key file> <rules folder> | tsuba rules verify <rules folder>")),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// MCP stdio transport: one JSON-RPC message per line. Stdout carries protocol messages only; anything else goes to stderr.
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
            Err(_) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error: not valid JSON" } })),
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
