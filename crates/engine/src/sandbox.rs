//! Dynamic analysis: run a script we are unsure about for a short while inside macOS's built-in sandbox
//! (Seatbelt / sandbox-exec) and watch what it actually does, instead of reading the code line by line.
//!
//! What we check is untrusted, so we don't rely on a single layer but stack several; if one is bypassed the next still holds:
//! 1. Least privilege: the program can only read and write a fake home folder and a work folder. It cannot write anywhere
//!    else either (no hijacking commands in /opt/homebrew/bin, no dropping files in /Applications), and external drives,
//!    other users' folders and the shared temp folders are invisible.
//! 2. Close the "make the system do it for me" exits: LaunchServices (open), AppleEvents (osascript), launchctl,
//!    the clipboard, the keychain, DNS, preferences, signalling processes outside the sandbox or reading their command
//!    lines. Seatbelt's file and network rules don't cover these, yet they can escape the sandbox or carry data out.
//! 3. Network micro-segmentation: the only reachable address is a local recording proxy, so every request is seen;
//!    direct connections to the internet are blocked by the system.
//! 4. Resource limits: file size, CPU time and process count are capped, so fork bombs and disk fillers can't take down
//!    the user's machine.
//! 5. Behaviour monitoring: decoy files (each with a unique marker), a diff of the fake home folder after the run,
//!    the operations the sandbox denied (denial records in the system log carrying this run's tag), and processes that
//!    leave the process group to linger in the background.
//!
//! Runs have a time limit. Afterwards (timed out or not) every process the run started is killed and the temp folder is removed.
//!
//! Limitations:
//! - Seeing nothing bad in a minute doesn't mean safe (some programs delay, or wait for the user to type a password).
//!   The verdict only says what was seen this time.
//! - Apple no longer recommends sandbox-exec and a VM may be needed one day; it is wrapped in this one module so it is easy to replace.
//! - The first-stage proxy only sees plain HTTP; for HTTPS it sees which host was contacted but not the content
//!   (certificate interception is left for later).
//! - When trying an install (npm install) the proxy forwards only connections to the official npm registry, so packages
//!   download and install scripts run; any other address an install script contacts is still only recorded, never let
//!   through. Dependencies installed from git URLs can't be downloaded.

use crate::rules::{Finding, Severity};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Test only: builds a sample profile to check that the real home folder is locked and the network restricted.
pub fn _profile_for_test() -> String {
    let jail = JailPaths { root: "/tmp/jail".into(), fake_home: "/tmp/jail/home".into(), work: "/tmp/jail/work".into() };
    profile(Path::new("/Users/someone"), &jail, 12345, "tag")
}

pub fn available() -> bool {
    Path::new("/usr/bin/sandbox-exec").is_file()
}

/// One network request seen by the proxy
#[derive(Clone, Debug, Serialize)]
pub struct NetEvent {
    /// Where it connected: host[:port] for HTTP, host:443 for an HTTPS CONNECT
    pub target: String,
    /// Method and path, visible only for plain HTTP requests
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request: String,
    /// Decoy markers found in the request (the program sent decoy data out)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaked: Vec<String>,
    /// Kinds of other real-looking secrets in a plain request (`SecretKind` ids); only the kind is kept, never the value.
    /// Records from before the English conversion hold Chinese kind names; `secret_label` shows those unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    /// A connection to the official npm registry during an install that was really forwarded
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forwarded: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Behavior {
    /// Exit code, or None when the program was killed for running too long
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub seconds: f64,
    /// Network requests recorded by the proxy
    pub network: Vec<NetEvent>,
    /// Files that appeared in the fake home folder during the run (relative to it)
    pub new_files: Vec<String>,
    /// The start of stdout / stderr
    pub output: String,
    /// Operations the sandbox denied (from the system log), e.g. writing to /opt/homebrew/bin or running osascript
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<Denied>,
}

/// One operation the sandbox denied
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Denied {
    /// Name of the program that tried it
    pub process: String,
    /// Seatbelt operation name, e.g. file-write-create, process-exec*, network-outbound
    pub operation: String,
    /// Target: a path, program, preferences domain or port
    pub target: String,
}

/// A decoy: a file in the fake home folder whose content carries a unique marker. If the program reads it and sends it out,
/// the marker shows up in the network request.
struct Decoy {
    rel: &'static str,
    marker: &'static str,
    label: fn() -> String,
    body: &'static str,
}

const DECOYS: &[Decoy] = &[
    Decoy { rel: ".ssh/id_ed25519", marker: "TSUBA-DECOY-SSH", label: || tr!("SSH private key"), body: "-----BEGIN OPENSSH PRIVATE KEY-----\nTSUBA-DECOY-SSH not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n" },
    Decoy { rel: ".aws/credentials", marker: "TSUBA-DECOY-AWS", label: || tr!("AWS credentials file"), body: "[default]\naws_access_key_id = TSUBA-DECOY-AWS\naws_secret_access_key = not-a-real-secret\n" },
    Decoy { rel: ".config/solana/id.json", marker: "TSUBA-DECOY-SOLANA", label: || tr!("Solana wallet"), body: "[\"TSUBA-DECOY-SOLANA\", 0, 0]\n" },
    // Stand-ins for the browser password store and wallet extension data
    Decoy { rel: "Library/Application Support/Google/Chrome/Default/Login Data", marker: "TSUBA-DECOY-CHROME", label: || tr!("Chrome password store"), body: "SQLite format 3\x00 TSUBA-DECOY-CHROME\n" },
    Decoy { rel: "Library/Application Support/Exodus/exodus.wallet/seed.seco", marker: "TSUBA-DECOY-WALLET", label: || tr!("Exodus wallet"), body: "TSUBA-DECOY-WALLET not-a-real-wallet\n" },
];

/// Decoy secrets in environment variables: same format as the real thing (some stealers validate the format before
/// sending), with a unique marker embedded. Stealing environment variables is one of the most common tricks of poisoned
/// packages, and file decoys don't catch it.
struct EnvDecoy {
    name: &'static str,
    value: &'static str,
    marker: &'static str,
    label: fn() -> String,
}

const ENV_DECOYS: &[EnvDecoy] = &[
    EnvDecoy { name: "OPENAI_API_KEY", value: "sk-proj-TSUBADECOYOPENAI7f3kQ9xLm2Vb8Nc4Rt6Yw1Zp5Hs0Jd", marker: "TSUBADECOYOPENAI", label: || tr!("OpenAI API key (environment variable)") },
    EnvDecoy { name: "ANTHROPIC_API_KEY", value: "sk-ant-api03-TSUBADECOYANTHROPIC4hG8kL2mN6pQ0rS3tV7wX1yZ5aB9cD", marker: "TSUBADECOYANTHROPIC", label: || tr!("Anthropic API key (environment variable)") },
    EnvDecoy { name: "AWS_ACCESS_KEY_ID", value: "AKIATSUBADECOYAWSK7Q", marker: "TSUBADECOYAWSK", label: || tr!("AWS access key (environment variable)") },
    EnvDecoy { name: "AWS_SECRET_ACCESS_KEY", value: "TSUBADECOYAWSSECRET/9xLm2Vb8Nc4Rt6Yw1Zp5Hs0", marker: "TSUBADECOYAWSSECRET", label: || tr!("AWS secret access key (environment variable)") },
    EnvDecoy { name: "GITHUB_TOKEN", value: "ghp_TSUBADECOYGITHUB4hG8kL2mN6pQ0rS3tV7w", marker: "TSUBADECOYGITHUB", label: || tr!("GitHub token (environment variable)") },
    EnvDecoy { name: "NPM_TOKEN", value: "npm_TSUBADECOYNPM8kL2mN6pQ0rS3tV7wX1yZ5a", marker: "TSUBADECOYNPM", label: || tr!("npm token (environment variable)") },
];

/// What a decoy marker stands for, for people reading the evidence
pub fn decoy_label(marker: &str) -> String {
    let label = DECOYS.iter().find(|d| d.marker == marker).map(|d| d.label).or_else(|| ENV_DECOYS.iter().find(|d| d.marker == marker).map(|d| d.label));
    label.map_or_else(|| marker.to_string(), |label| label())
}

/// Formats of real secrets. If they show up in outgoing plain text (and aren't our decoys), the program is sending secrets out.
/// Evidence keeps only the kind, never the value (engineering rules: no API keys in logs or evidence).
/// The kind is a fixed English id because it is stored in check history; `secret_label` localizes it for display.
fn secret_patterns() -> &'static [(&'static str, regex::Regex)] {
    static PATTERNS: std::sync::OnceLock<Vec<(&'static str, regex::Regex)>> = std::sync::OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            ("OpenAI / Anthropic API key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
            ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
            ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
            ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
            ("private key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        ]
        .into_iter()
        .map(|(kind, re)| (kind, regex::Regex::new(re).expect("secret format regex")))
        .collect()
    })
}

/// A secret kind from `NetEvent::secrets` in the user's language. Unknown kinds (Chinese names in old records) are shown as they are.
pub fn secret_label(kind: &str) -> String {
    match kind {
        "OpenAI / Anthropic API key" => tr!("OpenAI / Anthropic API key"),
        "AWS access key" => tr!("AWS access key"),
        "GitHub token" => tr!("GitHub token"),
        "Google API key" => tr!("Google API key"),
        "Slack token" => tr!("Slack token"),
        "npm token" => tr!("npm token"),
        "private key" => tr!("private key"),
        other => other.to_string(),
    }
}

/// Joins labels with the list separator of the user's language
fn join_labels(labels: impl IntoIterator<Item = String>) -> String {
    labels.into_iter().collect::<Vec<_>>().join(&tr!(", "))
}

/// Checks outgoing data: which decoys (markers) it carries, and which kinds of real-looking secrets.
pub fn scan_outbound(text: &str) -> (Vec<String>, Vec<String>) {
    let leaked: Vec<String> = DECOYS.iter().map(|d| d.marker).chain(ENV_DECOYS.iter().map(|d| d.marker)).filter(|m| text.contains(m)).map(String::from).collect();
    // Remove our own decoy values first; only what remains counts as "other" secrets
    let mut rest = text.to_string();
    for d in ENV_DECOYS {
        rest = rest.replace(d.value, "");
    }
    let secrets: Vec<String> = secret_patterns().iter().filter(|(_, re)| re.is_match(&rest)).map(|(kind, _)| kind.to_string()).collect();
    (leaked, secrets)
}

/// Replaces secrets with "[kind redacted]" before they go into evidence. The result is stored, so it stays in English.
pub fn redact_secrets(text: &str) -> String {
    secret_patterns().iter().fold(text.to_string(), |acc, (kind, re)| re.replace_all(&acc, format!("[{kind} redacted]")).into_owned())
}

/// New files in these folders after a run are suspicious signs of persistence or a dropped payload
const WATCH_NEW: &[&str] = &["Library/LaunchAgents", ".node_modules", ".task", ".n2", ".npl", ".config/.node"];

fn write_decoys(home: &Path) -> std::io::Result<()> {
    for d in DECOYS {
        let p = home.join(d.rel);
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, d.body)?;
    }
    // Create these folders up front so "new files" can be compared afterwards
    for w in WATCH_NEW {
        let _ = std::fs::create_dir_all(home.join(w));
    }
    // A few fake shell history lines so the environment looks lived in
    std::fs::write(home.join(".zsh_history"), "ls\ncd ~/code\ngit status\nnpm install\n")?;
    Ok(())
}

/// PATH inside the sandbox: the real PATH + default locations of common version managers + system paths,
/// so node / npm installed under the home folder can be found.
///
/// An App launched from Finder or as a login item gets only /usr/bin:/bin:/usr/sbin:/sbin as PATH;
/// paths set up in ~/.zshrc (fnm, nvm) are missing. If node still isn't found in the fixed locations,
/// ask the user's login shell for its PATH once (the result is cached).
fn sandbox_path() -> String {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
        dirs.extend(manager_bin_dirs(&crate::home_dir()));
        dirs.extend(["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
        if !dirs.iter().any(|d| d.join("node").is_file())
            && let Some(p) = login_shell_path()
        {
            dirs.extend(std::env::split_paths(&p));
        }
        let mut seen = std::collections::HashSet::new();
        dirs.retain(|d| !d.as_os_str().is_empty() && seen.insert(d.clone()));
        std::env::join_paths(dirs).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
    })
    .clone()
}

/// Kills the process group we started ourselves with process_group(0) (the group id is the child's pid).
/// Only ever use it on such self-created groups. With pid 0 or 1, kill(-pid) would hit every process of the
/// current user, so those are refused first.
pub(crate) fn kill_own_group(child_pid: u32) {
    let Ok(pgid) = i32::try_from(child_pid) else { return };
    if pgid > 1 {
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
}

/// Default bin folders of fnm / volta / bun / asdf (only those that exist). nvm's default version needs alias
/// resolution, so that is left to the login shell.
fn manager_bin_dirs(home: &Path) -> Vec<PathBuf> {
    let mut fnm_roots: Vec<PathBuf> = std::env::var_os("FNM_DIR").map(PathBuf::from).into_iter().collect();
    fnm_roots.extend([home.join(".local/share/fnm"), home.join("Library/Application Support/fnm"), home.join(".fnm")]);
    fnm_roots
        .into_iter()
        .map(|r| r.join("aliases/default/bin"))
        .chain([".volta/bin", ".bun/bin", ".asdf/shims", ".local/bin"].map(|d| home.join(d)))
        .filter(|d| d.is_dir())
        .collect()
}

/// Prints PATH from the user's login + interactive shell (`fnm env` and the like usually live in .zshrc, hence -i).
/// rc files may print other things to stdout, so PATH is cut out between markers; give up after 3 seconds.
fn login_shell_path() -> Option<String> {
    const MARK: &str = "__TSUBA_PATH__";
    let shell = std::env::var("SHELL").ok().filter(|s| s.starts_with('/')).unwrap_or_else(|| "/bin/zsh".into());
    let mut child = Command::new(shell)
        .args(["-ilc", &format!("printf '{MARK}%s{MARK}' \"$PATH\"")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .ok()?;
    let start = Instant::now();
    while child.try_wait().ok()?.is_none() {
        if start.elapsed() > Duration::from_secs(3) {
            kill_own_group(child.id());
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    let (_, rest) = out.split_once(MARK)?;
    let (path, _) = rest.split_once(MARK)?;
    (!path.is_empty()).then(|| path.to_string())
}

/// node / python / package managers are often installed in these subfolders of the home folder. With the home folder
/// locked they must stay readable, or the sandbox can't even read node itself. They hold nothing sensitive like .ssh,
/// wallets or browser passwords.
const TOOL_SUBDIRS: &[&str] = &[
    ".local", ".nvm", ".fnm", ".volta", ".bun", ".cargo", ".npm-global", ".asdf", ".rbenv", ".pyenv", ".deno",
    "Library/pnpm", "Library/Application Support/fnm", "Library/Caches/fnm", ".yarn",
];

/// System tools a sandboxed program may not run directly: they ask the system to launch programs, send AppleEvents,
/// register background jobs, or read the keychain and clipboard, bypassing Seatbelt's file and network rules.
/// The system service rules below are a second door for the same thing.
const BLOCKED_TOOLS: &[&str] = &["/usr/bin/open", "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/security", "/usr/bin/pbcopy", "/usr/bin/pbpaste", "/usr/bin/sudo"];

/// System services (mach service names) sandboxed programs may not look up
const BLOCKED_SERVICES: &[&str] = &[
    // LaunchServices: opening an App or document starts it outside the sandbox
    "com.apple.coreservices.launchservicesd",
    // AppleEvents: making Finder, Terminal or System Events run commands for it
    "com.apple.coreservices.appleevents",
    // Clipboard: may hold a freshly copied password or seed phrase
    "com.apple.pasteboard.1",
    // DNS: with direct connections blocked, data can still leave encoded in domain lookups
    "com.apple.dnssd.service",
    // Keychain
    "com.apple.SecurityServer",
    "com.apple.securityd.xpc",
];

/// Escapes a path in Seatbelt string syntax
fn esc(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
}

/// The Seatbelt profile. The base is allow default (programs must read /usr and /System to run at all), tightened to least privilege on top.
///
/// Two pitfalls:
/// - Later rules override earlier ones, but a specific operation name beats a wildcard one: after deny file-read*,
///   a later allow file* doesn't override it, so allows must name file-read* / file-write* separately.
/// - Rules match the resolved real path (/private/var/folders/…), so jail paths must be canonicalized first.
///
/// Every deny carries this run's tag (ASCII only: it is a matching key, not text for people). When something is denied
/// the tag appears in the system log, and the denied operations are collected by it after the run.
fn profile(real_home: &Path, jail: &JailPaths, proxy_port: u16, tag: &str) -> String {
    let mark = format!("(with message \"{tag}\")");
    // Tool folders under the home folder are read-only: node / python installed there can run, but nothing can be written to the real home
    let tools: Vec<PathBuf> = TOOL_SUBDIRS.iter().map(|d| real_home.join(d)).filter(|p| p.exists()).collect();
    let tool_allows: String = tools.iter().map(|p| format!("(allow file-read* process-exec (subpath \"{}\"))\n", esc(p))).collect();
    // node lstats every parent folder when resolving real paths (/Users, /Users/xx, ~/.local …) and exits with EPERM if denied.
    // Allow only the metadata of those folders themselves: no listing, no reading. Same for the jail's parents (getcwd needs them).
    let mut parents: Vec<PathBuf> = tools.iter().flat_map(|p| p.ancestors().skip(1).take_while(|a| a.starts_with(real_home)).map(Path::to_path_buf).collect::<Vec<_>>()).collect();
    parents.extend(real_home.parent().map(Path::to_path_buf));
    parents.extend(jail.root.ancestors().map(Path::to_path_buf));
    parents.sort();
    parents.dedup();
    let metadata: String = parents.iter().map(|p| format!("(literal \"{}\")", esc(p))).collect::<Vec<_>>().join(" ");
    let tools_exec: String = BLOCKED_TOOLS.iter().map(|t| format!("(literal \"{t}\")")).collect::<Vec<_>>().join(" ");
    let services: String = BLOCKED_SERVICES.iter().map(|s| format!("(global-name \"{s}\")")).collect::<Vec<_>>().join(" ");
    format!(
        r#"(version 1)
(allow default)
; Writes: nowhere except the fake home and work folders (not /opt/homebrew/bin, /Applications, external drives, /tmp)
(deny file-write* (subpath "/") {mark})
; Reads: external drives, all user folders and the shared temp folders are hidden
(deny file-read* (subpath "/Volumes") (subpath "/Users") (subpath "/private/tmp") (subpath "/private/var/folders") {mark})
; The real home folder is fully locked: no real private keys, wallets or passwords (holds even when home is not under /Users)
(deny file* (subpath "{real}") {mark})
; Every program reads the real user's text encoding setting once; harmless, allowed so it doesn't flood the log
(allow file-read* (literal "{real}/.CFUserTextEncoding"))
; Tool folders: read-only, executable
{tools}(allow file-read-metadata {metadata})
; Fake home and work folders are readable and writable; the profile in the jail root stays invisible
(allow file-read* file-write* (subpath "{fake}") (subpath "{work}"))
(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper") (regex #"^/dev/fd/") (regex #"^/dev/tty"))
; Processes: no tools that make the system act on its behalf; signals and process info only within this sandbox
(deny process-exec {tools_exec} {mark})
(deny signal {mark})
(allow signal (target same-sandbox))
(deny process-info* {mark})
(allow process-info* (target same-sandbox))
; System services: LaunchServices, AppleEvents, clipboard, DNS, keychain, and preferences
(deny mach-lookup {services} (global-name-prefix "com.apple.lsd.") {mark})
(deny appleevent-send {mark})
(deny user-preference-write {mark})
(deny user-preference-read {mark})
; Network: denied by default; only the local recording proxy is allowed
(deny network* {mark})
(allow network-outbound (remote ip "localhost:{port}"))
(allow network-bind (local ip "localhost:*"))
"#,
        real = esc(real_home),
        tools = tool_allows,
        fake = esc(&jail.fake_home),
        work = esc(&jail.work),
        port = proxy_port,
    )
}

/// The only addresses really let through when trying an install: the official npm registry (HTTPS CONNECT only).
const REGISTRY_HOSTS: &[&str] = &["registry.npmjs.org:443", "registry.yarnpkg.com:443"];

/// A minimal recording proxy: acts as an HTTP proxy, records each request's target and content, scans for decoy markers,
/// then answers with an empty 200. Requests are never forwarded, so sandboxed programs can't reach a real attacker server.
/// With forward_registry, CONNECTs to the official npm registry are really connected; everything else is still only recorded.
const MAX_PROXY_CONNECTIONS: usize = 32;
/// Cap on recorded network requests; enough to see the behaviour
const MAX_NET_EVENTS: usize = 300;

type ProxyHandle = (u16, Arc<Mutex<Vec<NetEvent>>>, mpsc::Sender<()>);

fn start_proxy(forward_registry: bool) -> std::io::Result<ProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let ev = events.clone();
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                // Concurrent connections are capped: thousands of connections in the sandbox don't become thousands of threads on the host
                Ok((stream, _)) if active.load(Ordering::SeqCst) >= MAX_PROXY_CONNECTIONS => drop(stream),
                Ok((stream, _)) => {
                    let (ev, active) = (ev.clone(), active.clone());
                    active.fetch_add(1, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        handle_proxy_conn(stream, ev, forward_registry);
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Ok((port, events, stop_tx))
}

fn handle_proxy_conn(mut stream: TcpStream, events: Arc<Mutex<Vec<NetEvent>>>, forward_registry: bool) {
    // On macOS an accepted connection inherits the listener's non-blocking mode, so reads and writes would return WouldBlock
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = vec![0u8; 16384];
    let mut data = Vec::new();
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 256 * 1024 {
            break;
        }
        // Once the headers are in, read the body by Content-Length too: exfiltrated data is usually in a POST body
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            let body_len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
            if data.len() >= end + 4 + body_len.min(256 * 1024) {
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&data);
    let first = text.lines().next().unwrap_or("").to_string();
    let mut target = String::new();
    let mut request = String::new();
    if let Some(rest) = first.strip_prefix("CONNECT ") {
        // CONNECT host:443 HTTP/1.1: HTTPS, only the target is visible
        target = rest.split_whitespace().next().unwrap_or("").to_string();
        if forward_registry && REGISTRY_HOSTS.contains(&target.to_lowercase().as_str()) {
            // Record on connect rather than when the tunnel closes: npm keeps connections alive, so the tunnel may still be open at the end
            let upstream = connect_upstream(&target);
            events.lock().unwrap().push(NetEvent { target, request, leaked: vec![], secrets: vec![], forwarded: upstream.is_some() });
            match upstream {
                Some(u) => tunnel(stream, u),
                None => {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                }
            }
            return;
        }
        let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    } else if let Some((method, rest)) = first.split_once(' ') {
        // GET http://host/path HTTP/1.1: plain text, the whole request is visible
        let url = rest.split_whitespace().next().unwrap_or("");
        target = url.strip_prefix("http://").and_then(|u| u.split('/').next()).unwrap_or(url).to_string();
        request = redact_secrets(&format!("{method} {url}"));
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    let (leaked, secrets) = scan_outbound(&text);
    let mut events = events.lock().unwrap();
    if (!target.is_empty() || !leaked.is_empty()) && events.len() < MAX_NET_EVENTS {
        events.push(NetEvent { target, request, leaked, secrets, forwarded: false });
    }
}

fn connect_upstream(target: &str) -> Option<TcpStream> {
    use std::net::ToSocketAddrs;
    let addr = target.to_socket_addrs().ok()?.next()?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(10)).ok()
}

/// Connects the client to upstream and relays both ways until either side closes. Only used for the official npm registry.
fn tunnel(mut client: TcpStream, mut upstream: TcpStream) {
    let _ = client.set_read_timeout(None);
    if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return;
    }
    let (Ok(mut c2), Ok(mut u2)) = (client.try_clone(), upstream.try_clone()) else { return };
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut upstream);
        let _ = upstream.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut u2, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

/// Compares the fake home folder after the run and lists the new files.
fn new_files(home: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for w in WATCH_NEW {
        let dir = home.join(w);
        for p in crate::walk_files(&dir, 200) {
            if let Ok(rel) = p.strip_prefix(home) {
                out.push(rel.to_string_lossy().to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The jail's folders (all resolved real paths, since Seatbelt matches real paths)
struct JailPaths {
    root: PathBuf,
    fake_home: PathBuf,
    work: PathBuf,
}

/// A prepared sandbox: folders + decoys, the recording proxy, the profile, and this run's random tag.
struct Jail {
    _dir: tempfile::TempDir,
    paths: JailPaths,
    profile: PathBuf,
    proxy_url: String,
    events: Arc<Mutex<Vec<NetEvent>>>,
    stop_tx: mpsc::Sender<()>,
    /// Written into every deny rule; this run's denials are found in the system log by it
    tag: String,
}

/// A random hex string. Only tells runs apart, so it needs no cryptographic strength.
fn random_hex() -> String {
    use std::hash::{BuildHasher, RandomState};
    let state = RandomState::new();
    format!("{:016X}{:016X}", state.hash_one(Instant::now()), state.hash_one(std::process::id()))
}

fn prepare_jail(forward_registry: bool) -> std::io::Result<Jail> {
    let real_home = crate::home_dir();
    let dir = tempfile::Builder::new().prefix("tsuba-sandbox-").tempdir()?;
    let root = std::fs::canonicalize(dir.path())?;
    let paths = JailPaths { fake_home: root.join("home"), work: root.join("work"), root };
    std::fs::create_dir_all(&paths.fake_home)?;
    std::fs::create_dir_all(&paths.work)?;
    write_decoys(&paths.fake_home)?;
    let (port, events, stop_tx) = start_proxy(forward_registry)?;
    let tag = format!("tsuba-{}", random_hex());
    // The profile lives in the jail root: the sandbox can only use home and work, so it can't see the profile or the tag
    let profile = paths.root.join("profile.sb");
    std::fs::write(&profile, self::profile(&real_home, &paths, port, &tag))?;
    Ok(Jail { _dir: dir, paths, profile, proxy_url: format!("http://127.0.0.1:{port}"), events, stop_tx, tag })
}

/// Resource limits: 1 GiB per file, CPU time per process, and the user's process count (256 more than now).
/// The process limit counts all of the user's processes, so it can't be a small fixed number, or nothing would start
/// once the user has a few more programs open.
struct Limits {
    file_size: libc::rlim_t,
    cpu_seconds: libc::rlim_t,
    processes: Option<libc::rlim_t>,
}

impl Limits {
    fn for_timeout(timeout: Duration) -> Limits {
        let own = own_process_count().map(|n| (n + 256) as libc::rlim_t);
        Limits { file_size: 1 << 30, cpu_seconds: timeout.as_secs() as libc::rlim_t * 2 + 30, processes: own }
    }

    /// Called after fork and before exec: only setrlimit, to stay async-signal-safe
    fn apply(&self) -> std::io::Result<()> {
        let set = |resource, value: libc::rlim_t| {
            let lim = libc::rlimit { rlim_cur: value, rlim_max: value };
            if unsafe { libc::setrlimit(resource, &lim) } != 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
        };
        set(libc::RLIMIT_FSIZE, self.file_size)?;
        set(libc::RLIMIT_CPU, self.cpu_seconds)?;
        if let Some(n) = self.processes {
            set(libc::RLIMIT_NPROC, n)?;
        }
        Ok(())
    }
}

fn own_process_count() -> Option<usize> {
    let out = Command::new("/bin/ps").args(["-x", "-o", "pid="]).output().ok()?;
    out.status.success().then(|| out.stdout.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count())
}

/// Runs a command (argv[0] is the program) in a prepared jail with a time limit, reaps it, and collects its behaviour.
fn exec_jailed(jail: &Jail, argv: &[String], cwd: &Path, timeout: Duration) -> std::io::Result<Behavior> {
    let limits = Limits::for_timeout(timeout);
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-f")
        .arg(&jail.profile)
        .args(argv)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", &jail.paths.fake_home)
        // The completed PATH, so node / npm (often under the home folder, read-only in the profile) can be found
        .env("PATH", sandbox_path())
        .env("TMPDIR", &jail.paths.work)
        .env("USER", "user")
        .env("HTTP_PROXY", &jail.proxy_url)
        .env("HTTPS_PROXY", &jail.proxy_url)
        .env("ALL_PROXY", &jail.proxy_url)
        .env("http_proxy", &jail.proxy_url)
        .env("https_proxy", &jail.proxy_url)
        .env("npm_config_proxy", &jail.proxy_url)
        .env("npm_config_https_proxy", &jail.proxy_url)
        .envs(ENV_DECOYS.iter().map(|d| (d.name, d.value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own process group, so every child it starts can be killed together at the end
        .process_group(0);
    unsafe { command.pre_exec(move || limits.apply()) };
    let mut child = command.spawn()?;

    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });

    let start = Instant::now();
    let mut timed_out = false;
    let exit_code = loop {
        match child.try_wait()? {
            Some(status) => break status.code(),
            None if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(50)),
            None => {
                timed_out = true;
                break None;
            }
        }
    };
    let seconds = start.elapsed().as_secs_f64();
    // Kill the whole process group whether or not it timed out: after the main process exits, children it put in the
    // background keep running and hold the output pipes open, so reading the output below would never finish
    kill_own_group(child.id());
    let _ = child.wait();
    // Only this run's own process group is killed. Never scan all processes to chase "escaped" ones: one misidentification
    // kills the user's own programs (it really happened: Slack, VS Code, Docker and several system services were killed).
    std::thread::sleep(Duration::from_millis(100));
    let _ = jail.stop_tx.send(());

    let mut output = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    output.push_str(&String::from_utf8_lossy(&t_err.join().unwrap_or_default()));
    let output: String = output.chars().take(4000).collect();
    let network = jail.events.lock().unwrap().clone();
    let new_files = new_files(&jail.paths.fake_home);
    let denied = read_denials(&jail.tag, seconds);

    Ok(Behavior { exit_code, timed_out, seconds, network, new_files, output, denied })
}


/// Reads this run's denied operations from the system log. The log may land a little late, so wait briefly first.
/// Denied system services such as the clipboard or DNS aren't always logged, so this only adds evidence; the rules apply regardless.
fn read_denials(tag: &str, seconds: f64) -> Vec<Denied> {
    std::thread::sleep(Duration::from_millis(300));
    let window = format!("{}s", seconds.ceil() as u64 + 10);
    let predicate = format!("sender == \"Sandbox\" AND eventMessage CONTAINS \"{tag}\"");
    let Ok(out) = Command::new("/usr/bin/log").args(["show", "--last", &window, "--style", "compact", "--predicate", &predicate]).output() else {
        return vec![];
    };
    let mut denied = Vec::new();
    for d in String::from_utf8_lossy(&out.stdout).lines().filter_map(parse_denial) {
        if !denied.contains(&d) && denied.len() < 100 {
            denied.push(d);
        }
    }
    denied
}

/// Parses one kernel log line: `Sandbox: touch(97285) deny(1) file-write-create /opt/homebrew/bin/x`
fn parse_denial(line: &str) -> Option<Denied> {
    let rest = &line[line.find("Sandbox: ")? + "Sandbox: ".len()..];
    let (process, rest) = rest.split_once('(')?;
    let rest = &rest[rest.find(" deny(")? + 1..];
    let mut parts = rest.splitn(3, ' ');
    parts.next()?;
    let operation = parts.next()?.to_string();
    let target = parts.next().unwrap_or("").trim().to_string();
    // Programs routinely look up global preferences; that's not an overreach
    if target == "kcfpreferencesanyapplication" {
        return None;
    }
    Some(Denied { process: process.to_string(), operation, target })
}

/// Runs a script in the sandbox. `interpreter` is usually "/bin/bash". No real address is ever contacted.
pub fn run_script(script: &str, interpreter: &str, timeout: Duration) -> std::io::Result<Behavior> {
    let jail = prepare_jail(false)?;
    let script_path = jail.paths.work.join("script.sh");
    std::fs::write(&script_path, script)?;
    let argv = vec![interpreter.to_string(), script_path.to_string_lossy().into_owned()];
    exec_jailed(&jail, &argv, &jail.paths.work.clone(), timeout)
}

/// Runs a project's start command in the sandbox (e.g. npm start, node server.js).
///
/// The project is copied into the jail and run there, which exposes interview projects whose malicious code runs on
/// open or start: reading decoy wallets and keys, writing to hidden folders or login items, sending data out.
/// ditto does copy-on-write on APFS, so it costs almost no disk space; .git is skipped.
/// Note: raw sockets straight to a C2 are blocked by the system (no content visible, but the attacker isn't reached either);
/// exfiltrated content is visible only for clients that use the HTTP proxy.
pub fn run_project(project_dir: &Path, argv: &[String], timeout: Duration) -> std::io::Result<Behavior> {
    run_in_copy(project_dir, argv, timeout, false)
}

/// Tries installing a project's dependencies (npm install) in the sandbox so their preinstall / postinstall scripts really run.
/// Poisoned packages mostly strike in install scripts: reading keys, writing to hidden folders, sending data out.
/// Only downloads from the official npm registry are let through; other addresses install scripts contact are recorded and blocked.
pub fn run_install(project_dir: &Path, timeout: Duration) -> std::io::Result<Behavior> {
    run_in_copy(project_dir, &install_argv(), timeout, true)
}

pub fn install_argv() -> Vec<String> {
    ["npm", "install", "--no-audit", "--no-fund", "--foreground-scripts"].map(String::from).to_vec()
}

fn run_in_copy(project_dir: &Path, argv: &[String], timeout: Duration, forward_registry: bool) -> std::io::Result<Behavior> {
    let jail = prepare_jail(forward_registry)?;
    let dest = jail.paths.work.join("project");
    // ditto keeps the structure and uses APFS clonefile; faster than cp -R and saves disk space
    let status = Command::new("/usr/bin/ditto").arg(project_dir).arg(&dest).arg("--norsrc").status();
    if !matches!(status, Ok(s) if s.success()) {
        // Without ditto, fall back to a plain recursive copy
        copy_dir(project_dir, &dest)?;
    }
    let _ = std::fs::remove_dir_all(dest.join(".git"));
    exec_jailed(&jail, argv, &dest, timeout)
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)?.flatten() {
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        match entry.file_type()? {
            t if t.is_dir() => copy_dir(&src, &dst)?,
            t if t.is_file() => {
                std::fs::copy(&src, &dst)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Turns observed behaviour into evidence. Judged by behaviour, but going online, downloading and writing files are
/// normal for install scripts and don't count as bad on their own.
pub fn findings(b: &Behavior) -> Vec<Finding> {
    let mut out = Vec::new();
    let loc = tr!("Sandbox run");

    for ev in &b.network {
        if !ev.leaked.is_empty() {
            let decoys = join_labels(ev.leaked.iter().map(|m| decoy_label(m)));
            out.push(Finding::new(
                Severity::High,
                tr!("The program sent decoy secrets ({decoys}) to {target}. Tsuba planted these fakes, so this is proof it steals data", decoys = decoys, target = ev.target),
                &loc,
            ));
        }
        if !ev.secrets.is_empty() {
            let kinds = join_labels(ev.secrets.iter().map(|k| secret_label(k)));
            out.push(Finding::new(Severity::High, tr!("A plain-text request to {target} appears to contain secrets ({kinds}); the program may be sending them out", target = ev.target, kinds = kinds), &loc));
        }
    }
    // Connecting to a bare IP is evidence for the layer above (normal install scripts usually use domain names)
    for ev in &b.network {
        let host = ev.target.split(':').next().unwrap_or("");
        if crate::net::is_ip(host) && !host.starts_with("127.") {
            out.push(Finding::new(Severity::Medium, tr!("The program connected straight to the IP address {target} while running", target = ev.target), &loc));
        }
    }
    for f in &b.new_files {
        if f.starts_with("Library/LaunchAgents") {
            out.push(Finding::new(Severity::High, tr!("The program wrote {file}, a launch agent that starts at login, to keep running after a restart", file = f), &loc));
        } else if f.contains(".node_modules") || f.starts_with(".task") || f.contains(".config/.node") {
            out.push(Finding::new(Severity::High, tr!("The program wrote {file} into a hidden folder, a common hiding place for attackers", file = f), &loc));
        }
    }
    for d in &b.denied {
        if let Some((severity, message)) = classify_denial(d) {
            out.push(Finding::new(severity, message, &loc));
        }
    }
    out
}

/// These places in the real home folder hold private keys, cloud credentials, wallets and browser passwords. A program that
/// ignores $HOME and reads them by their real path is going after the user's real data.
const SENSITIVE_HOME_PATHS: &[&str] = &[
    "/.ssh/", "/.aws/", "/.gnupg/", "/.kube/", "/.docker/config.json", "/.netrc", "/.config/solana/",
    "/Library/Keychains/", "/Library/Application Support/Google/Chrome/", "/Library/Application Support/BraveSoftware/",
    "/Library/Application Support/Firefox/", "/Library/Application Support/Exodus/", "/Library/Cookies/",
];

/// Turns one denied operation into evidence. Things normal install scripts also do (installing a command in /usr/local/bin,
/// opening a browser, connecting straight to 443) are only evidence for the AI, never a verdict on their own; only clear
/// malicious signals are high risk.
fn classify_denial(d: &Denied) -> Option<(Severity, String)> {
    let (op, target, who) = (d.operation.as_str(), d.target.as_str(), d.process.as_str());
    let persistence = target.contains("/LaunchAgents/") || target.contains("/LaunchDaemons/") || target.ends_with("/LaunchAgents") || target.contains("/Library/StartupItems");
    if op.starts_with("file-write") && persistence {
        return Some((Severity::High, tr!("{process} tried to add a launch agent at {target} outside the sandbox, so it would start at login. The sandbox blocked it.", process = who, target = target)));
    }
    if op.starts_with("file-write") && ["/opt/homebrew/", "/usr/local/", "/Applications/"].iter().any(|p| target.starts_with(p)) {
        // Normal install scripts often put commands in /usr/local/bin too, so this is only evidence for the AI and takes no part in the verdict
        return Some((Severity::Low, tr!("{process} tried to write {target} outside the sandbox, where commands and apps are installed. The sandbox blocked it.", process = who, target = target)));
    }
    // ssh and git look up ~/.ssh by the real user anyway; that doesn't count
    if op.starts_with("file-read") && !matches!(who, "ssh" | "git" | "git-remote-https") && target.starts_with("/Users/") && SENSITIVE_HOME_PATHS.iter().any(|p| target.contains(p)) {
        return Some((Severity::High, tr!("{process} bypassed the fake home folder and tried to read the real {target}. The sandbox blocked it.", process = who, target = target)));
    }
    if op.starts_with("process-exec") {
        return match target {
            "/usr/bin/security" => Some((Severity::High, tr!("{process} tried to run security to read the keychain. The sandbox blocked it.", process = who))),
            "/usr/bin/osascript" => Some((Severity::Medium, tr!("{process} tried to run osascript (fake system password prompts are a common trick of macOS stealers). The sandbox blocked it.", process = who))),
            "/bin/launchctl" => Some((Severity::Medium, tr!("{process} tried to register a background job with launchctl. The sandbox blocked it.", process = who))),
            "/usr/bin/pbpaste" | "/usr/bin/pbcopy" => Some((Severity::Medium, tr!("{process} tried to read or write the clipboard. The sandbox blocked it.", process = who))),
            _ => None,
        };
    }
    if op == "user-preference-write" {
        return Some((Severity::Medium, tr!("{process} tried to change the settings of {target}. The sandbox blocked it.", process = who, target = target)));
    }
    // Bypassing the proxy: many normal programs do it on 443 / 80 (HTTP clients that ignore proxies), so only unusual ports count
    if op == "network-outbound" {
        let port = target.rsplit(':').next().unwrap_or("");
        if !port.is_empty() && !matches!(port, "80" | "443" | "53") && port.chars().all(|c| c.is_ascii_digit()) {
            return Some((Severity::Medium, tr!("{process} bypassed the proxy to connect straight to port {port}. The sandbox blocked it (trojan control servers often use unusual ports).", process = who, port = port)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_denial_lines() {
        let d = parse_denial("2026-10-28 06:42:46.282 E  kernel[0:1a96468] (Sandbox) Sandbox: touch(97102) deny(1) file-write-create /opt/homebrew/bin/x").unwrap();
        assert_eq!(d, Denied { process: "touch".into(), operation: "file-write-create".into(), target: "/opt/homebrew/bin/x".into() });
        let d = parse_denial("Sandbox: node(1) deny(1) file-read-data /Users/a/Library/Application Support/Google/Chrome/Default/Login Data").unwrap();
        assert_eq!(d.target, "/Users/a/Library/Application Support/Google/Chrome/Default/Login Data", "spaces in the path must be kept");
        assert_eq!(parse_denial("Sandbox: curl(1) deny(1) network-outbound remote:*:1224").unwrap().target, "remote:*:1224");
        assert!(parse_denial("Sandbox: curl(1) deny(1) user-preference-read kcfpreferencesanyapplication").is_none(), "looking up global preferences is noise");
        assert!(parse_denial("log run noninteractively").is_none());
    }

    #[test]
    fn profile_blocks_escape_routes() {
        let p = _profile_for_test();
        for must in [
            "(deny file-write* (subpath \"/\")",
            "(subpath \"/Volumes\")",
            "(literal \"/usr/bin/osascript\")",
            "com.apple.coreservices.launchservicesd",
            "com.apple.dnssd.service",
            "com.apple.pasteboard.1",
            "(deny user-preference-write",
            "(allow signal (target same-sandbox))",
            "(with message \"tag\")",
        ] {
            assert!(p.contains(must), "profile is missing {must}:\n{p}");
        }
        // The jail root (where the profile lives) is not readable, only home and work
        assert!(p.contains("(subpath \"/tmp/jail/home\") (subpath \"/tmp/jail/work\")") && !p.contains("(subpath \"/tmp/jail\")"));
    }
}

/// A project's start command: `npm start` when there is a package.json, otherwise a guess from common entry points.
pub fn project_start_argv(dir: &Path) -> Vec<String> {
    if dir.join("package.json").is_file() {
        return vec!["npm".into(), "start".into()];
    }
    for entry in ["index.js", "server.js", "main.js", "app.js"] {
        if dir.join(entry).is_file() {
            return vec!["node".into(), entry.into()];
        }
    }
    vec!["npm".into(), "start".into()]
}

/// Runs a project's start command in the sandbox and returns the evidence and findings.
pub fn analyze_project(dir: &Path, timeout: Duration) -> (Value, Vec<Finding>) {
    let argv = project_start_argv(dir);
    match run_project(dir, &argv, timeout) {
        Ok(b) => {
            let f = findings(&b);
            (json!({ "sandbox": b, "sandbox_command": argv.join(" ") }), f)
        }
        Err(e) => (json!({ "sandbox_error": e.to_string() }), vec![]),
    }
}

/// The full result of one sandbox run: behaviour + findings, ready to go into the evidence for the model.
pub fn analyze_script(script: &str, timeout: Duration) -> (Value, Vec<Finding>) {
    match run_script(script, "/bin/bash", timeout) {
        Ok(b) => {
            let f = findings(&b);
            (json!({ "sandbox": b }), f)
        }
        Err(e) => (json!({ "sandbox_error": e.to_string() }), vec![]),
    }
}
