//! 动态分析：把拿不准的脚本放进 macOS 自带的沙箱（Seatbelt / sandbox-exec）里跑一小会儿，
//! 看它实际做了什么，而不是逐行读代码。
//!
//! 沙箱做三件事：
//! 1. 把真实的家目录整个锁死，程序读不到用户真正的 SSH 私钥、钱包、浏览器密码。
//! 2. 给程序一个假的家目录，里面放诱饵文件（每份带一个唯一标记）。程序碰了诱饵就暴露意图。
//! 3. 只允许程序连本机的一个记录代理，所有网络请求都被看见；想直连外网会被系统挡住。
//!
//! 运行有时间上限，结束后把它启动的所有子进程一起杀掉，临时目录整个删除。
//!
//! 局限：
//! - 跑一分钟没看到坏行为，不代表安全（有的程序会拖延发作、或等用户输密码）。结论只说“这次看到了什么”。
//! - 苹果已不推荐 sandbox-exec 接口，未来可能需要换成虚拟机方案。这里把它包在一个模块里，方便替换。
//! - 第一阶段的代理只能看明文 HTTP；HTTPS 只能看到连了哪个域名，看不到内容（留待后续做证书拦截）。

use crate::rules::{Finding, Severity};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 仅供测试：生成一份样例规则，确认真实家目录被锁死、网络被限制。
pub fn _profile_for_test() -> String {
    profile(Path::new("/Users/someone"), Path::new("/tmp/fake"), Path::new("/tmp/work"), 12345)
}

pub fn available() -> bool {
    Path::new("/usr/bin/sandbox-exec").is_file()
}

/// 代理看到的一次网络请求
#[derive(Clone, Debug, Serialize)]
pub struct NetEvent {
    /// 连接的目标：HTTP 是 host[:port]，HTTPS CONNECT 是 host:443
    pub target: String,
    /// 明文请求时能看到的方法和路径（HTTPS 看不到）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request: String,
    /// 命中的诱饵标记（说明程序把诱饵数据发了出去）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaked: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Behavior {
    /// 程序是否正常结束、退出码、是否超时被杀
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub seconds: f64,
    /// 代理记录的网络请求
    pub network: Vec<NetEvent>,
    /// 运行后假家目录里新出现的文件（相对假家目录）
    pub new_files: Vec<String>,
    /// stdout / stderr 的开头
    pub output: String,
}

/// 诱饵：假家目录里的一个文件，内容带唯一标记。程序读了并外传，标记就会出现在网络请求里。
struct Decoy {
    rel: &'static str,
    marker: &'static str,
    body: &'static str,
}

const DECOYS: &[Decoy] = &[
    Decoy { rel: ".ssh/id_ed25519", marker: "TSUBA-DECOY-SSH", body: "-----BEGIN OPENSSH PRIVATE KEY-----\nTSUBA-DECOY-SSH not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n" },
    Decoy { rel: ".aws/credentials", marker: "TSUBA-DECOY-AWS", body: "[default]\naws_access_key_id = TSUBA-DECOY-AWS\naws_secret_access_key = not-a-real-secret\n" },
    Decoy { rel: ".config/solana/id.json", marker: "TSUBA-DECOY-SOLANA", body: "[\"TSUBA-DECOY-SOLANA\", 0, 0]\n" },
    // 浏览器密码库和钱包扩展数据的占位
    Decoy { rel: "Library/Application Support/Google/Chrome/Default/Login Data", marker: "TSUBA-DECOY-CHROME", body: "SQLite format 3\x00 TSUBA-DECOY-CHROME\n" },
    Decoy { rel: "Library/Application Support/Exodus/exodus.wallet/seed.seco", marker: "TSUBA-DECOY-WALLET", body: "TSUBA-DECOY-WALLET not-a-real-wallet\n" },
];

/// 运行后这些目录里出现新文件就是可疑的持久化 / 落地痕迹
const WATCH_NEW: &[&str] = &["Library/LaunchAgents", ".node_modules", ".task", ".n2", ".npl", ".config/.node"];

fn write_decoys(home: &Path) -> std::io::Result<()> {
    for d in DECOYS {
        let p = home.join(d.rel);
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, d.body)?;
    }
    // 预建这些目录，方便之后对比“新出现的文件”
    for w in WATCH_NEW {
        let _ = std::fs::create_dir_all(home.join(w));
    }
    // 几条假的 shell 历史，让环境看起来像有人在用
    std::fs::write(home.join(".zsh_history"), "ls\ncd ~/code\ngit status\nnpm install\n")?;
    Ok(())
}

/// 沙箱里的 PATH：在固定系统路径前面加上真实 PATH，让装在家目录的 node / npm 能被找到。
fn sandbox_path() -> String {
    let base = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin";
    match std::env::var("PATH") {
        Ok(p) if !p.is_empty() => format!("{p}:{base}"),
        _ => base.to_string(),
    }
}

/// node / python / 包管理器常装在家目录下的这些子目录里。锁死家目录时要放行它们的只读，
/// 否则沙箱里连 node 本身都读不到。这些目录里没有 .ssh、钱包、浏览器密码这类敏感文件。
const TOOL_SUBDIRS: &[&str] = &[
    ".local", ".nvm", ".fnm", ".volta", ".bun", ".cargo", ".npm-global", ".asdf", ".rbenv", ".pyenv", ".deno",
    "Library/pnpm", "Library/Application Support/fnm", "Library/Caches/fnm", ".yarn",
];

/// Seatbelt 规则：允许大部分操作（程序要能读 /usr、/bin 才能跑），但锁死真实家目录、限制网络。
fn profile(real_home: &Path, fake_home: &Path, work: &Path, proxy_port: u16) -> String {
    let esc = |p: &Path| p.to_string_lossy().replace('"', "\\\"");
    // 工具目录只读放行：让 node 等能被执行，但程序不能往真实家目录写东西
    let tool_allows: String = TOOL_SUBDIRS
        .iter()
        .map(|d| real_home.join(d))
        .filter(|p| p.exists())
        .map(|p| format!("(allow file-read* process-exec (subpath \"{}\"))\n", esc(&p)))
        .collect();
    format!(
        r#"(version 1)
(allow default)
; 真实家目录整个锁死：读不到用户真正的私钥、钱包、密码
(deny file* (subpath "{real}"))
; 但放行工具目录的只读，否则装在家目录里的 node / python 跑不起来
{tools}; 假家目录和临时工作目录可读可写
(allow file* (subpath "{fake}"))
(allow file* (subpath "{work}"))
; 网络：默认禁止，只放行到本机的记录代理
(deny network*)
(allow network-outbound (remote ip "localhost:{port}"))
(allow network-bind (local ip "localhost:*"))
"#,
        real = esc(real_home),
        tools = tool_allows,
        fake = esc(fake_home),
        work = esc(work),
        port = proxy_port,
    )
}

/// 极简记录代理：扮演 HTTP 代理，把每个请求的目标和内容记下来，扫描诱饵标记，然后返回一个空的 200。
/// 不把请求真正转发出去，所以沙箱里的程序连不上真实的攻击服务器。
type ProxyHandle = (u16, Arc<Mutex<Vec<NetEvent>>>, mpsc::Sender<()>);

fn start_proxy() -> std::io::Result<ProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let ev = events.clone();
    std::thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let ev = ev.clone();
                    std::thread::spawn(move || handle_proxy_conn(stream, ev));
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

fn handle_proxy_conn(mut stream: TcpStream, events: Arc<Mutex<Vec<NetEvent>>>) {
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
        // 读到请求头结束就够了（明文 HTTP）；CONNECT 只有一行
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&data);
    let first = text.lines().next().unwrap_or("").to_string();
    let mut target = String::new();
    let mut request = String::new();
    if let Some(rest) = first.strip_prefix("CONNECT ") {
        // CONNECT host:443 HTTP/1.1 —— HTTPS，只能看到目标
        target = rest.split_whitespace().next().unwrap_or("").to_string();
        let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    } else if let Some((method, rest)) = first.split_once(' ') {
        // GET http://host/path HTTP/1.1 —— 明文，能看到完整请求
        let url = rest.split_whitespace().next().unwrap_or("");
        target = url.strip_prefix("http://").and_then(|u| u.split('/').next()).unwrap_or(url).to_string();
        request = format!("{method} {url}");
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    let leaked: Vec<String> = DECOYS.iter().filter(|d| text.contains(d.marker)).map(|d| d.marker.to_string()).collect();
    if !target.is_empty() || !leaked.is_empty() {
        events.lock().unwrap().push(NetEvent { target, request, leaked });
    }
}

/// 运行后对比假家目录，列出新出现的文件。
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
    // 工作目录（脚本被放这里运行）里新下载的可执行文件
    out.sort();
    out.dedup();
    out
}

/// 准备好沙箱：假家目录 + 诱饵、工作目录、记录代理、规则文件。返回牢笼和各路径。
struct Jail {
    _dir: tempfile::TempDir,
    fake_home: PathBuf,
    work: PathBuf,
    profile: PathBuf,
    proxy_url: String,
    events: Arc<Mutex<Vec<NetEvent>>>,
    stop_tx: mpsc::Sender<()>,
}

fn prepare_jail() -> std::io::Result<Jail> {
    let real_home = crate::home_dir();
    let dir = tempfile::Builder::new().prefix("tsuba-sandbox-").tempdir()?;
    let fake_home = dir.path().join("home");
    let work = dir.path().join("work");
    std::fs::create_dir_all(&fake_home)?;
    std::fs::create_dir_all(&work)?;
    write_decoys(&fake_home)?;
    let (port, events, stop_tx) = start_proxy()?;
    let profile = dir.path().join("profile.sb");
    std::fs::write(&profile, self::profile(&real_home, &fake_home, &work, port))?;
    Ok(Jail { _dir: dir, fake_home, work, profile, proxy_url: format!("http://127.0.0.1:{port}"), events, stop_tx })
}

/// 在准备好的牢笼里运行一条命令（argv 的第一个是程序），限时、收尸、收集行为。
fn exec_jailed(jail: &Jail, argv: &[String], cwd: &Path, timeout: Duration) -> std::io::Result<Behavior> {
    let mut child = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&jail.profile)
        .args(argv)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", &jail.fake_home)
        // 继承真实 PATH，node / npm（常装在家目录，已在规则里放行只读）才能被找到
        .env("PATH", sandbox_path())
        .env("TMPDIR", &jail.work)
        .env("USER", "user")
        .env("HTTP_PROXY", &jail.proxy_url)
        .env("HTTPS_PROXY", &jail.proxy_url)
        .env("ALL_PROXY", &jail.proxy_url)
        .env("http_proxy", &jail.proxy_url)
        .env("https_proxy", &jail.proxy_url)
        .env("npm_config_proxy", &jail.proxy_url)
        .env("npm_config_https_proxy", &jail.proxy_url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // 单独的进程组，超时时能把它启动的所有子进程一起杀掉
        .process_group(0)
        .spawn()?;
    let pgid = child.id() as i32;

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
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                let _ = child.wait();
                break None;
            }
        }
    };
    let seconds = start.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_millis(100));
    let _ = jail.stop_tx.send(());

    let mut output = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    output.push_str(&String::from_utf8_lossy(&t_err.join().unwrap_or_default()));
    let output: String = output.chars().take(4000).collect();
    let network = jail.events.lock().unwrap().clone();
    let new_files = new_files(&jail.fake_home);

    Ok(Behavior { exit_code, timed_out, seconds, network, new_files, output })
}

/// 在沙箱里运行一段脚本。`interpreter` 通常是 "/bin/bash"。不联网执行任何真实地址。
pub fn run_script(script: &str, interpreter: &str, timeout: Duration) -> std::io::Result<Behavior> {
    let jail = prepare_jail()?;
    let script_path = jail.work.join("script.sh");
    std::fs::write(&script_path, script)?;
    let argv = vec![interpreter.to_string(), script_path.to_string_lossy().into_owned()];
    exec_jailed(&jail, &argv, &jail.work.clone(), timeout)
}

/// 在沙箱里运行一个项目的启动命令（例如 npm start、node server.js）。
///
/// 把项目拷进牢笼里运行，面试项目“打开/启动就执行”的恶意代码会在这里暴露：
/// 读诱饵钱包和密钥、往隐藏目录或开机自启写东西、把数据发往外部。
/// 用 ditto 在 APFS 上做写时复制，几乎不额外占磁盘；跳过 .git。
/// 注意：直连 C2 的原始套接字会被系统挡住（看不到内容，但也到不了攻击者）；
/// 走 HTTP 代理的客户端才能看到外传内容。
pub fn run_project(project_dir: &Path, argv: &[String], timeout: Duration) -> std::io::Result<Behavior> {
    let jail = prepare_jail()?;
    let dest = jail.work.join("project");
    // ditto 保留结构、跟随 APFS clonefile；比 cp -R 快且省盘
    let status = Command::new("/usr/bin/ditto").arg(project_dir).arg(&dest).arg("--norsrc").status();
    if !matches!(status, Ok(s) if s.success()) {
        // ditto 不在就退回普通递归复制
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

/// 把观察到的行为翻译成证据。靠行为判断，但正常安装脚本的联网、下载、写文件本身不算坏。
pub fn findings(b: &Behavior) -> Vec<Finding> {
    let mut out = Vec::new();
    let loc = "沙箱运行";

    for ev in &b.network {
        if !ev.leaked.is_empty() {
            out.push(Finding::new(
                Severity::High,
                format!("程序把诱饵敏感数据（{}）发往 {}，这是窃取数据的铁证", ev.leaked.join("、"), ev.target),
                loc,
            ));
        }
    }
    // 连接裸 IP 作为证据交给上层判断（正常安装脚本一般连域名）
    for ev in &b.network {
        let host = ev.target.split(':').next().unwrap_or("");
        if crate::net::is_ip(host) && !host.starts_with("127.") {
            out.push(Finding::new(Severity::Medium, format!("程序运行时直接连接 IP 地址 {}", ev.target), loc));
        }
    }
    for f in &b.new_files {
        if f.starts_with("Library/LaunchAgents") {
            out.push(Finding::new(Severity::High, format!("程序往开机自启目录写入了 {f}（想在重启后继续运行）"), loc));
        } else if f.contains(".node_modules") || f.starts_with(".task") || f.contains(".config/.node") {
            out.push(Finding::new(Severity::High, format!("程序往隐藏目录写入了 {f}（攻击者常用的藏身位置）"), loc));
        }
    }
    out
}

/// 一个项目的启动命令：有 package.json 就用 `npm start`，否则按常见入口猜。
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

/// 在沙箱里跑一个项目的启动命令，返回证据和命中。
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

/// 一次沙箱运行的完整结果：行为 + 证据，可放进证据里交给模型。
pub fn analyze_script(script: &str, timeout: Duration) -> (Value, Vec<Finding>) {
    match run_script(script, "/bin/bash", timeout) {
        Ok(b) => {
            let f = findings(&b);
            (json!({ "sandbox": b }), f)
        }
        Err(e) => (json!({ "sandbox_error": e.to_string() }), vec![]),
    }
}
