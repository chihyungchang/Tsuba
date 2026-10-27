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
use std::path::Path;
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

/// Seatbelt 规则：允许大部分操作（程序要能读 /usr、/bin 才能跑），但锁死真实家目录、限制网络。
fn profile(real_home: &Path, fake_home: &Path, work: &Path, proxy_port: u16) -> String {
    let esc = |p: &Path| p.to_string_lossy().replace('"', "\\\"");
    format!(
        r#"(version 1)
(allow default)
; 真实家目录整个锁死：读不到用户真正的私钥、钱包、密码
(deny file* (subpath "{real}"))
; 假家目录和临时工作目录可读可写
(allow file* (subpath "{fake}"))
(allow file* (subpath "{work}"))
; 网络：默认禁止，只放行到本机的记录代理
(deny network*)
(allow network-outbound (remote ip "localhost:{port}"))
(allow network-bind (local ip "localhost:*"))
"#,
        real = esc(real_home),
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

/// 在沙箱里运行一段脚本。`interpreter` 通常是 "/bin/bash"。不联网执行任何真实地址。
pub fn run_script(script: &str, interpreter: &str, timeout: Duration) -> std::io::Result<Behavior> {
    let real_home = crate::home_dir();
    let jail = tempfile::Builder::new().prefix("tsuba-sandbox-").tempdir()?;
    let fake_home = jail.path().join("home");
    let work = jail.path().join("work");
    std::fs::create_dir_all(&fake_home)?;
    std::fs::create_dir_all(&work)?;
    write_decoys(&fake_home)?;

    let (port, events, stop_tx) = start_proxy()?;
    let profile_path = jail.path().join("profile.sb");
    std::fs::write(&profile_path, profile(&real_home, &fake_home, &work, port))?;
    let script_path = work.join("script.sh");
    std::fs::write(&script_path, script)?;

    let proxy = format!("http://127.0.0.1:{port}");
    let mut child = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&profile_path)
        .arg(interpreter)
        .arg(&script_path)
        .current_dir(&work)
        .env_clear()
        .env("HOME", &fake_home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin")
        .env("TMPDIR", &work)
        .env("USER", "user")
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
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
                // 杀掉整个进程组
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                let _ = child.wait();
                break None;
            }
        }
    };
    let seconds = start.elapsed().as_secs_f64();
    // 给代理一点时间收尾，再停下它
    std::thread::sleep(Duration::from_millis(100));
    let _ = stop_tx.send(());

    let mut output = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    output.push_str(&String::from_utf8_lossy(&t_err.join().unwrap_or_default()));
    let output: String = output.chars().take(4000).collect();
    let network = events.lock().unwrap().clone();
    let new_files = new_files(&fake_home);

    Ok(Behavior { exit_code, timed_out, seconds, network, new_files, output })
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
