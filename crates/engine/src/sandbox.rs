//! 动态分析：把拿不准的脚本放进 macOS 自带的沙箱（Seatbelt / sandbox-exec）里跑一小会儿，
//! 看它实际做了什么，而不是逐行读代码。
//!
//! 被检查的东西是不可信的，所以不靠单独一层，而是几层叠起来，任何一层被绕过还有下一层：
//! 1. 最小权限：只给程序假家目录和工作目录的读写；家目录以外也不能写（防止往 /opt/homebrew/bin
//!    劫持命令、往 /Applications 落地），外接硬盘、其他用户目录、共享临时目录都看不到。
//! 2. 堵住“让系统替它干活”的出口：LaunchServices（open）、AppleEvents（osascript）、launchctl、
//!    剪贴板、钥匙串、DNS、偏好设置、给沙箱外的进程发信号或读它们的命令行——这些都是 Seatbelt
//!    文件和网络规则管不到、但能逃出沙箱或把数据带出去的路。
//! 3. 网络微隔离：只能连本机的一个记录代理，所有请求都被看见；直连外网被系统挡住。
//! 4. 资源上限：单个文件、CPU 时间、进程数都有上限，叉子炸弹和写满磁盘拖不垮用户的电脑。
//! 5. 行为监控：诱饵文件（每份带唯一标记）、运行后对比假家目录、收集被沙箱拦下的越权操作
//!    （系统日志里带本次运行标记的拒绝记录），以及脱离进程组想在后台驻留的进程。
//!
//! 运行有时间上限，结束后（不论是否超时）把它启动的所有进程一起杀掉，临时目录整个删除。
//!
//! 局限：
//! - 跑一分钟没看到坏行为，不代表安全（有的程序会拖延发作、或等用户输密码）。结论只说“这次看到了什么”。
//! - 苹果已不推荐 sandbox-exec 接口，未来可能需要换成虚拟机方案。这里把它包在一个模块里，方便替换。
//! - 第一阶段的代理只能看明文 HTTP；HTTPS 只能看到连了哪个域名，看不到内容（留待后续做证书拦截）。
//! - 试装依赖（npm install）时代理只把到 npm 官方源的连接真正转发出去，让包能下载下来、安装脚本能跑起来；
//!   安装脚本想连的其他地址照样只记录、不放行。从 git 地址装的依赖下载不到。

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

/// 仅供测试：生成一份样例规则，确认真实家目录被锁死、网络被限制。
pub fn _profile_for_test() -> String {
    let jail = JailPaths { root: "/tmp/jail".into(), fake_home: "/tmp/jail/home".into(), work: "/tmp/jail/work".into() };
    profile(Path::new("/Users/someone"), &jail, 12345, "tag")
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
    /// 试装依赖时到 npm 官方源的连接，真的转发了出去
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forwarded: bool,
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
    /// 被沙箱拦下的越权操作（来自系统日志），例如往 /opt/homebrew/bin 写文件、运行 osascript
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<Denied>,
}

/// 沙箱拦下的一次越权操作
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Denied {
    /// 做这件事的程序名
    pub process: String,
    /// Seatbelt 的操作名，例如 file-write-create、process-exec*、network-outbound
    pub operation: String,
    /// 目标：路径、程序、偏好设置域或端口
    pub target: String,
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

/// 沙箱里的 PATH：真实 PATH + 常见版本管理器的默认位置 + 系统路径，让装在家目录的 node / npm 能被找到。
///
/// 从 Finder / 登录项启动的 App 拿到的 PATH 只有 /usr/bin:/bin:/usr/sbin:/sbin，
/// fnm / nvm 这类在 ~/.zshrc 里才配置的路径都不在里面。固定位置还找不到 node 时，
/// 再问一次用户的登录 shell 要 PATH（结果缓存，只问一次）。
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

/// 结束我们自己用 process_group(0) 启动的那一组进程（组号就是子进程的 pid）。
/// 只能用在这种自建的组上。pid 为 0 或 1 时 kill(-pid) 会变成“当前用户的所有进程”，所以先挡掉。
fn kill_own_group(child_pid: u32) {
    let Ok(pgid) = i32::try_from(child_pid) else { return };
    if pgid > 1 {
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
}

/// fnm / volta / bun / asdf 的默认 bin 目录（只取存在的）。nvm 的默认版本要解析别名，交给登录 shell。
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

/// 用用户的登录 + 交互 shell 打印 PATH（fnm env 之类通常写在 .zshrc 里，所以要 -i）。
/// rc 文件可能往 stdout 打印别的东西，用标记把 PATH 截出来；超过 3 秒就放弃。
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

/// node / python / 包管理器常装在家目录下的这些子目录里。锁死家目录时要放行它们的只读，
/// 否则沙箱里连 node 本身都读不到。这些目录里没有 .ssh、钱包、浏览器密码这类敏感文件。
const TOOL_SUBDIRS: &[&str] = &[
    ".local", ".nvm", ".fnm", ".volta", ".bun", ".cargo", ".npm-global", ".asdf", ".rbenv", ".pyenv", ".deno",
    "Library/pnpm", "Library/Application Support/fnm", "Library/Caches/fnm", ".yarn",
];

/// 沙箱里程序不能直接运行的系统工具：它们会请系统替它启动程序、发 AppleEvents、注册开机任务、
/// 读钥匙串和剪贴板，绕开 Seatbelt 的文件和网络规则。下面的系统服务规则是同一件事的第二道门。
const BLOCKED_TOOLS: &[&str] = &["/usr/bin/open", "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/security", "/usr/bin/pbcopy", "/usr/bin/pbpaste", "/usr/bin/sudo"];

/// 不让沙箱里的程序找的系统服务（mach 服务名）
const BLOCKED_SERVICES: &[&str] = &[
    // LaunchServices：open 一个 App 或文档，被打开的程序不在沙箱里
    "com.apple.coreservices.launchservicesd",
    // AppleEvents：让 Finder、Terminal、System Events 替它执行命令
    "com.apple.coreservices.appleevents",
    // 剪贴板：可能有刚复制的密码、助记词
    "com.apple.pasteboard.1",
    // DNS：直连被挡住后，可以把数据编码进域名查询带出去
    "com.apple.dnssd.service",
    // 钥匙串
    "com.apple.SecurityServer",
    "com.apple.securityd.xpc",
];

/// 每个路径名都用 Seatbelt 的字符串语法转义
fn esc(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
}

/// Seatbelt 规则。底子是 allow default（程序要能读 /usr、/System 才跑得起来），在上面按最小权限收紧。
///
/// 两个坑：
/// - 后写的规则覆盖先写的，但“具体的操作名”比“通配的操作名”优先：先写了 deny file-read*，
///   后面的 allow file* 盖不住它，所以放行时要逐类写 file-read* / file-write*。
/// - 规则匹配的是解析后的真实路径（/private/var/folders/…），所以牢笼路径必须先 canonicalize。
///
/// 每条 deny 都带上本次运行的标记，被拦下时系统日志里会出现这个标记，运行后据此收集越权操作。
fn profile(real_home: &Path, jail: &JailPaths, proxy_port: u16, tag: &str) -> String {
    let mark = format!("(with message \"{tag}\")");
    // 家目录下的工具目录只读放行：让装在家目录里的 node / python 能运行，但不能往真实家目录写
    let tools: Vec<PathBuf> = TOOL_SUBDIRS.iter().map(|d| real_home.join(d)).filter(|p| p.exists()).collect();
    let tool_allows: String = tools.iter().map(|p| format!("(allow file-read* process-exec (subpath \"{}\"))\n", esc(p))).collect();
    // node 解析真实路径时会 lstat 每一级父目录（/Users、/Users/xx、~/.local ……），被拒就直接报 EPERM 退出。
    // 只放行这几级目录本身的元数据：不能列目录、不能读内容。牢笼的各级父目录同理（getcwd 要用）。
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
; 写：除了假家目录和工作目录，哪里都不能写（/opt/homebrew/bin、/Applications、外接硬盘、/tmp）
(deny file-write* (subpath "/") {mark})
; 读：外接硬盘、所有用户目录、共享临时目录都不让看
(deny file-read* (subpath "/Volumes") (subpath "/Users") (subpath "/private/tmp") (subpath "/private/var/folders") {mark})
; 真实家目录整个锁死：读不到用户真正的私钥、钱包、密码（家目录不在 /Users 下时也成立）
(deny file* (subpath "{real}") {mark})
; 每个程序都会按真实用户读一次文字编码设置，无害，放行免得日志里全是它
(allow file-read* (literal "{real}/.CFUserTextEncoding"))
; 工具目录只读、可执行
{tools}(allow file-read-metadata {metadata})
; 假家目录和工作目录可读可写；牢笼根目录里的规则文件看不到
(allow file-read* file-write* (subpath "{fake}") (subpath "{work}"))
(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper") (regex #"^/dev/fd/") (regex #"^/dev/tty"))
; 进程：不能直接运行让系统替它干活的工具；只能给自己沙箱里的进程发信号、看它们的信息
(deny process-exec {tools_exec} {mark})
(deny signal {mark})
(allow signal (target same-sandbox))
(deny process-info* {mark})
(allow process-info* (target same-sandbox))
; 系统服务：LaunchServices、AppleEvents、剪贴板、DNS、钥匙串，以及偏好设置
(deny mach-lookup {services} (global-name-prefix "com.apple.lsd.") {mark})
(deny appleevent-send {mark})
(deny user-preference-write {mark})
(deny user-preference-read {mark})
; 网络：默认禁止，只放行到本机的记录代理
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

/// 试装依赖时唯一真正放行的地址：npm 官方源（只走 HTTPS CONNECT）。
const REGISTRY_HOSTS: &[&str] = &["registry.npmjs.org:443", "registry.yarnpkg.com:443"];

/// 极简记录代理：扮演 HTTP 代理，把每个请求的目标和内容记下来，扫描诱饵标记，然后返回一个空的 200。
/// 不把请求真正转发出去，所以沙箱里的程序连不上真实的攻击服务器。
/// forward_registry 为 true 时，到 npm 官方源的 CONNECT 会真的接通，其他照旧只记录。
const MAX_PROXY_CONNECTIONS: usize = 32;
/// 记下的网络请求上限，够看清行为就行
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
                // 同时处理的连接有上限：沙箱里的程序开几千个连接，也不会在宿主这边开几千个线程
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
    // macOS 上 accept 出来的连接会继承监听端口的非阻塞模式，读写会直接返回 WouldBlock
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
        if forward_registry && REGISTRY_HOSTS.contains(&target.to_lowercase().as_str()) {
            // 连上就记，不等隧道关闭：npm 用长连接，结束时隧道可能还没断
            let upstream = connect_upstream(&target);
            events.lock().unwrap().push(NetEvent { target, request, leaked: vec![], forwarded: upstream.is_some() });
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
        // GET http://host/path HTTP/1.1 —— 明文，能看到完整请求
        let url = rest.split_whitespace().next().unwrap_or("");
        target = url.strip_prefix("http://").and_then(|u| u.split('/').next()).unwrap_or(url).to_string();
        request = format!("{method} {url}");
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    let leaked: Vec<String> = DECOYS.iter().filter(|d| text.contains(d.marker)).map(|d| d.marker.to_string()).collect();
    let mut events = events.lock().unwrap();
    if (!target.is_empty() || !leaked.is_empty()) && events.len() < MAX_NET_EVENTS {
        events.push(NetEvent { target, request, leaked, forwarded: false });
    }
}

fn connect_upstream(target: &str) -> Option<TcpStream> {
    use std::net::ToSocketAddrs;
    let addr = target.to_socket_addrs().ok()?.next()?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(10)).ok()
}

/// 把客户端和上游接通，双向转发，直到任一边关闭。只用于 npm 官方源。
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

/// 牢笼里的几个目录（都是解析后的真实路径，Seatbelt 按真实路径匹配）
struct JailPaths {
    root: PathBuf,
    fake_home: PathBuf,
    work: PathBuf,
}

/// 准备好的沙箱：目录 + 诱饵、记录代理、规则文件，以及本次运行的两个随机标记。
struct Jail {
    _dir: tempfile::TempDir,
    paths: JailPaths,
    profile: PathBuf,
    proxy_url: String,
    events: Arc<Mutex<Vec<NetEvent>>>,
    stop_tx: mpsc::Sender<()>,
    /// 写进每条 deny 规则，系统日志里据此找出这次运行被拦下的操作
    tag: String,
}

/// 一个随机十六进制串。只用来区分每次运行，不需要密码学强度。
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
    // 规则文件放在牢笼根目录：沙箱里只能读写 home 和 work，看不到规则和标记
    let profile = paths.root.join("profile.sb");
    std::fs::write(&profile, self::profile(&real_home, &paths, port, &tag))?;
    Ok(Jail { _dir: dir, paths, profile, proxy_url: format!("http://127.0.0.1:{port}"), events, stop_tx, tag })
}

/// 资源上限。单个文件 1 GiB、每个进程的 CPU 时间、整个用户的进程数（在当前数量上多给 256 个）。
/// 进程数是按用户算的，所以不能设一个固定的小数，否则用户自己开的程序多一点就什么都跑不起来。
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

    /// 在 fork 之后、exec 之前调用：只用 setrlimit，满足 async-signal-safe 的要求
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

/// 在准备好的牢笼里运行一条命令（argv 的第一个是程序），限时、收尸、收集行为。
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
        // 补全后的 PATH，node / npm（常装在家目录，已在规则里放行只读）才能被找到
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // 单独的进程组，结束时能把它启动的所有子进程一起杀掉
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
    // 不论是否超时，都把整个进程组杀掉：主进程退出了，它放到后台的子进程还会接着跑，
    // 而且会一直占着输出管道，下面读输出就永远等不到头
    kill_own_group(child.id());
    let _ = child.wait();
    // 只杀本次运行自己的进程组，不扫描全机进程去追“逃逸”的进程：认错一次就会杀掉用户自己的程序
    // （真实发生过，结束了 Slack、VS Code、Docker 和多个系统服务）。
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


/// 从系统日志里读出这次运行被沙箱拦下的操作。日志可能晚一点落盘，读之前稍等。
/// 剪贴板、DNS 这类系统服务被拒时不一定写日志，所以这里只是证据的补充，规则本身照样生效。
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

/// 解析一行内核日志：`Sandbox: touch(97285) deny(1) file-write-create /opt/homebrew/bin/x`
fn parse_denial(line: &str) -> Option<Denied> {
    let rest = &line[line.find("Sandbox: ")? + "Sandbox: ".len()..];
    let (process, rest) = rest.split_once('(')?;
    let rest = &rest[rest.find(" deny(")? + 1..];
    let mut parts = rest.splitn(3, ' ');
    parts.next()?;
    let operation = parts.next()?.to_string();
    let target = parts.next().unwrap_or("").trim().to_string();
    // 程序查全局偏好设置是常规动作，不算越权
    if target == "kcfpreferencesanyapplication" {
        return None;
    }
    Some(Denied { process: process.to_string(), operation, target })
}

/// 在沙箱里运行一段脚本。`interpreter` 通常是 "/bin/bash"。不联网执行任何真实地址。
pub fn run_script(script: &str, interpreter: &str, timeout: Duration) -> std::io::Result<Behavior> {
    let jail = prepare_jail(false)?;
    let script_path = jail.paths.work.join("script.sh");
    std::fs::write(&script_path, script)?;
    let argv = vec![interpreter.to_string(), script_path.to_string_lossy().into_owned()];
    exec_jailed(&jail, &argv, &jail.paths.work.clone(), timeout)
}

/// 在沙箱里运行一个项目的启动命令（例如 npm start、node server.js）。
///
/// 把项目拷进牢笼里运行，面试项目“打开/启动就执行”的恶意代码会在这里暴露：
/// 读诱饵钱包和密钥、往隐藏目录或开机自启写东西、把数据发往外部。
/// 用 ditto 在 APFS 上做写时复制，几乎不额外占磁盘；跳过 .git。
/// 注意：直连 C2 的原始套接字会被系统挡住（看不到内容，但也到不了攻击者）；
/// 走 HTTP 代理的客户端才能看到外传内容。
pub fn run_project(project_dir: &Path, argv: &[String], timeout: Duration) -> std::io::Result<Behavior> {
    run_in_copy(project_dir, argv, timeout, false)
}

/// 在沙箱里试装一个项目的依赖（npm install），让依赖的 preinstall / postinstall 脚本真的跑一遍。
/// 投毒的包多半在安装脚本里动手：读密钥、往隐藏目录写东西、把数据发出去。
/// 只放行到 npm 官方源的下载，安装脚本连别的地址照样被记录、被挡住。
pub fn run_install(project_dir: &Path, timeout: Duration) -> std::io::Result<Behavior> {
    run_in_copy(project_dir, &install_argv(), timeout, true)
}

pub fn install_argv() -> Vec<String> {
    ["npm", "install", "--no-audit", "--no-fund", "--foreground-scripts"].map(String::from).to_vec()
}

fn run_in_copy(project_dir: &Path, argv: &[String], timeout: Duration, forward_registry: bool) -> std::io::Result<Behavior> {
    let jail = prepare_jail(forward_registry)?;
    let dest = jail.paths.work.join("project");
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
    for d in &b.denied {
        if let Some((severity, message)) = classify_denial(d) {
            out.push(Finding::new(severity, message, loc));
        }
    }
    out
}

/// 真实家目录里的这些位置放着私钥、云凭证、钱包和浏览器密码。程序无视 $HOME、按真实路径去读它们，
/// 说明是冲着用户的真实数据来的。
const SENSITIVE_HOME_PATHS: &[&str] = &[
    "/.ssh/", "/.aws/", "/.gnupg/", "/.kube/", "/.docker/config.json", "/.netrc", "/.config/solana/",
    "/Library/Keychains/", "/Library/Application Support/Google/Chrome/", "/Library/Application Support/BraveSoftware/",
    "/Library/Application Support/Firefox/", "/Library/Application Support/Exodus/", "/Library/Cookies/",
];

/// 把一次被拦下的越权操作翻译成证据。正常安装脚本也会做的事（往 /usr/local/bin 装命令、
/// 打开浏览器、直连 443）只作为证据交给 AI，不单独定罪；只有明确的恶意信号才是高危。
fn classify_denial(d: &Denied) -> Option<(Severity, String)> {
    let (op, target, who) = (d.operation.as_str(), d.target.as_str(), d.process.as_str());
    let persistence = target.contains("/LaunchAgents/") || target.contains("/LaunchDaemons/") || target.ends_with("/LaunchAgents") || target.contains("/Library/StartupItems");
    if op.starts_with("file-write") && persistence {
        return Some((Severity::High, format!("{who} 想在沙箱外的 {target} 写入开机自启项，被沙箱挡住了")));
    }
    if op.starts_with("file-write") && ["/opt/homebrew/", "/usr/local/", "/Applications/"].iter().any(|p| target.starts_with(p)) {
        // 正常安装脚本也常把命令装进 /usr/local/bin，只作为证据交给 AI，不参与判断
        return Some((Severity::Low, format!("{who} 想往沙箱外的 {target} 写文件（装命令或程序的位置），被沙箱挡住了")));
    }
    // ssh、git 本来就按真实用户找 ~/.ssh，不算
    if op.starts_with("file-read") && !matches!(who, "ssh" | "git" | "git-remote-https") && target.starts_with("/Users/") && SENSITIVE_HOME_PATHS.iter().any(|p| target.contains(p)) {
        return Some((Severity::High, format!("{who} 绕过假家目录、直接读取真实的 {target}，被沙箱挡住了")));
    }
    if op.starts_with("process-exec") {
        return match target {
            "/usr/bin/security" => Some((Severity::High, format!("{who} 想运行 security 读取钥匙串，被沙箱挡住了"))),
            "/usr/bin/osascript" => Some((Severity::Medium, format!("{who} 想运行 osascript（假冒系统密码框是 macOS 窃密木马的常见手法），被沙箱挡住了"))),
            "/bin/launchctl" => Some((Severity::Medium, format!("{who} 想用 launchctl 注册后台任务，被沙箱挡住了"))),
            "/usr/bin/pbpaste" | "/usr/bin/pbcopy" => Some((Severity::Medium, format!("{who} 想读写剪贴板，被沙箱挡住了"))),
            _ => None,
        };
    }
    if op == "user-preference-write" {
        return Some((Severity::Medium, format!("{who} 想修改 {target} 的设置，被沙箱挡住了")));
    }
    // 绕过代理直连：443 / 80 很多正常程序也会（不认代理的 HTTP 客户端），只看少见的端口
    if op == "network-outbound" {
        let port = target.rsplit(':').next().unwrap_or("");
        if !port.is_empty() && !matches!(port, "80" | "443" | "53") && port.chars().all(|c| c.is_ascii_digit()) {
            return Some((Severity::Medium, format!("{who} 绕过代理直接连接端口 {port}，被沙箱挡住了（木马的控制端常用不常见的端口）")));
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
        assert_eq!(d.target, "/Users/a/Library/Application Support/Google/Chrome/Default/Login Data", "路径里的空格要保留");
        assert_eq!(parse_denial("Sandbox: curl(1) deny(1) network-outbound remote:*:1224").unwrap().target, "remote:*:1224");
        assert!(parse_denial("Sandbox: curl(1) deny(1) user-preference-read kcfpreferencesanyapplication").is_none(), "查全局设置是噪音");
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
            assert!(p.contains(must), "规则里缺少 {must}:\n{p}");
        }
        // 牢笼根目录（放规则文件的地方）不在可读范围内，只有 home 和 work
        assert!(p.contains("(subpath \"/tmp/jail/home\") (subpath \"/tmp/jail/work\")") && !p.contains("(subpath \"/tmp/jail\")"));
    }
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
