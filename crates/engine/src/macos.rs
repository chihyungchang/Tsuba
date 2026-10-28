//! 检查 macOS 安装包（.dmg / .pkg / .app）：签名、公证、下载来源、隐藏的可执行文件、安装脚本。
//!
//! 只读挂载、只读展开，不运行其中任何程序。

use crate::rules::{self, Finding, Severity};
use serde_json::{Map, Value, json};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// 运行一个系统命令，超时就杀掉。返回（退出码，stdout + stderr）。
pub fn run(args: &[&str], timeout_secs: u64) -> (i32, String) {
    let mut child = match Command::new(args[0]).args(&args[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => return (-1, e.to_string()),
    };
    // 输出可能很大（strings），必须边跑边读，否则管道写满会卡死
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t1 = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t2 = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let code = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code().unwrap_or(-1),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(30)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break -1;
            }
        }
    };
    let mut out = t1.join().unwrap_or_default();
    out.extend(t2.join().unwrap_or_default());
    (code, String::from_utf8_lossy(&out).trim().to_string())
}

fn tail(s: &str, n: usize) -> String {
    let c: Vec<char> = s.chars().collect();
    c[c.len().saturating_sub(n)..].iter().collect()
}

/// macOS 会记录文件是从哪个网址下载的（kMDItemWhereFroms）。
pub fn where_from(path: &str) -> Vec<String> {
    let (code, out) = run(&["mdls", "-raw", "-name", "kMDItemWhereFroms", path], 10);
    if code != 0 || out == "(null)" || out.is_empty() {
        return vec![];
    }
    let lines: Vec<&str> = out.lines().collect();
    if lines.len() < 2 {
        return vec![];
    }
    lines[1..lines.len() - 1].iter().map(|l| l.trim().trim_matches(|c| c == '"' || c == ',').to_string()).filter(|l| !l.is_empty()).collect()
}

pub fn has_quarantine(path: &str) -> bool {
    run(&["xattr", "-p", "com.apple.quarantine", path], 5).0 == 0
}

pub fn inspect_app(app: &Path, findings: &mut Vec<Finding>) -> Value {
    let name = app.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let app_s = app.to_string_lossy().to_string();
    let mut info = Map::new();
    info.insert("app".into(), json!(name));

    let (code, out) = run(&["codesign", "-dv", "--verbose=2", &app_s], 30);
    info.insert("codesign".into(), json!(tail(&out, 800)));
    if code != 0 || out.contains("code object is not signed") {
        findings.push(Finding::new(Severity::High, "应用没有代码签名", &name));
    } else if out.contains("Signature=adhoc") {
        findings.push(Finding::new(Severity::High, "应用只有临时签名（adhoc），没有开发者身份", &name));
    }
    if let Some(dev) = out.lines().find_map(|l| l.strip_prefix("Authority=Developer ID Application:")) {
        info.insert("developer".into(), json!(dev.trim()));
    }
    let (code, out) = run(&["spctl", "--assess", "--type", "execute", "-vv", &app_s], 30);
    info.insert("gatekeeper".into(), json!(tail(&out, 400)));
    if code != 0 {
        findings.push(Finding::new(Severity::Medium, "Gatekeeper 评估不通过（未公证或被拒绝）", &name).with_snippet(tail(&out, 200)));
    }

    if let Ok(plist) = plist::Value::from_file(app.join("Contents/Info.plist"))
        && let Some(d) = plist.as_dictionary() {
            let exe = d.get("CFBundleExecutable").and_then(|v| v.as_string()).unwrap_or("");
            info.insert("bundle_id".into(), json!(d.get("CFBundleIdentifier").and_then(|v| v.as_string())));
            info.insert("executable".into(), json!(exe));
            info.insert("sha256".into(), json!(crate::sha256_file(&app.join("Contents/MacOS").join(exe))));
            if exe.starts_with('.') {
                findings.push(Finding::new(Severity::High, format!("主程序被替换成隐藏文件 {exe}（Jamf 披露的 Contagious Interview 手法）"), &name));
            }
        }

    let macos_dir = app.join("Contents/MacOS");
    if let Ok(rd) = std::fs::read_dir(&macos_dir) {
        let entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        let names: Vec<String> = entries.iter().filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).collect();
        let hidden: Vec<&String> = names.iter().filter(|n| n.starts_with('.')).collect();
        if !hidden.is_empty() {
            findings.push(Finding::new(Severity::High, format!("可执行目录里有隐藏文件：{}", hidden.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), &name));
        }
        info.insert("macos_dir".into(), json!(names.iter().take(20).collect::<Vec<_>>()));
        for p in entries.iter().take(5) {
            let small = p.metadata().map(|m| m.is_file() && m.len() < 60_000_000).unwrap_or(false);
            if !small {
                continue;
            }
            let loc = format!("{name}/Contents/MacOS/{}", p.file_name().unwrap().to_string_lossy());
            findings.extend(crate::intel::yara::scan_file(p, &loc));
            let (code, out) = run(&["strings", "-n", "8", &p.to_string_lossy()], 20);
            if code == 0 {
                let text: String = out.chars().take(3_000_000).collect();
                // 二进制里的字符串噪声大（系统库也会带这些路径），统一降为中等，交给模型结合上下文判断
                for mut f in rules::scan_text(&text, &loc) {
                    if f.severity == Severity::High {
                        f.severity = Severity::Medium;
                    }
                    findings.push(f);
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(app.join("Contents/Resources")) {
        for p in rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "sh")) {
            let text = crate::read_limited(&p, 200_000);
            findings.extend(rules::scan_text(&text, &format!("{name}/Resources/{}", p.file_name().unwrap().to_string_lossy())));
        }
    }
    Value::Object(info)
}

pub fn inspect_dmg(path: &str, findings: &mut Vec<Finding>) -> Map<String, Value> {
    let mut info = Map::new();
    let Ok(mnt) = tempfile::Builder::new().prefix("tsuba-").tempdir() else {
        info.insert("error".into(), json!("无法创建临时目录"));
        return info;
    };
    let mnt_s = mnt.path().to_string_lossy().to_string();
    let (code, out) = run(&["hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", &mnt_s, path], 60);
    if code != 0 {
        info.insert("error".into(), json!(format!("无法挂载：{}", tail(&out, 200))));
        return info;
    }
    let dmg_name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    info.extend(inspect_volume(mnt.path(), &dmg_name, findings));
    run(&["hdiutil", "detach", "-force", &mnt_s], 30);
    info
}

/// 镜像挂载后的系统文件，不算可疑
const VOLUME_SYSTEM_FILES: &[&str] = &[
    ".DS_Store", ".fseventsd", ".background", ".VolumeIcon.icns", ".Trashes", ".TemporaryItems", ".Spotlight-V100", ".DocumentRevisions-V100", ".apdisk",
];

/// 文件开头是不是 Mach-O 可执行文件（含 universal binary）
fn is_macho(p: &Path) -> bool {
    let mut magic = [0u8; 4];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut magic)).is_ok()
        && matches!(u32::from_be_bytes(magic), 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA)
}

fn is_script(p: &Path) -> bool {
    crate::read_limited(p, 2).starts_with("#!")
}

/// 目录像不像一个安装镜像的内容：挂在 /Volumes 下，或者根目录里有 .app / .pkg、指向“应用程序”或“终端”的快捷方式。
/// 用户扫描 /Volumes/Zeff 或从镜像里拷出来的文件夹时，要按安装镜像检查，而不是当成代码项目。
pub fn looks_like_volume(dir: &Path) -> bool {
    if !dir.is_dir() || dir.join("package.json").is_file() {
        return false;
    }
    if dir.parent() == Some(Path::new("/Volumes")) {
        return true;
    }
    std::fs::read_dir(dir).map(|rd| rd.flatten().any(|e| {
        let p = e.path();
        let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
        let link = std::fs::read_link(&p).map(|t| t.to_string_lossy().to_string()).unwrap_or_default();
        ext == "app" || ext == "pkg" || link == "/Applications" || link.contains("Terminal.app") || link.contains("iTerm.app")
    })).unwrap_or(false)
}

/// 检查一个已挂载的安装镜像（自己只读挂载的，或用户刚打开的 /Volumes/xxx）。
pub fn inspect_volume(root: &Path, label: &str, findings: &mut Vec<Finding>) -> Map<String, Value> {
    let mut info = Map::new();
    let entries: Vec<PathBuf> = std::fs::read_dir(root).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    let name_of = |p: &Path| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    info.insert("contents".into(), json!(entries.iter().take(30).map(|p| name_of(p)).collect::<Vec<_>>()));
    let ext = |p: &Path| p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let apps: Vec<Value> = entries.iter().filter(|p| ext(p) == "app").take(3).map(|a| inspect_app(a, findings)).collect();
    let pkgs: Vec<Value> = entries.iter().filter(|p| ext(p) == "pkg").take(2).map(|p| Value::Object(inspect_pkg(&p.to_string_lossy(), findings))).collect();

    // 指向“终端”的快捷方式：引导用户把镜像里的文件拖进终端运行，从终端运行的脚本不经过 Gatekeeper
    for p in &entries {
        if let Ok(target) = std::fs::read_link(p) {
            let t = target.to_string_lossy();
            if t.contains("Terminal.app") || t.contains("iTerm.app") {
                findings.push(Finding::new(
                    Severity::High,
                    format!("安装镜像里放了一个指向“终端”的快捷方式（{}），这是引导你把文件拖进终端运行、绕过 Gatekeeper 的骗局", name_of(p)),
                    label,
                ));
            }
        }
    }

    // 根目录里可以直接运行的脚本，不管扩展名是什么（Zeff 用的是 Installer.file）
    let mut scripts = Map::new();
    for f in entries.iter().filter(|p| p.is_file() && !p.is_symlink() && (is_script(p) || matches!(ext(p).as_str(), "command" | "sh" | "tool"))) {
        let fname = name_of(f);
        let text = crate::read_limited(f, 200_000);
        findings.push(Finding::new(Severity::Medium, format!("安装镜像里带了一个可以直接运行的脚本 {fname}"), label));
        findings.extend(rules::scan_text(&text, &fname));
        findings.extend(crate::intel::yara::scan_file(f, &fname));
        scripts.insert(fname, json!(text.chars().take(6000).collect::<String>()));
    }

    // 资源派生（文件的 com.apple.ResourceFork 扩展属性）：Bundlore 把加密载荷藏在这里，
    // 镜像里只看得到一个 203 字节的 .command，它运行时从自己的资源派生里截出载荷、解压执行。
    // 只读文件内容的扫描器看不到它。正常文件的资源派生只放自定义图标。
    let mut forks = Vec::new();
    for f in entries.iter().filter(|p| p.is_file() && !p.is_symlink()) {
        let Some((size, embedded)) = resource_fork(f) else { continue };
        let fname = name_of(f);
        if let Some(kind) = embedded {
            findings.push(Finding::new(
                Severity::High,
                format!("{fname} 的资源派生里藏着一个{kind}（{size} 字节）。正常文件的资源派生只放图标，这是把载荷藏在扫描器看不到的地方"),
                label,
            ));
        } else if is_script(f) && size > SCRIPT_FORK_LIMIT {
            findings.push(Finding::new(Severity::Medium, format!("可以直接运行的脚本 {fname} 带着 {size} 字节的资源派生，正常脚本没有"), label));
        }
        forks.push(json!({ "file": fname, "size": size, "embedded": embedded }));
    }

    // 隐藏目录里的可执行程序：正常的安装镜像不会把程序藏起来
    let mut hidden = Vec::new();
    for p in entries.iter().filter(|p| name_of(p).starts_with('.') && !VOLUME_SYSTEM_FILES.contains(&name_of(p).as_str())) {
        let files = if p.is_dir() { crate::walk_files(p, 200) } else { vec![p.clone()] };
        for f in files.iter().filter(|f| is_macho(f) || is_script(f)) {
            let rel = f.strip_prefix(root).unwrap_or(f).to_string_lossy().to_string();
            findings.extend(crate::intel::yara::scan_file(f, &rel));
            let (code, out) = run(&["codesign", "-dv", &f.to_string_lossy()], 15);
            let signed = code == 0 && !out.contains("Signature=adhoc");
            findings.push(Finding::new(
                Severity::High,
                format!("安装镜像的隐藏目录里藏着一个可执行程序 {rel}{}", if signed { "" } else { "，而且没有开发者签名" }),
                label,
            ));
            hidden.push(json!({ "path": rel, "macho": is_macho(f), "codesign": tail(&out, 300), "sha256": crate::sha256_file(f) }));
        }
    }

    if apps.is_empty() && pkgs.is_empty() && (!scripts.is_empty() || !hidden.is_empty()) {
        findings.push(Finding::new(Severity::Medium, "安装镜像里没有正常的应用程序或安装包，只有脚本和程序文件", label));
    }
    info.insert("apps".into(), json!(apps));
    if !pkgs.is_empty() {
        info.insert("pkgs".into(), json!(pkgs));
    }
    if !scripts.is_empty() {
        info.insert("scripts".into(), Value::Object(scripts));
    }
    if !hidden.is_empty() {
        info.insert("hidden_executables".into(), json!(hidden));
    }
    if !forks.is_empty() {
        info.insert("resource_forks".into(), json!(forks));
    }
    info
}

/// 脚本的资源派生超过这个大小才算异常：给脚本设个自定义图标也就几十 KB
const SCRIPT_FORK_LIMIT: u64 = 64 * 1024;

/// 文件的资源派生：大小，以及里面有没有藏着压缩包或可执行程序（只看文件头标记，不解压、不执行）。
/// 没有资源派生时返回 None。
fn resource_fork(p: &Path) -> Option<(u64, Option<&'static str>)> {
    let fork = p.join("..namedfork/rsrc");
    let size = std::fs::metadata(&fork).ok()?.len();
    if size == 0 {
        return None;
    }
    let mut data = Vec::new();
    std::fs::File::open(&fork).ok()?.take(4 << 20).read_to_end(&mut data).ok()?;
    const MAGICS: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "压缩包"),
        (b"\x1f\x8b\x08", "gzip 压缩数据"),
        (b"7z\xbc\xaf\x27\x1c", "7z 压缩包"),
        (b"\xcf\xfa\xed\xfe", "可执行程序（Mach-O）"),
        (b"\xca\xfe\xba\xbe", "可执行程序（Mach-O）"),
        (b"#!/bin/", "脚本"),
    ];
    let embedded = MAGICS.iter().find(|(m, _)| data.windows(m.len()).any(|w| w == *m)).map(|(_, k)| *k);
    Some((size, embedded))
}

/// 当前挂载的磁盘镜像：挂载点 → 镜像文件路径。
pub fn mounted_images() -> Vec<(PathBuf, PathBuf)> {
    let (code, out) = run(&["hdiutil", "info", "-plist"], 10);
    if code != 0 {
        return vec![];
    }
    let Ok(plist) = plist::Value::from_reader_xml(out.as_bytes()) else { return vec![] };
    let mut result = Vec::new();
    let images = plist.as_dictionary().and_then(|d| d.get("images")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for img in images {
        let Some(d) = img.as_dictionary() else { continue };
        let Some(image) = d.get("image-path").and_then(|v| v.as_string()) else { continue };
        for ent in d.get("system-entities").and_then(|v| v.as_array()).into_iter().flatten() {
            if let Some(mp) = ent.as_dictionary().and_then(|e| e.get("mount-point")).and_then(|v| v.as_string()) {
                result.push((PathBuf::from(mp), PathBuf::from(image)));
            }
        }
    }
    result
}

pub fn inspect_pkg(path: &str, findings: &mut Vec<Finding>) -> Map<String, Value> {
    let pkg_name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut info = Map::new();
    info.insert("pkg".into(), json!(pkg_name));
    let (code, out) = run(&["pkgutil", "--check-signature", path], 30);
    info.insert("signature".into(), json!(tail(&out, 600)));
    if code != 0 || out.to_lowercase().contains("no signature") {
        findings.push(Finding::new(Severity::High, "安装包没有签名", &pkg_name));
    }
    let Ok(tmp) = tempfile::Builder::new().prefix("tsuba-pkg-").tempdir() else { return info };
    let dest = tmp.path().join("x");
    let (code, _) = run(&["pkgutil", "--expand", path, &dest.to_string_lossy()], 60);
    if code == 0 {
        let mut scripts = Map::new();
        for p in crate::walk_files(&dest, 2000) {
            let is_script = p.file_name().is_some_and(|n| n == "preinstall" || n == "postinstall")
                || p.parent().and_then(|d| d.file_name()).is_some_and(|n| n == "Scripts");
            if !is_script || scripts.len() >= 10 {
                continue;
            }
            let text = crate::read_limited(&p, 100_000);
            let rel = p.strip_prefix(&dest).unwrap_or(&p).to_string_lossy().to_string();
            findings.extend(rules::scan_text(&text, &format!("{pkg_name}:{}", p.file_name().unwrap().to_string_lossy())));
            scripts.insert(rel, json!(text.chars().take(4000).collect::<String>()));
        }
        info.insert("scripts".into(), Value::Object(scripts));
    }
    info
}

pub fn inspect_path(path: &str) -> (Value, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut info = Map::new();
    info.insert("path".into(), json!(path));
    if !Path::new(path).exists() {
        info.insert("error".into(), json!("文件不存在"));
        return (Value::Object(info), findings);
    }
    let from = where_from(path);
    info.insert("where_from".into(), json!(from));
    if Path::new(path).is_file() {
        info.insert("sha256".into(), json!(crate::sha256_file(Path::new(path))));
    }
    info.insert("quarantined".into(), json!(has_quarantine(path)));
    let low = path.to_lowercase();
    let low = low.trim_end_matches('/');
    if low.ends_with(".dmg") {
        info.extend(inspect_dmg(path, &mut findings));
    } else if low.ends_with(".pkg") || low.ends_with(".mpkg") {
        info.extend(inspect_pkg(path, &mut findings));
    } else if low.ends_with(".app")
        && let Value::Object(m) = inspect_app(Path::new(path), &mut findings) {
            info.extend(m);
        }
    (Value::Object(info), findings)
}
