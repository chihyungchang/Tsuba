//! 检查 macOS 安装包（.dmg / .pkg / .app）：签名、公证、下载来源、隐藏的可执行文件、安装脚本。
//!
//! 只读挂载、只读展开，不运行其中任何程序。

use crate::rules::{self, Finding, Severity};
use serde_json::{Map, Value, json};
use std::io::Read;
use std::path::Path;
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
            let (code, out) = run(&["strings", "-n", "8", &p.to_string_lossy()], 20);
            if code == 0 {
                let text: String = out.chars().take(3_000_000).collect();
                let loc = format!("{name}/Contents/MacOS/{}", p.file_name().unwrap().to_string_lossy());
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
    let entries: Vec<_> = std::fs::read_dir(mnt.path()).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    info.insert("contents".into(), json!(entries.iter().take(30).filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).collect::<Vec<_>>()));
    let ext = |p: &Path| p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let apps: Vec<Value> = entries.iter().filter(|p| ext(p) == "app").take(3).map(|a| inspect_app(a, findings)).collect();
    info.insert("apps".into(), json!(apps));
    let pkgs: Vec<Value> = entries.iter().filter(|p| ext(p) == "pkg").take(2).map(|p| Value::Object(inspect_pkg(&p.to_string_lossy(), findings))).collect();
    if !pkgs.is_empty() {
        info.insert("pkgs".into(), json!(pkgs));
    }
    for f in entries.iter().filter(|p| p.is_file() && matches!(ext(p).as_str(), "command" | "sh" | "tool")) {
        let fname = f.file_name().unwrap().to_string_lossy().to_string();
        findings.push(Finding::new(Severity::Medium, format!("安装镜像里带了可双击运行的脚本 {fname}"), &dmg_name));
        findings.extend(rules::scan_text(&crate::read_limited(f, 200_000), &fname));
    }
    run(&["hdiutil", "detach", "-force", &mnt_s], 30);
    info
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
