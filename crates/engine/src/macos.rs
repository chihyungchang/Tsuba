//! Checks macOS installers (.dmg / .pkg / .app): signature, notarization, download source, hidden executables, install scripts.
//!
//! Mounted and expanded read-only; nothing inside is ever run.

use crate::rules::{self, Finding, Severity};
use serde_json::{Map, Value, json};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Runs a system command and kills it on timeout. Returns (exit code, stdout + stderr).
pub fn run(args: &[&str], timeout_secs: u64) -> (i32, String) {
    let mut child = match Command::new(args[0]).args(&args[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => return (-1, e.to_string()),
    };
    // Output can be large (strings), so read while it runs, or a full pipe would hang it
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

/// macOS records which URL a file was downloaded from (kMDItemWhereFroms).
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
        findings.push(Finding::new(Severity::High, tr!("The app has no code signature"), &name));
    } else if out.contains("Signature=adhoc") {
        findings.push(Finding::new(Severity::High, tr!("The app has only an ad-hoc signature, with no developer identity"), &name));
    }
    if let Some(dev) = out.lines().find_map(|l| l.strip_prefix("Authority=Developer ID Application:")) {
        info.insert("developer".into(), json!(dev.trim()));
    }
    let (code, out) = run(&["spctl", "--assess", "--type", "execute", "-vv", &app_s], 30);
    info.insert("gatekeeper".into(), json!(tail(&out, 400)));
    if code != 0 {
        findings.push(Finding::new(Severity::Medium, tr!("Gatekeeper rejects the app (not notarized, or refused)"), &name).with_snippet(tail(&out, 200)));
    }

    if let Ok(plist) = plist::Value::from_file(app.join("Contents/Info.plist"))
        && let Some(d) = plist.as_dictionary() {
            let exe = d.get("CFBundleExecutable").and_then(|v| v.as_string()).unwrap_or("");
            info.insert("bundle_id".into(), json!(d.get("CFBundleIdentifier").and_then(|v| v.as_string())));
            info.insert("executable".into(), json!(exe));
            info.insert("sha256".into(), json!(crate::sha256_file(&app.join("Contents/MacOS").join(exe))));
            if exe.starts_with('.') {
                findings.push(Finding::new(Severity::High, tr!("The main executable is the hidden file {exe} (the Contagious Interview technique reported by Jamf)", exe = exe), &name));
            }
        }

    let macos_dir = app.join("Contents/MacOS");
    if let Ok(rd) = std::fs::read_dir(&macos_dir) {
        let entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        let names: Vec<String> = entries.iter().filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).collect();
        let hidden: Vec<&String> = names.iter().filter(|n| n.starts_with('.')).collect();
        if !hidden.is_empty() {
            findings.push(Finding::new(Severity::High, tr!("Hidden files in the executable folder: {files}", files = hidden.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), &name));
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
                // Strings from binaries are noisy (system libraries carry these paths too), so cap them at medium and let the model judge in context
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
        info.insert("error".into(), json!(tr!("Couldn't create a temporary folder")));
        return info;
    };
    let mnt_s = mnt.path().to_string_lossy().to_string();
    let (code, out) = run(&["hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", &mnt_s, path], 60);
    if code != 0 {
        info.insert("error".into(), json!(tr!("Couldn't mount the disk image: {error}", error = tail(&out, 200))));
        return info;
    }
    let dmg_name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    info.extend(inspect_volume(mnt.path(), &dmg_name, findings));
    run(&["hdiutil", "detach", "-force", &mnt_s], 30);
    info
}

/// System files on a mounted image; not suspicious
const VOLUME_SYSTEM_FILES: &[&str] = &[
    ".DS_Store", ".fseventsd", ".background", ".VolumeIcon.icns", ".Trashes", ".TemporaryItems", ".Spotlight-V100", ".DocumentRevisions-V100", ".apdisk",
];

/// Whether the file starts like a Mach-O executable (universal binaries included)
fn is_macho(p: &Path) -> bool {
    let mut magic = [0u8; 4];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut magic)).is_ok()
        && matches!(u32::from_be_bytes(magic), 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA)
}

fn is_script(p: &Path) -> bool {
    crate::read_limited(p, 2).starts_with("#!")
}

/// Whether a folder looks like the contents of an installer image: mounted under /Volumes, or with an .app / .pkg, or a
/// shortcut to Applications or Terminal at the top. When the user scans /Volumes/Zeff or a folder copied out of an image,
/// it must be checked as an installer image, not as a code project.
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

/// Checks a mounted installer image (one we mounted read-only, or a /Volumes/xxx the user just opened).
pub fn inspect_volume(root: &Path, label: &str, findings: &mut Vec<Finding>) -> Map<String, Value> {
    let mut info = Map::new();
    let entries: Vec<PathBuf> = std::fs::read_dir(root).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    let name_of = |p: &Path| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    info.insert("contents".into(), json!(entries.iter().take(30).map(|p| name_of(p)).collect::<Vec<_>>()));
    let ext = |p: &Path| p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let apps: Vec<Value> = entries.iter().filter(|p| ext(p) == "app").take(3).map(|a| inspect_app(a, findings)).collect();
    let pkgs: Vec<Value> = entries.iter().filter(|p| ext(p) == "pkg").take(2).map(|p| Value::Object(inspect_pkg(&p.to_string_lossy(), findings))).collect();

    // A shortcut to Terminal: lures the user into dragging a file from the image into Terminal, and scripts run from Terminal skip Gatekeeper
    for p in &entries {
        if let Ok(target) = std::fs::read_link(p) {
            let t = target.to_string_lossy();
            if t.contains("Terminal.app") || t.contains("iTerm.app") {
                findings.push(Finding::new(
                    Severity::High,
                    tr!("The installer image contains a shortcut to Terminal ({name}). This is a scam to get you to drag a file into Terminal and run it, bypassing Gatekeeper.", name = name_of(p)),
                    label,
                ));
            }
        }
    }

    // Runnable scripts at the top level, whatever the extension (Zeff used Installer.file)
    let mut scripts = Map::new();
    for f in entries.iter().filter(|p| p.is_file() && !p.is_symlink() && (is_script(p) || matches!(ext(p).as_str(), "command" | "sh" | "tool"))) {
        let fname = name_of(f);
        let text = crate::read_limited(f, 200_000);
        findings.push(Finding::new(Severity::Medium, tr!("The installer image contains a script that can be run directly: {file}", file = fname), label));
        findings.extend(rules::scan_text(&text, &fname));
        findings.extend(crate::intel::yara::scan_file(f, &fname));
        scripts.insert(fname, json!(text.chars().take(6000).collect::<String>()));
    }

    // Resource forks (a file's com.apple.ResourceFork extended attribute): Bundlore hides an encrypted payload there.
    // The image shows only a 203-byte .command, which at run time cuts the payload out of its own resource fork, unpacks and runs it.
    // Scanners that only read file contents don't see it. Normal files only keep a custom icon in their resource fork.
    let mut forks = Vec::new();
    for f in entries.iter().filter(|p| p.is_file() && !p.is_symlink()) {
        let Some((size, embedded)) = resource_fork(f) else { continue };
        let fname = name_of(f);
        if let Some(kind) = embedded {
            findings.push(Finding::new(
                Severity::High,
                tr!("The resource fork of {file} hides {kind} ({size} bytes). Normal files keep only an icon there; this hides a payload where scanners don't look.", file = fname, kind = fork_content_label(kind), size = size),
                label,
            ));
        } else if is_script(f) && size > SCRIPT_FORK_LIMIT {
            findings.push(Finding::new(Severity::Medium, tr!("The runnable script {file} carries a {size}-byte resource fork, which normal scripts don't have", file = fname, size = size), label));
        }
        forks.push(json!({ "file": fname, "size": size, "embedded": embedded }));
    }

    // Executables in hidden folders: normal installer images don't hide programs
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
                if signed { tr!("An executable is hidden in a hidden folder of the installer image: {path}", path = rel) } else { tr!("An executable is hidden in a hidden folder of the installer image: {path}, and it has no developer signature", path = rel) },
                label,
            ));
            hidden.push(json!({ "path": rel, "macho": is_macho(f), "codesign": tail(&out, 300), "sha256": crate::sha256_file(f) }));
        }
    }

    if apps.is_empty() && pkgs.is_empty() && (!scripts.is_empty() || !hidden.is_empty()) {
        findings.push(Finding::new(Severity::Medium, tr!("The installer image has no regular app or installer package, only scripts and program files"), label));
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

/// A script's resource fork is only unusual above this size: a custom icon is a few dozen KB
const SCRIPT_FORK_LIMIT: u64 = 64 * 1024;

/// A file's resource fork: its size, and whether it hides an archive or executable (by magic bytes only; never unpacked or run).
/// None when there is no resource fork. The kind is an English id because it also goes into the evidence.
fn resource_fork(p: &Path) -> Option<(u64, Option<&'static str>)> {
    let fork = p.join("..namedfork/rsrc");
    let size = std::fs::metadata(&fork).ok()?.len();
    if size == 0 {
        return None;
    }
    let mut data = Vec::new();
    std::fs::File::open(&fork).ok()?.take(4 << 20).read_to_end(&mut data).ok()?;
    const MAGICS: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "zip archive"),
        (b"\x1f\x8b\x08", "gzip data"),
        (b"7z\xbc\xaf\x27\x1c", "7z archive"),
        (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
        (b"\xca\xfe\xba\xbe", "Mach-O executable"),
        (b"#!/bin/", "script"),
    ];
    let embedded = MAGICS.iter().find(|(m, _)| data.windows(m.len()).any(|w| w == *m)).map(|(_, k)| *k);
    Some((size, embedded))
}

/// What a resource fork hides, in the user's language
fn fork_content_label(kind: &str) -> String {
    match kind {
        "zip archive" => tr!("a zip archive"),
        "gzip data" => tr!("gzip data"),
        "7z archive" => tr!("a 7z archive"),
        "Mach-O executable" => tr!("a Mach-O executable"),
        "script" => tr!("a script"),
        other => other.to_string(),
    }
}

/// Currently mounted disk images: mount point → image file path.
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
        findings.push(Finding::new(Severity::High, tr!("The installer package is not signed"), &pkg_name));
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
        info.insert("error".into(), json!(tr!("The file doesn't exist")));
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
