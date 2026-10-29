//! Allowlist, quarantine and folder scans all read and write ~/.tsuba, so they get their own test binary with TSUBA_HOME pointed at a temporary folder.

use std::path::Path;
use tsuba_engine::rules::Verdict;
use tsuba_engine::store::Config;
use tsuba_engine::{quarantine, scan, trust};

fn offline() -> Config {
    Config::default().offline_only()
}

const RISKY_SCRIPT: &str = "#!/bin/bash\nxattr -d com.apple.quarantine /Applications/Zeff.app\n";

#[test]
fn trust_quarantine_and_folder_scan() {
    let home = tempfile::tempdir().unwrap();
    // The only test in this binary that touches local storage, so it doesn't race other tests over the environment variable
    unsafe { std::env::set_var("TSUBA_HOME", home.path()) };
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("install.sh");
    std::fs::write(&script, RISKY_SCRIPT).unwrap();
    std::fs::write(dir.path().join("photo.jpg"), "not code").unwrap();
    let cfg = offline();

    // Folder scan: picks scripts, skips photos; a second scan reuses results for unchanged files
    let r = scan::scan_folder(&cfg, dir.path(), |_| {});
    assert_eq!((r.checked, r.unchanged), (1, 0));
    assert_eq!(r.hits.len(), 1);
    assert!(r.hits[0].verdict >= Verdict::Warn, "a script that removes the quarantine flag should be flagged");
    let again = scan::scan_folder(&cfg, dir.path(), |_| {});
    assert_eq!((again.checked, again.unchanged, again.hits.len()), (0, 1, 1));
    assert!(!again.hits[0].fresh);

    // Allowlist: allowed once marked safe; checked again as soon as the content changes
    assert_ne!(tsuba_engine::evaluate_path(&cfg, &script).2.verdict, Verdict::Allow);
    trust::trust_path(&script).unwrap();
    assert_eq!(tsuba_engine::evaluate_path(&cfg, &script).2.verdict, Verdict::Allow);
    std::fs::write(&script, format!("{RISKY_SCRIPT}# changed\n")).unwrap();
    assert!(!trust::is_trusted_path(&script), "changed content should no longer be trusted");
    assert_ne!(tsuba_engine::evaluate_path(&cfg, &script).2.verdict, Verdict::Allow);
    trust::remove(&trust::list()[0].key);
    assert!(trust::list().is_empty());

    // Ignoring a command's warning covers exactly those findings: a new finding warns again
    let warning = vec![tsuba_engine::rules::Finding::new(tsuba_engine::rules::Severity::Medium, "install script", "package.json")];
    trust::ignore_command("npm install left-pad", &warning);
    assert!(trust::is_ignored_command("npm install left-pad", &warning));
    assert!(!trust::is_ignored_command("npm install other", &warning));
    let mut changed = warning.clone();
    changed.push(tsuba_engine::rules::Finding::new(tsuba_engine::rules::Severity::Medium, "new C2 address", "index.js"));
    assert!(!trust::is_ignored_command("npm install left-pad", &changed), "a different warning should not stay ignored");
    trust::remove("command:npm install left-pad");
    assert!(trust::list().is_empty());

    // Quarantine: a single file can be quarantined, restored and deleted
    let item = quarantine::quarantine(&script, "test").unwrap();
    assert!(!script.exists() && Path::new(&item.stored).is_file());
    quarantine::restore(&item.id).unwrap();
    assert!(script.is_file());
    let item = quarantine::quarantine(&script, "test").unwrap();
    quarantine::delete(&item.id).unwrap();
    assert!(!Path::new(&item.stored).exists() && quarantine::list().is_empty());
}

#[test]
fn folder_scan_picks_projects_and_skips_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("Online_Store");
    std::fs::create_dir_all(project.join(".vscode")).unwrap();
    std::fs::create_dir_all(project.join("node_modules/dep")).unwrap();
    std::fs::write(project.join("package.json"), "{}").unwrap();
    std::fs::write(project.join("node_modules/dep/install.sh"), RISKY_SCRIPT).unwrap();
    std::fs::create_dir_all(dir.path().join("photos")).unwrap();
    std::fs::write(dir.path().join("photos/a.png"), "x").unwrap();
    std::fs::write(dir.path().join("Zeff.dmg"), "x").unwrap();
    let (items, truncated) = scan::candidates(dir.path());
    let names: Vec<String> = items.iter().map(|p| p.strip_prefix(dir.path()).unwrap().display().to_string()).collect();
    assert_eq!(names, vec!["Online_Store", "Zeff.dmg"]);
    assert!(!truncated);
}

/// Fixture set acceptance: every inert malicious sample is caught and benign samples have zero false positives. This is how the missed "scan a folder of installer images" case was found.
#[test]
fn evaluation_on_fixtures_meets_targets() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let set = tempfile::tempdir().unwrap();
    for (sub, names) in [
        ("malicious", &["fake_interview_project", "malicious_extension", "vscode_autorun_project", "fake_meeting_volume", "poisoned_mcp_project", "poisoned_skill"][..]),
        ("benign", &["normal_extension", "normal_project"][..]),
    ] {
        std::fs::create_dir_all(set.path().join(sub)).unwrap();
        for n in names {
            std::os::unix::fs::symlink(fixtures.join(n), set.path().join(sub).join(n)).unwrap();
        }
    }
    let ev = tsuba_engine::evaluation::run(&Config::default(), set.path(), |_| {});
    let missed: Vec<_> = ev.missed().map(|s| s.name.clone()).collect();
    let fps: Vec<_> = ev.false_positives().map(|s| s.name.clone()).collect();
    assert!(missed.is_empty() && fps.is_empty(), "missed {missed:?}, false positives {fps:?}");
    assert!(ev.passes());
}
