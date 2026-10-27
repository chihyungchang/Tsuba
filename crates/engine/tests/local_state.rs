//! 白名单、隔离区、文件夹扫描：都读写 ~/.tsuba，单独一个测试程序，把 TSUBA_HOME 指到临时目录。

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
    // 这个测试程序里只有它读写本机存储，不会和别的测试抢环境变量
    unsafe { std::env::set_var("TSUBA_HOME", home.path()) };
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("install.sh");
    std::fs::write(&script, RISKY_SCRIPT).unwrap();
    std::fs::write(dir.path().join("photo.jpg"), "not code").unwrap();
    let cfg = offline();

    // 文件夹扫描：只挑脚本，跳过照片；第二次扫没变化的沿用结果
    let r = scan::scan_folder(&cfg, dir.path(), |_| {});
    assert_eq!((r.checked, r.unchanged), (1, 0));
    assert_eq!(r.hits.len(), 1);
    assert!(r.hits[0].verdict >= Verdict::Warn, "删除隔离标记的脚本应被标出");
    let again = scan::scan_folder(&cfg, dir.path(), |_| {});
    assert_eq!((again.checked, again.unchanged, again.hits.len()), (0, 1, 1));
    assert!(!again.hits[0].fresh);

    // 白名单：标记安全后放行；内容一变就重新检查
    assert_ne!(tsuba_engine::evaluate_path(&cfg, &script).2.verdict, Verdict::Allow);
    trust::trust_path(&script).unwrap();
    assert_eq!(tsuba_engine::evaluate_path(&cfg, &script).2.verdict, Verdict::Allow);
    std::fs::write(&script, format!("{RISKY_SCRIPT}# changed\n")).unwrap();
    assert!(!trust::is_trusted_path(&script), "内容变了不应再信任");
    assert_ne!(tsuba_engine::evaluate_path(&cfg, &script).2.verdict, Verdict::Allow);
    trust::remove(&trust::list()[0].key);
    assert!(trust::list().is_empty());

    // 隔离区：单个文件也能隔离、恢复、删除
    let item = quarantine::quarantine(&script, "测试").unwrap();
    assert!(!script.exists() && Path::new(&item.stored).is_file());
    quarantine::restore(&item.id).unwrap();
    assert!(script.is_file());
    let item = quarantine::quarantine(&script, "测试").unwrap();
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

/// 样本集验收：现有惰性样本全部检出、正常样本零误报。漏掉的“扫描安装镜像文件夹”就是这样发现的。
#[test]
fn evaluation_on_fixtures_meets_targets() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let set = tempfile::tempdir().unwrap();
    for (sub, names) in [
        ("malicious", &["fake_interview_project", "malicious_extension", "vscode_autorun_project", "fake_meeting_volume"][..]),
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
    assert!(missed.is_empty() && fps.is_empty(), "漏报 {missed:?}，误报 {fps:?}");
    assert!(ev.passes());
}
