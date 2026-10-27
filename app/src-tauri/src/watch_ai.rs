//! 监控 AI 编程工具：新增或修改的 MCP server、skill、插件 hooks。

use crate::watch::{paused, two_phase};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::AppHandle;
use tsuba_engine::agents::{self, McpServer};
use tsuba_engine::rules::{self, Verdict};
use tsuba_engine::store::{self, Config};

/// 见过的 MCP server 和 skill：键 → 内容指纹
#[derive(Clone)]
struct AiSeen(Arc<Mutex<HashMap<String, String>>>);

impl AiSeen {
    /// 第一次运行时把现有的全部记为见过，只检查之后新出现或改动的。已有的可以在“体检”里扫描
    fn load() -> AiSeen {
        let v = store::load_json("ai_seen.json");
        let map: HashMap<String, String> = serde_json::from_value(v).unwrap_or_default();
        let seen = AiSeen(Arc::new(Mutex::new(map)));
        if !store::home().join("ai_seen.json").exists() {
            for s in agents::user_mcp_servers() {
                seen.changed(&format!("mcp:{}", s.key()), &s.fingerprint());
            }
            for u in agents::all_units() {
                seen.changed(&format!("unit:{}", u.display()), &agents::unit_fingerprint(&u));
            }
        }
        seen
    }

    /// 内容和上次不一样（或第一次见到）就记下来并返回 true
    fn changed(&self, key: &str, fp: &str) -> bool {
        let mut m = self.0.lock().unwrap();
        if m.get(key).map(String::as_str) == Some(fp) {
            return false;
        }
        m.insert(key.to_string(), fp.to_string());
        store::save_json("ai_seen.json", &json!(*m));
        true
    }
}

/// 同一个文件短时间内会连续变动多次，等安静下来再检查
#[derive(Clone, Default)]
struct Debounce(Arc<Mutex<HashSet<PathBuf>>>);

impl Debounce {
    fn run(&self, key: PathBuf, delay: Duration, f: impl FnOnce() + Send + 'static) {
        if !self.0.lock().unwrap().insert(key.clone()) {
            return;
        }
        let me = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            me.0.lock().unwrap().remove(&key);
            f();
        });
    }
}

fn check_server(app: &AppHandle, cfg: &Config, s: McpServer) {
    if tsuba_engine::trust::is_trusted_mcp(&s) {
        return;
    }
    let title = format!("{} · {}（MCP server）", s.client, s.name);
    let detail = s.command_line();
    two_phase(app, cfg, "ai_tool", &title, |c| {
        let findings = agents::scan_mcp_server(&s, c.intel.online_lookup);
        let evidence = json!({ "command": format!("(新增的 MCP server) {detail}"), "targets": [{ "kind": "mcp_server", "server": s }], "findings": findings });
        tsuba_engine::judge_evidence(c, &evidence, findings)
    });
}

fn check_unit(app: &AppHandle, cfg: &Config, unit: &Path) {
    if tsuba_engine::trust::is_trusted_path(unit) {
        return;
    }
    let (info, findings) = agents::scan_unit(unit);
    // skill 经常随着同步更新，没问题的不记录、不调用模型
    if rules::offline_verdict(&findings) == Verdict::Allow {
        return;
    }
    let title = format!("{}（{}）", info["path"].as_str().unwrap_or(""), if info["kind"] == "hooks" { "插件 hooks" } else { "skill" });
    let evidence = json!({ "command": format!("(新增或修改的 AI 工具 {}) {}", info["kind"], info["path"]), "targets": [{ "kind": "ai_skill", "info": info }], "findings": findings });
    two_phase(app, cfg, "ai_tool", &title, |c| tsuba_engine::judge_evidence(c, &evidence, findings.clone()));
}

pub fn start(app: &AppHandle, cfg: Arc<Mutex<Config>>, watchers: &mut Vec<RecommendedWatcher>) {
    let seen = AiSeen::load();
    let debounce = Debounce::default();

    // MCP 配置文件：~/.claude.json 写得很频繁，所以只在 server 的配置真的变了时才检查
    let configs: Vec<(String, PathBuf)> = agents::user_mcp_configs().into_iter().map(|(c, p)| (c.to_string(), p)).collect();
    let parents: HashSet<PathBuf> = configs.iter().filter_map(|(_, p)| p.parent().map(Path::to_path_buf)).filter(|p| p.is_dir()).collect();
    let (app2, cfg2, seen2, deb2, configs2) = (app.clone(), cfg.clone(), seen.clone(), debounce.clone(), configs.clone());
    if let Ok(mut w) = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(ev) = res else { return };
        for p in ev.paths {
            let Some((client, path)) = configs2.iter().find(|(_, c)| *c == p).cloned() else { continue };
            let (app3, cfg3, seen3) = (app2.clone(), cfg2.clone(), seen2.clone());
            deb2.run(path.clone(), Duration::from_secs(2), move || {
                if paused() {
                    return;
                }
                let cfg = cfg3.lock().unwrap().clone();
                for s in agents::parse_mcp_config(&client, &path) {
                    if seen3.changed(&format!("mcp:{}", s.key()), &s.fingerprint()) {
                        check_server(&app3, &cfg, s);
                    }
                }
            });
        }
    }) {
        for p in &parents {
            let _ = w.watch(p, RecursiveMode::NonRecursive);
        }
        watchers.push(w);
    }

    // skill 和插件目录
    let (app2, cfg2, seen2, deb2) = (app.clone(), cfg.clone(), seen.clone(), debounce.clone());
    if let Ok(mut w) = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(ev) = res else { return };
        for p in ev.paths {
            let Some(unit) = agents::unit_of(&p) else { continue };
            let (app3, cfg3, seen3) = (app2.clone(), cfg2.clone(), seen2.clone());
            deb2.run(unit.clone(), Duration::from_secs(3), move || {
                if paused() || !unit.exists() {
                    return;
                }
                if seen3.changed(&format!("unit:{}", unit.display()), &agents::unit_fingerprint(&unit)) {
                    let cfg = cfg3.lock().unwrap().clone();
                    check_unit(&app3, &cfg, &unit);
                }
            });
        }
    }) {
        for root in agents::skill_roots() {
            let _ = w.watch(&root, RecursiveMode::Recursive);
        }
        watchers.push(w);
    }
}
