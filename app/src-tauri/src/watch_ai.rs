//! Watches AI coding tools: new or changed MCP servers, skills and plugin hooks.

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

/// MCP servers and skills already seen: key → content fingerprint
#[derive(Clone)]
struct AiSeen(Arc<Mutex<HashMap<String, String>>>);

impl AiSeen {
    /// On the first run, mark everything present as seen and only check what is added or changed later. Existing ones can be scanned in Health Check
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

    /// Records the fingerprint and returns true when it differs from last time (or is new)
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

/// A file often changes several times in a row; wait until it settles before checking
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
    let title = tr!("{client} · {name} (MCP server)", client = s.client, name = s.name);
    let detail = s.command_line();
    two_phase(app, cfg, "ai_tool", &title, |c| {
        let findings = agents::scan_mcp_server(&s, c.intel.online_lookup);
        let evidence = json!({ "command": format!("(new MCP server) {detail}"), "targets": [{ "kind": "mcp_server", "server": s }], "findings": findings });
        tsuba_engine::judge_evidence(c, &evidence, findings)
    });
}

fn check_unit(app: &AppHandle, cfg: &Config, unit: &Path) {
    if tsuba_engine::trust::is_trusted_path(unit) {
        return;
    }
    let (info, findings) = agents::scan_unit(unit);
    // Skills get updated by syncing all the time: clean ones are not recorded and don't call the model
    if rules::offline_verdict(&findings) == Verdict::Allow {
        return;
    }
    let path = info["path"].as_str().unwrap_or("");
    let title = if info["kind"] == "hooks" { tr!("{path} (plugin hooks)", path = path) } else { tr!("{path} (skill)", path = path) };
    let evidence = json!({ "command": format!("(new or changed AI tool {}) {}", info["kind"], info["path"]), "targets": [{ "kind": "ai_skill", "info": info }], "findings": findings });
    two_phase(app, cfg, "ai_tool", &title, |c| tsuba_engine::judge_evidence(c, &evidence, findings.clone()));
}

pub fn start(app: &AppHandle, cfg: Arc<Mutex<Config>>, watchers: &mut Vec<RecommendedWatcher>) {
    let seen = AiSeen::load();
    let debounce = Debounce::default();

    // MCP config files: ~/.claude.json is written very often, so only check when a server's config really changed
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

    // Skill and plugin folders
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
