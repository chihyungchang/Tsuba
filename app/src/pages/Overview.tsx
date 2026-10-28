import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { GuardianKatana } from "../brand";
import { Icon } from "../icons";
import { IntelManifest, LogEntry, Overview } from "../types";
import { Banner, Spinner, baseName, errText, formatCompact, formatNumber, relativeTime } from "../ui";
import { t } from "../i18n";

type Go = (page: "history" | "scan" | "doctor" | "settings") => void;

/** Short name of an entry: commands as-is (truncated), files by file name only */
const entryName = (e: LogEntry, max = 42) => (e.source === "terminal" || e.source === "paste" ? (e.title.length > max ? `${e.title.slice(0, max - 2)}…` : e.title) : baseName(e.title));

/** The log tag: quarantine first, then by verdict */
function logTag(e: LogEntry): { text: string; tone: string } {
  if (e.action === "quarantined") return { text: "QUAR", tone: "quar" };
  if (e.action === "deleted") return { text: "DEL", tone: "quar" };
  if (e.report.verdict === "block") return { text: "BLOCK", tone: "block" };
  if (e.report.verdict === "warn") return { text: "WARN", tone: "warn" };
  return { text: "PASS", tone: "pass" };
}

const LOG_OPEN_KEY = "tsuba-log-open";

/**
 * Terminal log at the bottom: the latest checks, one per line like command output; click a line for details.
 * Collapses to a single status line; whether it is collapsed is remembered on this Mac.
 */
function TermLog({ entries, status, openEntry, go }: { entries: LogEntry[]; status: { text: string; count: string; tone: string }; openEntry: (id: string) => void; go: Go }) {
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(LOG_OPEN_KEY) !== "0";
    } catch {
      return true;
    }
  });
  const toggle = () => {
    const next = !open;
    setOpen(next);
    try {
      localStorage.setItem(LOG_OPEN_KEY, next ? "1" : "0");
    } catch {
      // Not remembered: it just opens expanded next time
    }
  };
  return (
    <section className={`term-log ${open ? "is-open" : ""}`} aria-label={t("Recent checks")}>
      <div className="term-head">
        <button type="button" className="term-toggle" onClick={toggle} aria-expanded={open} title={open ? t("Hide log") : t("Show log")}>
          <Icon.chevron size={12} className="term-chevron" />
          <span className="term-prompt">tsuba ▸</span>
          <b className={`term-status tone-${status.tone}`}>{status.text}</b>
          <span className={`term-count tone-${status.tone}`}>{status.count}</span>
        </button>
        <button type="button" className="term-more" onClick={() => go("history")}>
          {t("All History →")}
        </button>
      </div>
      {/* Always rendered so opening and closing can animate the height; inert keeps hidden rows out of Tab order */}
      <div className="term-body" inert={!open}>
        <div className="term-lines">
          {entries.length === 0 && <div className="term-empty">{t("No checks yet. Once the terminal is connected, checked commands show up here.")}</div>}
          {entries.map((e) => {
            const tag = logTag(e);
            return (
              <button type="button" key={e.id} className="term-line" onClick={() => openEntry(e.id)}>
                <span className="term-time">{relativeTime(e.time, { short: true })}</span>
                <span className={`term-tag tag-${tag.tone}`}>{tag.text}</span>
                <span className="term-title">{entryName(e, 80)}</span>
                {e.report.summary && <span className="term-summary">· {e.report.summary}</span>}
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export function OverviewPage({
  overview,
  reload,
  onScanned,
  openEntry,
  go,
}: {
  overview: Overview | null;
  reload: () => void;
  onScanned: (e: LogEntry) => void;
  openEntry: (id: string) => void;
  go: Go;
}) {
  const [checking, setChecking] = useState("");
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [intel, setIntel] = useState<IntelManifest | null>(null);

  useEffect(() => {
    const load = () => invoke<LogEntry[]>("get_history", { limit: 200 }).then(setEntries);
    const loadIntel = () => invoke<IntelManifest>("intel_status").then(setIntel);
    load();
    loadIntel();
    const uns = [listen("history-updated", load), listen("intel-updated", loadIntel)];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, []);

  const check = async (path: string) => {
    setChecking(baseName(path));
    setError("");
    try {
      onScanned(await invoke<LogEntry>("scan_path", { path }));
    } catch (e) {
      setError(errText(e));
    } finally {
      setChecking("");
    }
  };

  // Anything dropped anywhere on the window gets checked
  useEffect(() => {
    const un = getCurrentWebview().onDragDropEvent((event) => {
      const p = event.payload;
      if (p.type === "enter" || p.type === "over") setDragging(true);
      else if (p.type === "leave") setDragging(false);
      else if (p.type === "drop") {
        setDragging(false);
        if (p.paths[0]) check(p.paths[0]);
      }
    });
    return () => {
      un.then((f) => f());
    };
    // check only depends on onScanned, so resubscribe only when it changes
  }, [onScanned]);

  if (!overview) return null;

  const setPaused = async (paused: boolean) => {
    setError("");
    try {
      await invoke("set_paused", { paused });
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };
  const pickAndCheck = async () => {
    const path = await invoke<string | null>("choose_folder");
    if (path) check(path);
  };

  const paused = overview.paused;
  const defenses = [
    { label: t("Terminal"), on: overview.shell_hook.installed },
    { label: t("Installers"), on: overview.watch_downloads },
    { label: t("Extensions"), on: overview.watch_extensions },
    { label: t("AI Coding Tools"), on: overview.watch_ai_tools },
  ];
  const active = defenses.filter((d) => d.on).length;
  const risky = entries.filter((e) => e.report.verdict !== "allow");
  const intelCount = intel?.sources.reduce((n, s) => n + s.count, 0) ?? 0;
  const status = paused
    ? { text: t("paused"), count: "0/4", tone: "block" }
    : { text: t("protected"), count: `${active}/4`, tone: active === 4 ? "allow" : "warn" };

  return (
    <>
      <div className={`dashboard ${dragging ? "is-dragging" : ""}`}>
        <section className={`dash-hero ${paused ? "is-paused" : active < defenses.length ? "is-partial" : ""}`} data-tauri-drag-region>
          <GuardianKatana paused={paused} partial={active < defenses.length} />
          <div className="dash-hero-text">
            {/* A quiet label, not a capsule: the checks below already say which defenses are on */}
            <span className="hero-status" role="status">
              {paused ? t("Unprotected") : active === defenses.length ? t("Guarding") : t("{active} of {total} defenses on", { active, total: defenses.length })}
            </span>
            <h1>{paused ? t("Active Defense Paused") : t("AI Active Defense")}</h1>
            <p className="dash-hero-lede">
              {paused ? t("The sword is sheathed: commands you run, installers you download, and new extensions and AI tools are not being checked. Resume as soon as you are done.") : t("Before unfamiliar code runs, offline rules and AI look at it for you: fake interview projects, fake meeting apps, poisoned packages and extensions, malicious MCP servers and skills.")}
            </p>
            {paused ? null : (
              <button type="button" className="layer-checks" onClick={() => go("settings")} title={t("Manage defenses in Settings")}>
                {defenses.map((d) => (
                  <span key={d.label} className={d.on ? "is-on" : "is-off"}>
                    {d.label}
                  </span>
                ))}
              </button>
            )}
            <div className="dash-hero-actions">
              {paused ? (
                <button className="cta cta-alarm" onClick={() => setPaused(false)}>
                  <Icon.play size={14} />
                  {t("Resume Protection")}
                </button>
              ) : (
                <button className="cta" disabled={!!checking} onClick={pickAndCheck}>
                  {checking ? <Spinner /> : <Icon.scan size={15} />}
                  {checking ? t("Checking {name}", { name: checking }) : t("Check a Folder")}
                </button>
              )}
              <span className="hero-links">
                <button className="link" onClick={() => go("scan")}>
                  {t("Scan")}
                </button>
                <button
                  className="link"
                  onClick={() => {
                    go("doctor");
                    window.dispatchEvent(new Event("tsuba-run-doctor"));
                  }}
                >
                  {t("Health Check")}
                </button>
                {paused ? (
                  <button className="link" onClick={() => go("settings")}>
                    {t("Settings")}
                  </button>
                ) : (
                  <button className="link" onClick={() => setPaused(true)}>
                    {t("Pause")}
                  </button>
                )}
              </span>
            </div>
            <div className="dash-hero-meta">{dragging ? t("Release to start checking") : t("You can also drag installers, project folders or scripts into the window")}</div>
          </div>
        </section>

        {error && <Banner onClose={() => setError("")}>{error}</Banner>}

        <section className="bento" aria-label={t("Summary")}>
          <button type="button" className={`cell cell-alert ${risky.length ? "" : "is-calm"}`} onClick={() => (risky[0] ? openEntry(risky[0].id) : go("history"))}>
            <span className="cell-go">{risky.length ? t("View →") : t("History →")}</span>
            <span className="cell-num">{risky.length}</span>
            <span className="cell-label">{risky.length === 0 ? t("No warnings to review") : t("Needs attention")}</span>
            {risky[0] && <span className="cell-last">{entryName(risky[0], 46)}</span>}
          </button>
          <button type="button" className="cell" onClick={() => go("history")}>
            <span className="cell-num">{formatNumber(overview.recent.total)}</span>
            <span className="cell-label">{overview.recent.total === 1 ? t("check") : t("checks")}</span>
          </button>
          <button type="button" className="cell" onClick={() => go("scan")}>
            <span className="cell-num">{overview.quarantined}</span>
            <span className="cell-label">{t("in quarantine")}</span>
          </button>
          <button type="button" className="cell cell-intel" onClick={() => go("settings")}>
            <span className="cell-num">{formatCompact(intelCount)}</span>
            <span className="cell-label">{intel?.updated ? t("Threat intel · updated {time}", { time: relativeTime(intel.updated) }) : t("Threat intel · not downloaded yet")}</span>
          </button>
        </section>
      </div>
      <TermLog entries={entries.slice(0, 3)} status={status} openEntry={openEntry} go={go} />
    </>
  );
}
