import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon } from "../icons";
import { LogEntry, QuarantineItem, SandboxResult } from "../types";
import { BackLink, Banner, ConfirmButton, Empty, MenuButton, toast, toastDone, FindingList, ReportView, Spinner, VerdictBadge, baseName, errText, relativeTime, shortPath } from "../ui";
import { lang, t } from "../i18n";
import { useTask } from "../tasks";

/** Sources whose entry title is a path on disk: can be quarantined, marked safe and shown in Finder */
const PATH_SOURCES: LogEntry["source"][] = ["download", "extension", "scan"];
/** Sources whose entry title is a file on disk (disk images included), which can be deleted */
const FILE_SOURCES: LogEntry["source"][] = [...PATH_SOURCES, "mount"];
const isCommand = (e: LogEntry) => e.source === "terminal" || e.source === "paste";

/** Secret kinds are stored as English IDs (see sandbox::secret_label); old records hold Chinese names, shown as they are */
function secretLabel(kind: string): string {
  const labels: Record<string, string> = {
    "OpenAI / Anthropic API key": t("OpenAI / Anthropic API key"),
    "AWS access key": t("AWS access key"),
    "GitHub token": t("GitHub token"),
    "Google API key": t("Google API key"),
    "Slack token": t("Slack token"),
    "npm token": t("npm token"),
    "private key": t("private key"),
  };
  return labels[kind] ?? kind;
}

// Built at render time so the labels follow the current language
function sourceLabel(source: LogEntry["source"]): string {
  switch (source) {
    case "terminal":
      return t("Terminal Command");
    case "paste":
      return t("Pasted Command");
    case "download":
      return t("Download");
    case "mount":
      return t("Opened Disk Image");
    case "extension":
      return t("Editor Extension");
    case "ai_tool":
      return t("AI Tool");
    case "scan":
      return t("Manual Check");
  }
}

/** What happened to the entry; empty for a plain scan */
function actionLabel(action: string): string {
  switch (action) {
    case "executed":
      return t("Ran");
    case "cancelled":
      return t("Cancelled");
    case "quarantined":
      return t("Quarantined");
    case "ejected":
      return t("Blocked from Opening");
    case "notified":
      return t("Warned");
    case "allowed":
      return t("Allowed");
    case "deleted":
      return t("Deleted");
    default:
      return "";
  }
}

const listSeparator = () => (lang() === "zh-Hans" ? "、" : ", ");

function dayLabel(iso: string): string {
  const time = new Date(iso.replace(" ", "T"));
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86400_000);
  if (time.toDateString() === today.toDateString()) return t("Today");
  if (time.toDateString() === yesterday.toDateString()) return t("Yesterday");
  return t("Earlier");
}

function SandboxPanel({ r }: { r: SandboxResult }) {
  const b = r.behavior;
  const denied = b.denied ?? [];
  const nothing = b.network.length === 0 && b.new_files.length === 0 && denied.length === 0 && r.findings.length === 0;
  return (
    <div className="sandbox">
      <div className="sandbox-head">
        <h3>{t("What the Sandbox Saw")}</h3>
        <span className="muted small">
          {t("Ran for {seconds} s", { seconds: b.seconds.toFixed(1) })}
          {b.timed_out ? ` · ${t("stopped at the time limit")}` : ""}
        </span>
      </div>
      {nothing && <p className="muted">{t("This run made no network requests and wrote no files. Seeing nothing bad does not prove it is safe.")}</p>}
      {b.network.length > 0 && (
        <div className="sandbox-block">
          <div className="sandbox-label">{t("Network Requests")}</div>
          <ul className="sandbox-list">
            {b.network.map((e, i) => (
              <li key={i}>
                <span className="mono">{e.target}</span>
                {e.forwarded && <span className="muted small"> {t("official npm registry, allowed")}</span>}
                {e.leaked && e.leaked.length > 0 && <span className="tone-block small"> {t("sent decoy data: {items}", { items: e.leaked.join(listSeparator()) })}</span>}
                {e.secrets && e.secrets.length > 0 && <span className="tone-block small"> {t("request appears to carry {items}", { items: e.secrets.map(secretLabel).join(listSeparator()) })}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {b.new_files.length > 0 && (
        <div className="sandbox-block">
          <div className="sandbox-label">{t("New Files")}</div>
          <ul className="sandbox-list">
            {b.new_files.map((f) => (
              <li key={f} className="mono">
                {f}
              </li>
            ))}
          </ul>
        </div>
      )}
      {denied.length > 0 && (
        <div className="sandbox-block">
          <div className="sandbox-label">{t("Blocked by the Sandbox")}</div>
          <ul className="sandbox-list">
            {denied.slice(0, 12).map((d, i) => (
              <li key={i}>
                {d.process} <span className="muted small">{d.operation}</span> <span className="mono">{d.target}</span>
              </li>
            ))}
            {denied.length > 12 && <li className="muted small">{t("{n} more", { n: denied.length - 12 })}</li>}
          </ul>
        </div>
      )}
      {r.findings.length > 0 && <FindingList findings={r.findings} />}
    </div>
  );
}

/** "Ran in <dir>": the directory sits at a different place in each language, so split the sentence around it */
function RanIn({ dir }: { dir: string }) {
  const [before, after = ""] = t("Ran in {dir}").split("{dir}");
  return (
    <div className="detail-cwd">
      {before}
      <span className="mono">{dir}</span>
      {after}
    </div>
  );
}

/** Needs a look: not allowed, and not ignored by the user */
function isRisky(e: LogEntry) {
  return e.report.verdict !== "allow" && !e.dismissed;
}

export function HistoryPage({ focusId, quarantine, reload }: { focusId: string | null; quarantine: QuarantineItem[]; reload: () => void }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [selected, setSelected] = useState<string | null>(focusId);
  const [filter, setFilter] = useState<"risky" | "all">("risky");
  const [error, setError] = useState("");
  const [sandbox, setSandbox] = useState<SandboxResult | null>(null);
  const [sandboxing, setSandboxing] = useState(false);
  useTask("sandbox", t("Sandbox run"), "history", sandboxing);

  useEffect(() => {
    setSandbox(null);
    setError("");
  }, [selected]);

  const load = useCallback(() => {
    invoke<LogEntry[]>("get_history", { limit: 500 }).then(setEntries);
  }, []);

  useEffect(() => {
    load();
    const un = listen("history-updated", load);
    return () => {
      un.then((f) => f());
    };
  }, [load]);

  useEffect(() => {
    if (focusId) {
      setSelected(focusId);
      setFilter("all");
    }
  }, [focusId]);

  const shown = useMemo(() => entries.filter((e) => filter === "all" || isRisky(e)), [entries, filter]);
  const groups = useMemo(() => {
    const out: { label: string; items: LogEntry[] }[] = [];
    for (const e of shown) {
      const label = dayLabel(e.time);
      const last = out[out.length - 1];
      if (last?.label === label) last.items.push(e);
      else out.push({ label, items: [e] });
    }
    return out;
  }, [shown]);
  const current = entries.find((e) => e.id === selected) ?? shown[0];
  const qItem = current?.quarantine_id ? quarantine.find((q) => q.id === current.quarantine_id) : undefined;
  const risky = entries.filter(isRisky).length;

  const act = async (cmd: string, args: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      toastDone(cmd);
      reload();
      load();
      return true;
    } catch (e) {
      setError(errText(e));
      return false;
    }
  };

  const setDismissed = async (id: string, dismissed: boolean) => {
    if (await act("set_entry_dismissed", { entryId: id, dismissed })) toast(dismissed ? t("Ignored. It stays in history but no longer counts as risky.") : t("Back in the risky list"));
  };

  const runSandbox = async (path: string, install = false) => {
    setSandboxing(true);
    setSandbox(null);
    setError("");
    try {
      setSandbox(await invoke<SandboxResult>("sandbox_script", { path, install }));
    } catch (e) {
      setError(errText(e));
    } finally {
      setSandboxing(false);
    }
  };

  // Up and down arrows move between entries, like a mail list
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.target instanceof HTMLInputElement || (ev.key !== "ArrowDown" && ev.key !== "ArrowUp")) return;
      const i = shown.findIndex((e) => e.id === current?.id);
      const next = shown[i + (ev.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        ev.preventDefault();
        setSelected(next.id);
        document.getElementById(`entry-${next.id}`)?.scrollIntoView({ block: "nearest" });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [shown, current]);

  const isDeleted = current?.action === "deleted";
  const isScript = current && !isDeleted && /\.(sh|command|bash|zsh|py)$/.test(current.title);
  const isFolder = current && !isDeleted && current.source === "scan" && !/\.[A-Za-z0-9]+\/?$/.test(current.title);

  return (
    <div className="split">
      <aside className="list-pane">
        <div className="list-head" data-tauri-drag-region>
          <BackLink />
          <h1 data-tauri-drag-region>{t("History")}</h1>
          <div className="segmented" role="tablist">
            <button role="tab" aria-selected={filter === "risky"} className={filter === "risky" ? "on" : ""} onClick={() => setFilter("risky")}>
              {t("Risky")}{risky > 0 && <span className="segmented-count">{risky}</span>}
            </button>
            <button role="tab" aria-selected={filter === "all"} className={filter === "all" ? "on" : ""} onClick={() => setFilter("all")}>
              {t("All")}
            </button>
          </div>
        </div>
        <div className="list-scroll">
          {shown.length === 0 && (
            <Empty icon="check" title={filter === "risky" ? t("Nothing Needs Attention") : t("No Checks Yet")}>
              {filter === "risky" ? t("Risky commands, downloads and extensions show up here.") : t("Once the terminal is connected, checked commands show up here.")}
            </Empty>
          )}
          {groups.map((g) => (
            <div key={g.label}>
              <div className="list-group-label">{g.label}</div>
              {g.items.map((e) => (
                <button
                  key={e.id}
                  id={`entry-${e.id}`}
                  className={`list-item verdict-${e.report.verdict} ${e.dismissed ? "is-dismissed" : ""} ${current?.id === e.id ? "selected" : ""}`}
                  onClick={() => setSelected(e.id)}
                >
                  <span className="list-item-bar" />
                  <div className="list-item-body">
                    <div className={`list-item-title ${isCommand(e) ? "mono" : ""}`}>{isCommand(e) ? e.title : baseName(e.title)}</div>
                    <div className="list-item-meta">
                      <span>{sourceLabel(e.source)}</span>
                      {e.dismissed ? <span>{t("Ignored")}</span> : actionLabel(e.action) && <span>{actionLabel(e.action)}</span>}
                      <span className="list-item-time">{relativeTime(e.time, { short: true })}</span>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ))}
        </div>
        {entries.length > 0 && (
          <div className="list-foot">
            <span className="muted small">{entries.length === 1 ? t("1 entry") : t("{n} entries", { n: entries.length })}</span>
            <ConfirmButton className="link" confirm={t("Click Again to Clear")} onConfirm={() => act("clear_history", {})}>
              {t("Clear History")}
            </ConfirmButton>
          </div>
        )}
      </aside>

      <main className="detail-pane">
        <div className="detail-drag" data-tauri-drag-region />
        {current ? (
          <article className="detail" key={current.id}>
            <div className="detail-head">
              <VerdictBadge v={current.report.verdict} large />
              <span className="detail-meta">
                {sourceLabel(current.source)} · {current.time.replace("T", " ").slice(0, 16)}
                {actionLabel(current.action) ? ` · ${actionLabel(current.action)}` : ""}
              </span>
            </div>
            {isCommand(current) ? (
              <pre className="command">{current.title}</pre>
            ) : (
              <div className="detail-title">
                <h2>{baseName(current.title)}</h2>
                {PATH_SOURCES.includes(current.source) && <div className="mono muted small">{shortPath(current.title)}</div>}
              </div>
            )}
            {current.cwd && <RanIn dir={shortPath(current.cwd)} />}

            {error && <Banner onClose={() => setError("")}>{error}</Banner>}

            <div className="toolbar">
              {qItem && (
                <>
                  <span className="toolbar-note">
                    <Icon.lock size={14} /> {t("Moved to Quarantine")}
                  </span>
                  <button onClick={() => act("restore_quarantine", { id: qItem.id })}>{t("Restore")}</button>
                  <ConfirmButton confirm={t("Confirm Permanent Delete")} onConfirm={() => act("delete_quarantine", { id: qItem.id })}>
                    {t("Delete Permanently")}
                  </ConfirmButton>
                </>
              )}
              {isDeleted && (
                <span className="toolbar-note">
                  <Icon.trash size={14} /> {t("File Deleted")}
                </span>
              )}
              {!qItem && !isDeleted && PATH_SOURCES.includes(current.source) && current.report.verdict !== "allow" && current.action !== "quarantined" && (
                <>
                  <button className="primary" onClick={() => act("quarantine_path", { path: current.title, reason: current.report.summary, entryId: current.id })}>
                    {t("Move to Quarantine")}
                  </button>
                  <button
                    onClick={async () => {
                      // A file marked safe is settled, so it leaves the risky list too
                      if (await act("trust_item", { key: current.title })) await invoke("set_entry_dismissed", { entryId: current.id, dismissed: true }).catch(() => {});
                    }}
                  >
                    {t("Mark as Safe")}
                  </button>
                </>
              )}
              {isCommand(current) && current.report.verdict === "warn" && !current.dismissed && (
                <button title={t("Runs without asking next time, unless the check finds something different")} onClick={() => act("ignore_command_warning", { entryId: current.id })}>
                  {t("Don't Warn Again")}
                </button>
              )}
              {current.report.verdict !== "allow" &&
                (current.dismissed ? (
                  <span className="toolbar-note">
                    <Icon.check size={14} /> {t("Ignored")}
                    <button className="link" onClick={() => setDismissed(current.id, false)}>
                      {t("Undo")}
                    </button>
                  </span>
                ) : (
                  <button title={t("Keeps the record but stops counting it as risky")} onClick={() => setDismissed(current.id, true)}>
                    {t("Ignore")}
                  </button>
                ))}
              {current.source === "scan" && isScript && (
                <button disabled={sandboxing} onClick={() => runSandbox(current.title)}>
                  {sandboxing ? <Spinner /> : null}
                  {sandboxing ? t("Running in Sandbox") : t("Try in Sandbox")}
                </button>
              )}
              {/* Two ways to try a project share one slot: running it and installing its dependencies */}
              {isFolder && (
                <MenuButton
                  disabled={sandboxing}
                  label={
                    <>
                      {sandboxing ? <Spinner /> : null}
                      {sandboxing ? t("Running in Sandbox") : t("Try in Sandbox")}
                    </>
                  }
                  items={[
                    { label: t("Run the Project"), detail: t("Starts it and watches what it reads, writes and connects to"), onSelect: () => runSandbox(current.title) },
                    { label: t("Install Dependencies"), detail: t("Runs npm install to see what the install scripts do"), onSelect: () => runSandbox(current.title, true) },
                  ]}
                />
              )}
              {/* Finder and delete are icons at the far right: delete stays apart from the other buttons and asks twice */}
              {FILE_SOURCES.includes(current.source) && !qItem && !isDeleted && (
                <span className="toolbar-end">
                  <button className="icon-button" aria-label={t("Show in Finder")} title={t("Show in Finder")} onClick={() => invoke("reveal_in_finder", { path: current.title })}>
                    <Icon.folder size={15} />
                  </button>
                  <ConfirmButton className="icon-button danger" label={t("Delete File")} confirm={t("Click Again to Delete Permanently")} onConfirm={() => act("delete_entry_file", { entryId: current.id })}>
                    <Icon.trash size={15} />
                  </ConfirmButton>
                </span>
              )}
            </div>

            {sandbox && <SandboxPanel r={sandbox} />}
            <ReportView report={current.report} />
          </article>
        ) : (
          <Empty icon="history" title={t("Select an Entry")}>
            {t("Pick one on the left to see why Tsuba decided what it did.")}
          </Empty>
        )}
      </main>
    </div>
  );
}
