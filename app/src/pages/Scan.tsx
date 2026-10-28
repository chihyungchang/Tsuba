import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon } from "../icons";
import { Config, FolderScan, LogEntry, QuarantineItem, ScanHit, TrustItem } from "../types";
import { Banner, ConfirmButton, Empty, toastDone, FindingList, Group, PageHeader, Row, Section, Spinner, Toggle, VerdictBadge, baseName, errText, relativeTime, shortPath } from "../ui";
import { t } from "../i18n";
import { useTask } from "../tasks";

function kindLabel(kind: ScanHit["kind"]): string {
  switch (kind) {
    case "installer":
      return t("Installer");
    case "extension":
      return t("Extension");
    case "skill":
      return t("AI skill");
    case "project":
      return t("Project");
    case "file":
      return t("Script");
    case "trusted":
      return t("Trusted");
  }
}
const KIND_ICON = { installer: "package", extension: "extension", skill: "plug", project: "folder", file: "terminal", trusted: "check" } as const;

const everyDays = (days: number) => (days === 1 ? t("Every day") : t("Every {n} days", { n: days }));

export function ScanPage({ quarantine, reload, onScanned }: { quarantine: QuarantineItem[]; reload: () => void; onScanned: (e: LogEntry) => void }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [result, setResult] = useState<FolderScan | null>(null);
  const [busy, setBusy] = useState("");
  const [progress, setProgress] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [trusted, setTrusted] = useState<TrustItem[]>([]);
  const [last, setLast] = useState<string | null>(null);
  const [error, setError] = useState("");
  useTask("scan", t("Folder scan"), "scan", !!busy);

  const load = useCallback(() => {
    invoke<Config>("get_config").then(setCfg);
    invoke<TrustItem[]>("trusted_list").then(setTrusted);
    invoke<{ last: string | null }>("scan_schedule_status").then((s) => setLast(s.last));
  }, []);

  useEffect(() => {
    load();
    const uns = [listen("status-changed", load), listen<string>("scan-progress", (e) => setProgress(e.payload))];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, [load]);

  const run = async (fn: () => Promise<void>, label = "") => {
    setError("");
    setBusy(label);
    try {
      await fn();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy("");
      setProgress("");
    }
  };

  const scanFolder = (path: string) =>
    run(async () => {
      setResult(null);
      setOpen(null);
      setResult(await invoke<FolderScan>("scan_folder", { path }));
    }, `scan:${path}`);

  const pickAndScan = () =>
    run(async () => {
      const path = await invoke<string | null>("choose_folder");
      if (!path) return;
      setBusy(`scan:${path}`);
      setResult(null);
      setOpen(null);
      setResult(await invoke<FolderScan>("scan_folder", { path }));
    }, "pick");

  const saveScan = (scan: Config["scan"]) =>
    run(async () => {
      if (!cfg) return;
      const next = { ...cfg, scan };
      await invoke("save_config", { config: next });
      setCfg(next);
    });

  const addFolder = () =>
    run(async () => {
      const path = await invoke<string | null>("choose_folder");
      if (path && cfg && !cfg.scan.folders.includes(path)) await saveScan({ ...cfg.scan, folders: [...cfg.scan.folders, path] });
    });

  // Once an item is handled, drop it from the results
  const settle = (path: string, cmd: "quarantine_path" | "trust_item", args: Record<string, unknown>) =>
    run(async () => {
      await invoke(cmd, args);
      toastDone(cmd);
      setResult((r) => (r ? { ...r, hits: r.hits.filter((h) => h.path !== path) } : r));
      reload();
      load();
    });

  const act = (cmd: string, args: Record<string, unknown>) =>
    run(async () => {
      await invoke(cmd, args);
      toastDone(cmd);
      reload();
      load();
    });

  const scanning = busy.startsWith("scan:") || busy === "pick";

  return (
    <div className="page">
      <PageHeader
        title={t("Scan")}
        subtitle={t("Installers, scripts, extensions and projects in Downloads, external drives and code folders. Photos, videos and dependency folders are skipped.")}
        icon="scan"
        tone={scanning ? "neutral" : result ? (result.hits.length ? "warn" : "allow") : "neutral"}
        status={scanning ? t("Scanning…") : result ? (result.hits.length === 0 ? t("Nothing found this time") : result.hits.length === 1 ? t("Found 1 item to review") : t("Found {n} items to review", { n: result.hits.length })) : last ? t("Last scheduled scan {time}", { time: relativeTime(last) }) : t("Not scanned yet")}
        stats={[
          { label: t("Favorite Folders"), value: cfg ? cfg.scan.folders.length : "—" },
          { label: t("Scheduled Scan"), value: cfg ? (cfg.scan.scheduled ? everyDays(cfg.scan.interval_days) : t("Off")) : "—" },
          { label: t("Quarantine"), value: quarantine.length, tone: quarantine.length ? "warn" : undefined },
          { label: t("Allowlist"), value: trusted.length },
        ]}
      >
        <button className="primary" disabled={busy !== ""} onClick={pickAndScan}>
          <Icon.folder size={14} />
          {t("Choose Folder…")}
        </button>
      </PageHeader>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      {(scanning || result) && (
        <Section title={t("Scan Results")} aside={result && <span className="section-aside">{shortPath(result.root)}</span>}>
          {scanning && (
            <div className="progress-card">
              <Spinner />
              <div className="progress-text">
                <div>{t("Scanning")}</div>
                <div className="mono muted small ellipsis">{progress ? shortPath(progress) : t("Listing files…")}</div>
              </div>
            </div>
          )}
          {result && (
            <>
              <div className="scan-summary">
                <span>
                  <strong>{result.checked}</strong> {t("newly checked")}
                </span>
                <span>
                  <strong>{result.unchanged}</strong> {t("unchanged, last results reused")}
                </span>
                <span className={result.hits.length > 0 ? "tone-warn" : "tone-allow"}>
                  <strong>{result.hits.length}</strong> {t("worth a look")}
                </span>
                {result.truncated && <span className="muted">{t("Too many files: only the first part was scanned")}</span>}
              </div>
              {result.hits.length === 0 ? (
                <Group>
                  <Empty icon="check" title={t("No Problems Found")} />
                </Group>
              ) : (
                <Group>
                  {result.hits.map((h) => (
                    <Row
                      key={h.path}
                      icon={KIND_ICON[h.kind]}
                      tone={h.verdict === "block" ? "block" : "warn"}
                      title={baseName(h.path)}
                      detail={h.summary}
                      trailing={
                        <>
                          <VerdictBadge v={h.verdict} />
                          <Icon.chevron size={14} className={`chevron ${open === h.path ? "is-open" : ""}`} />
                        </>
                      }
                      onClick={() => setOpen(open === h.path ? null : h.path)}
                    >
                      {open === h.path && (
                        <div className="row-expand">
                          <div className="mono muted small">
                            {kindLabel(h.kind)} · {shortPath(h.path)}
                          </div>
                          <FindingList findings={h.findings} />
                          <div className="toolbar">
                            <button className="primary" onClick={() => settle(h.path, "quarantine_path", { path: h.path, reason: h.summary })}>
                              {t("Move to Quarantine")}
                            </button>
                            <button disabled={busy !== ""} onClick={() => run(async () => onScanned(await invoke<LogEntry>("scan_path", { path: h.path })), "deep")}>
                              {busy === "deep" ? t("Checking…") : t("Ask AI to Recheck")}
                            </button>
                            <button onClick={() => settle(h.path, "trust_item", { key: h.path })}>{t("Mark as Safe")}</button>
                            <button className="link" onClick={() => invoke("reveal_in_finder", { path: h.path })}>
                              {t("Show in Finder")}
                            </button>
                          </div>
                        </div>
                      )}
                    </Row>
                  ))}
                </Group>
              )}
            </>
          )}
        </Section>
      )}

      {cfg && (
        <Section
          title={t("Favorite Folders")}
          aside={
            <button className="link" onClick={addFolder}>
              {t("Add…")}
            </button>
          }
        >
          <Group>
            {cfg.scan.folders.length === 0 && <Empty icon="folder" title={t("No Favorite Folders Yet")} />}
            {cfg.scan.folders.map((f) => (
              <Row
                key={f}
                icon="folder"
                title={baseName(shortPath(f)) || f}
                detail={<span className="mono">{shortPath(f)}</span>}
                trailing={
                  <>
                    <button disabled={busy !== ""} onClick={() => scanFolder(f)}>
                      {busy === `scan:${f}` ? t("Scanning…") : t("Scan")}
                    </button>
                    <button className="icon-button" aria-label={t("Remove")} title={t("Remove from favorite folders")} onClick={() => saveScan({ ...cfg.scan, folders: cfg.scan.folders.filter((x) => x !== f) })}>
                      ×
                    </button>
                  </>
                }
              />
            ))}
            <Row
              icon="refresh"
              title={t("Scheduled Scan")}
              detail={`${t("Rescans with the latest rules to catch old files that only newer rules recognize")} · ${everyDays(cfg.scan.interval_days)}${last ? ` · ${t("last {time}", { time: relativeTime(last) })}` : ""}`}
              trailing={<Toggle label={t("Scheduled Scan")} on={cfg.scan.scheduled} onChange={(v) => saveScan({ ...cfg.scan, scheduled: v })} />}
            />
          </Group>
        </Section>
      )}

      <Section title={t("Quarantine")} aside={quarantine.length > 0 && <span className="section-aside">{quarantine.length === 1 ? t("1 item") : t("{n} items", { n: quarantine.length })}</span>}>
        <Group>
          {quarantine.length === 0 ? (
            <Empty icon="lock" title={t("Quarantine Is Empty")}>
              {t("High-risk files and extensions are moved here. You can restore them at any time.")}
            </Empty>
          ) : (
            quarantine.map((q) => (
              <Row
                key={q.id}
                icon="lock"
                tone="block"
                title={baseName(q.original)}
                detail={`${relativeTime(q.time)} · ${q.reason}`}
                trailing={
                  <>
                    <button onClick={() => act("restore_quarantine", { id: q.id })}>{t("Restore")}</button>
                    <ConfirmButton confirm={t("Confirm Delete")} onConfirm={() => act("delete_quarantine", { id: q.id })}>
                      {t("Delete")}
                    </ConfirmButton>
                  </>
                }
              />
            ))
          )}
        </Group>
      </Section>

      <Section title={t("Allowlist")} aside={<span className="section-aside">{t("Recorded by content fingerprint; checked again if the content changes")}</span>}>
        <Group>
          {trusted.length === 0 ? (
            <Empty icon="check" title={t("Nothing Marked Yet")}>
              {t("Click “Mark as Safe” on a false alarm and Tsuba will not warn about it again.")}
            </Empty>
          ) : (
            trusted.map((item) => (
              <Row
                key={item.key}
                icon="check"
                tone="allow"
                title={baseName(item.label)}
                detail={`${shortPath(item.label)} · ${relativeTime(item.time)}`}
                trailing={
                  <button className="link" onClick={() => act("untrust_item", { key: item.key })}>
                    {t("Remove")}
                  </button>
                }
              />
            ))
          )}
        </Group>
      </Section>
    </div>
  );
}
