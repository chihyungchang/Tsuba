import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon } from "../icons";
import { Config, FolderScan, LogEntry, QuarantineItem, ScanHit, TrustItem } from "../types";
import { Banner, ConfirmButton, Empty, toastDone, FindingList, Group, PageHeader, Row, Section, Spinner, Toggle, VerdictBadge, baseName, errText, relativeTime, shortPath } from "../ui";

const KIND_LABEL: Record<ScanHit["kind"], string> = { installer: "安装包", extension: "扩展", skill: "AI skill", project: "项目", file: "脚本", trusted: "已信任" };
const KIND_ICON = { installer: "package", extension: "extension", skill: "plug", project: "folder", file: "terminal", trusted: "check" } as const;

export function ScanPage({ quarantine, reload, onScanned }: { quarantine: QuarantineItem[]; reload: () => void; onScanned: (e: LogEntry) => void }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [result, setResult] = useState<FolderScan | null>(null);
  const [busy, setBusy] = useState("");
  const [progress, setProgress] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [trusted, setTrusted] = useState<TrustItem[]>([]);
  const [last, setLast] = useState<string | null>(null);
  const [error, setError] = useState("");

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

  // 处理完一项就从结果里拿掉
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
        title="扫描"
        subtitle="下载目录、外接硬盘、代码目录里的安装包、脚本、扩展和项目。照片视频和依赖目录跳过。"
        icon="scan"
        tone={scanning ? "neutral" : result ? (result.hits.length ? "warn" : "allow") : "neutral"}
        status={scanning ? "正在扫描…" : result ? (result.hits.length ? `这次发现 ${result.hits.length} 个需要看的` : "这次没有发现问题") : last ? `上次定期扫描 ${relativeTime(last)}` : "还没有扫描过"}
        stats={[
          { label: "常用文件夹", value: cfg ? cfg.scan.folders.length : "—" },
          { label: "定期扫描", value: cfg ? (cfg.scan.scheduled ? `每 ${cfg.scan.interval_days} 天` : "已关闭") : "—" },
          { label: "隔离区", value: quarantine.length, tone: quarantine.length ? "warn" : undefined },
          { label: "白名单", value: trusted.length },
        ]}
      >
        <button className="primary" disabled={busy !== ""} onClick={pickAndScan}>
          <Icon.folder size={14} />
          选择文件夹…
        </button>
      </PageHeader>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      {(scanning || result) && (
        <Section title="扫描结果" aside={result && <span className="section-aside">{shortPath(result.root)}</span>}>
          {scanning && (
            <div className="progress-card">
              <Spinner />
              <div className="progress-text">
                <div>正在扫描</div>
                <div className="mono muted small ellipsis">{progress ? shortPath(progress) : "正在列出文件…"}</div>
              </div>
            </div>
          )}
          {result && (
            <>
              <div className="scan-summary">
                <span>
                  <strong>{result.checked}</strong> 个新检查
                </span>
                <span>
                  <strong>{result.unchanged}</strong> 个没变化，沿用上次结果
                </span>
                <span className={result.hits.length > 0 ? "tone-warn" : "tone-allow"}>
                  <strong>{result.hits.length}</strong> 个需要看一下
                </span>
                {result.truncated && <span className="muted">东西太多，只扫了前一部分</span>}
              </div>
              {result.hits.length === 0 ? (
                <Group>
                  <Empty icon="check" title="没有发现问题" />
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
                            {KIND_LABEL[h.kind]} · {shortPath(h.path)}
                          </div>
                          <FindingList findings={h.findings} />
                          <div className="toolbar">
                            <button className="primary" onClick={() => settle(h.path, "quarantine_path", { path: h.path, reason: h.summary })}>
                              移入隔离区
                            </button>
                            <button disabled={busy !== ""} onClick={() => run(async () => onScanned(await invoke<LogEntry>("scan_path", { path: h.path })), "deep")}>
                              {busy === "deep" ? "检查中…" : "让 AI 再看一遍"}
                            </button>
                            <button onClick={() => settle(h.path, "trust_item", { key: h.path })}>我确认它安全</button>
                            <button className="link" onClick={() => invoke("reveal_in_finder", { path: h.path })}>
                              在 Finder 中显示
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
          title="常用文件夹"
          aside={
            <button className="link" onClick={addFolder}>
              添加…
            </button>
          }
        >
          <Group>
            {cfg.scan.folders.length === 0 && <Empty icon="folder" title="还没有常用文件夹" />}
            {cfg.scan.folders.map((f) => (
              <Row
                key={f}
                icon="folder"
                title={baseName(shortPath(f)) || f}
                detail={<span className="mono">{shortPath(f)}</span>}
                trailing={
                  <>
                    <button disabled={busy !== ""} onClick={() => scanFolder(f)}>
                      {busy === `scan:${f}` ? "扫描中…" : "扫描"}
                    </button>
                    <button className="icon-button" aria-label="移除" title="从常用文件夹里移除" onClick={() => saveScan({ ...cfg.scan, folders: cfg.scan.folders.filter((x) => x !== f) })}>
                      ×
                    </button>
                  </>
                }
              />
            ))}
            <Row
              icon="refresh"
              title="定期扫描"
              detail={`每 ${cfg.scan.interval_days} 天用最新规则重扫一遍，找出规则更新后才认出来的老文件${last ? ` · 上次 ${relativeTime(last)}` : ""}`}
              trailing={<Toggle label="定期扫描" on={cfg.scan.scheduled} onChange={(v) => saveScan({ ...cfg.scan, scheduled: v })} />}
            />
          </Group>
        </Section>
      )}

      <Section title="隔离区" aside={quarantine.length > 0 && <span className="section-aside">{quarantine.length} 项</span>}>
        <Group>
          {quarantine.length === 0 ? (
            <Empty icon="lock" title="隔离区是空的">
              被判为高危的文件和扩展会挪到这里，随时可以恢复。
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
                    <button onClick={() => act("restore_quarantine", { id: q.id })}>恢复</button>
                    <ConfirmButton confirm="确认删除" onConfirm={() => act("delete_quarantine", { id: q.id })}>
                      删除
                    </ConfirmButton>
                  </>
                }
              />
            ))
          )}
        </Group>
      </Section>

      <Section title="白名单" aside={<span className="section-aside">按内容指纹记录，内容变了会重新检查</span>}>
        <Group>
          {trusted.length === 0 ? (
            <Empty icon="check" title="还没有标记过">
              误报的东西点“我确认它安全”，以后就不再提醒。
            </Empty>
          ) : (
            trusted.map((t) => (
              <Row
                key={t.key}
                icon="check"
                tone="allow"
                title={baseName(t.label)}
                detail={`${shortPath(t.label)} · ${relativeTime(t.time)}`}
                trailing={
                  <button className="link" onClick={() => act("untrust_item", { key: t.key })}>
                    移除
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
