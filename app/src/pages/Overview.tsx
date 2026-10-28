import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { TsubaRing } from "../brand";
import { Icon } from "../icons";
import { IntelManifest, LogEntry, Overview } from "../types";
import { Banner, Spinner, baseName, errText, relativeTime } from "../ui";

type Go = (page: "history" | "scan" | "doctor" | "settings") => void;

/** 记录的简称：命令原样显示（截断），文件只显示文件名 */
const entryName = (e: LogEntry, max = 42) => (e.source === "terminal" || e.source === "paste" ? (e.title.length > max ? `${e.title.slice(0, max - 2)}…` : e.title) : baseName(e.title));

/** 日志里的标签：隔离优先，其次按结论 */
function logTag(e: LogEntry): { text: string; tone: string } {
  if (e.action === "quarantined") return { text: "QUAR", tone: "quar" };
  if (e.action === "deleted") return { text: "DEL", tone: "quar" };
  if (e.report.verdict === "block") return { text: "BLOCK", tone: "block" };
  if (e.report.verdict === "warn") return { text: "WARN", tone: "warn" };
  return { text: "PASS", tone: "pass" };
}

const LOG_OPEN_KEY = "tsuba-log-open";

/**
 * 底部的终端日志：最近几条检查，像命令行输出一样一行一条，点一行看详情。
 * 可以收起成一行状态；收起与否记在本机。
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
    setOpen(!open);
    try {
      localStorage.setItem(LOG_OPEN_KEY, open ? "0" : "1");
    } catch {
      // 记不住只是下次默认展开
    }
  };
  return (
    <section className={`term-log ${open ? "is-open" : ""}`} aria-label="最近的检查">
      <div className="term-head">
        <button type="button" className="term-toggle" onClick={toggle} aria-expanded={open} title={open ? "收起日志" : "展开日志"}>
          <Icon.chevron size={12} className="term-chevron" />
          <span className="term-prompt">tsuba ▸</span>
          <b className={`term-status tone-${status.tone}`}>{status.text}</b>
          <span className={`term-count tone-${status.tone}`}>{status.count}</span>
        </button>
        <button type="button" className="term-more" onClick={() => go("history")}>
          全部记录 →
        </button>
      </div>
      {open && (
        <div className="term-lines">
          {entries.length === 0 && <div className="term-empty">还没有检查记录。接入终端后，检查过的命令会出现在这里。</div>}
          {entries.map((e) => {
            const tag = logTag(e);
            return (
              <button type="button" key={e.id} className="term-line" onClick={() => openEntry(e.id)}>
                <span className="term-time">{relativeTime(e.time)}</span>
                <span className={`term-tag tag-${tag.tone}`}>{tag.text}</span>
                <span className="term-title">{entryName(e, 80)}</span>
                {e.report.summary && <span className="term-summary">· {e.report.summary}</span>}
              </button>
            );
          })}
        </div>
      )}
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

  // 整个窗口都可以拖进来检查
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
    // check 只用到 onScanned，所以只在它变化时重新订阅
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
    { label: "终端命令", on: overview.shell_hook.installed },
    { label: "安装包", on: overview.watch_downloads },
    { label: "编辑器扩展", on: overview.watch_extensions },
    { label: "AI 编程工具", on: overview.watch_ai_tools },
  ];
  const active = defenses.filter((d) => d.on).length;
  const risky = entries.filter((e) => e.report.verdict !== "allow");
  const intelCount = intel?.sources.reduce((n, s) => n + s.count, 0) ?? 0;
  const status = paused
    ? { text: "已暂停", count: "0/4", tone: "block" }
    : { text: "守护中", count: `${active}/4`, tone: active === 4 ? "allow" : "warn" };

  return (
    <>
      <div className={`dashboard ${dragging ? "is-dragging" : ""}`}>
        <section className={`dash-hero ${paused ? "is-paused" : active < defenses.length ? "is-partial" : ""}`} data-tauri-drag-region>
          <TsubaRing defenses={defenses} paused={paused} />
          <div className="dash-hero-text">
            <span className="status-pill">{paused ? "守护已暂停 · 现在没有保护" : active === defenses.length ? "守护中 · 四道防线都在工作" : `守护中 · ${active} / ${defenses.length} 道防线在工作`}</span>
            <h1>{paused ? "保护已关闭，刀已入鞘。" : "陌生代码，先过这一关。"}</h1>
            {paused ? (
              <p className="dash-hero-warning">现在运行的命令、下载的安装包、新装的扩展和 AI 工具都不会被检查。处理完手头的事，马上恢复。</p>
            ) : (
              <button type="button" className="layer-checks" onClick={() => go("settings")} title="在设置里管理防线">
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
                  恢复守护
                </button>
              ) : (
                <button className="cta" disabled={!!checking} onClick={pickAndCheck}>
                  {checking ? <Spinner /> : <Icon.scan size={15} />}
                  {checking ? `正在检查 ${checking}` : "检查一个文件夹"}
                </button>
              )}
              <span className="hero-links">
                <button className="link" onClick={() => go("scan")}>
                  扫描
                </button>
                <button
                  className="link"
                  onClick={() => {
                    go("doctor");
                    window.dispatchEvent(new Event("tsuba-run-doctor"));
                  }}
                >
                  体检
                </button>
                {paused ? (
                  <button className="link" onClick={() => go("settings")}>
                    设置
                  </button>
                ) : (
                  <button className="link" onClick={() => setPaused(true)}>
                    暂停
                  </button>
                )}
              </span>
            </div>
            <div className="dash-hero-meta">{dragging ? "松开就开始检查" : "也可以把安装包、项目文件夹或脚本直接拖进窗口"}</div>
          </div>
        </section>

        {error && <Banner onClose={() => setError("")}>{error}</Banner>}

        <section className="bento" aria-label="小结">
          <button type="button" className={`cell cell-alert ${risky.length ? "" : "is-calm"}`} onClick={() => (risky[0] ? openEntry(risky[0].id) : go("history"))}>
            <span className="cell-go">{risky.length ? "查看 →" : "记录 →"}</span>
            <span className="cell-num">{risky.length}</span>
            <span className="cell-label">{risky.length ? "条需要你看一下" : "没有待处理的提醒"}</span>
            {risky[0] && <span className="cell-last">{entryName(risky[0], 46)}</span>}
          </button>
          <button type="button" className="cell" onClick={() => go("history")}>
            <span className="cell-num">{overview.recent.total.toLocaleString()}</span>
            <span className="cell-label">次检查</span>
          </button>
          <button type="button" className="cell" onClick={() => go("scan")}>
            <span className="cell-num">{overview.quarantined}</span>
            <span className="cell-label">在隔离区</span>
          </button>
          <button type="button" className="cell cell-intel" onClick={() => go("settings")}>
            <span className="cell-num">{intelCount >= 10000 ? `${(intelCount / 10000).toFixed(1)} 万` : intelCount.toLocaleString()}</span>
            <span className="cell-label">威胁情报{intel?.updated ? ` · ${relativeTime(intel.updated)} 更新` : " · 还没有下载"}</span>
          </button>
        </section>
      </div>
      <TermLog entries={entries.slice(0, 3)} status={status} openEntry={openEntry} go={go} />
    </>
  );
}
