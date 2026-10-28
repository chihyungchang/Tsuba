import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon } from "../icons";
import { ACTION_LABEL, LogEntry, QuarantineItem, SandboxResult, SOURCE_LABEL } from "../types";
import { BackLink, Banner, ConfirmButton, Empty, toastDone, FindingList, ReportView, Spinner, VerdictBadge, baseName, errText, relativeTime, shortPath } from "../ui";

/** 记录标题就是磁盘路径的来源：可以隔离、标记安全、在 Finder 里显示 */
const PATH_SOURCES: LogEntry["source"][] = ["download", "extension", "scan"];
/** 记录标题是磁盘上的文件（含安装镜像），可以直接删除 */
const FILE_SOURCES: LogEntry["source"][] = [...PATH_SOURCES, "mount"];
const isCommand = (e: LogEntry) => e.source === "terminal" || e.source === "paste";

function dayLabel(iso: string): string {
  const t = new Date(iso.replace(" ", "T"));
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86400_000);
  if (t.toDateString() === today.toDateString()) return "今天";
  if (t.toDateString() === yesterday.toDateString()) return "昨天";
  return "更早";
}

function SandboxPanel({ r }: { r: SandboxResult }) {
  const b = r.behavior;
  const denied = b.denied ?? [];
  const nothing = b.network.length === 0 && b.new_files.length === 0 && denied.length === 0 && r.findings.length === 0;
  return (
    <div className="sandbox">
      <div className="sandbox-head">
        <h3>沙箱里看到的行为</h3>
        <span className="muted small">
          运行 {b.seconds.toFixed(1)} 秒{b.timed_out ? " · 超时终止" : ""}
        </span>
      </div>
      {nothing && <p className="muted">这次运行没有联网、没有写文件。没看到坏行为不代表一定安全。</p>}
      {b.network.length > 0 && (
        <div className="sandbox-block">
          <div className="sandbox-label">网络请求</div>
          <ul className="sandbox-list">
            {b.network.map((e, i) => (
              <li key={i}>
                <span className="mono">{e.target}</span>
                {e.forwarded && <span className="muted small"> npm 官方源，已放行</span>}
                {e.leaked && e.leaked.length > 0 && <span className="tone-block small"> 发出了诱饵数据 {e.leaked.join("、")}</span>}
                {e.secrets && e.secrets.length > 0 && <span className="tone-block small"> 请求里带着疑似 {e.secrets.join("、")}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {b.new_files.length > 0 && (
        <div className="sandbox-block">
          <div className="sandbox-label">新建的文件</div>
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
          <div className="sandbox-label">被沙箱挡下的操作</div>
          <ul className="sandbox-list">
            {denied.slice(0, 12).map((d, i) => (
              <li key={i}>
                {d.process} <span className="muted small">{d.operation}</span> <span className="mono">{d.target}</span>
              </li>
            ))}
            {denied.length > 12 && <li className="muted small">还有 {denied.length - 12} 条</li>}
          </ul>
        </div>
      )}
      {r.findings.length > 0 && <FindingList findings={r.findings} />}
    </div>
  );
}

export function HistoryPage({ focusId, quarantine, reload }: { focusId: string | null; quarantine: QuarantineItem[]; reload: () => void }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [selected, setSelected] = useState<string | null>(focusId);
  const [filter, setFilter] = useState<"risky" | "all">("risky");
  const [error, setError] = useState("");
  const [sandbox, setSandbox] = useState<SandboxResult | null>(null);
  const [sandboxing, setSandboxing] = useState(false);

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

  const shown = useMemo(() => entries.filter((e) => filter === "all" || e.report.verdict !== "allow"), [entries, filter]);
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
  const risky = entries.filter((e) => e.report.verdict !== "allow").length;

  const act = async (cmd: string, args: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      toastDone(cmd);
      reload();
      load();
    } catch (e) {
      setError(errText(e));
    }
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

  // 上下键切换记录，像邮件列表一样
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
          <h1 data-tauri-drag-region>检查记录</h1>
          <div className="segmented" role="tablist">
            <button role="tab" aria-selected={filter === "risky"} className={filter === "risky" ? "on" : ""} onClick={() => setFilter("risky")}>
              有风险{risky > 0 && <span className="segmented-count">{risky}</span>}
            </button>
            <button role="tab" aria-selected={filter === "all"} className={filter === "all" ? "on" : ""} onClick={() => setFilter("all")}>
              全部
            </button>
          </div>
        </div>
        <div className="list-scroll">
          {shown.length === 0 && (
            <Empty icon="check" title={filter === "risky" ? "没有需要注意的记录" : "还没有检查记录"}>
              {filter === "risky" ? "有风险的命令、下载和扩展会出现在这里。" : "接入终端后，检查过的命令会出现在这里。"}
            </Empty>
          )}
          {groups.map((g) => (
            <div key={g.label}>
              <div className="list-group-label">{g.label}</div>
              {g.items.map((e) => (
                <button
                  key={e.id}
                  id={`entry-${e.id}`}
                  className={`list-item verdict-${e.report.verdict} ${current?.id === e.id ? "selected" : ""}`}
                  onClick={() => setSelected(e.id)}
                >
                  <span className="list-item-bar" />
                  <div className="list-item-body">
                    <div className={`list-item-title ${isCommand(e) ? "mono" : ""}`}>{isCommand(e) ? e.title : baseName(e.title)}</div>
                    <div className="list-item-meta">
                      <span>{SOURCE_LABEL[e.source]}</span>
                      {ACTION_LABEL[e.action] && <span>{ACTION_LABEL[e.action]}</span>}
                      <span className="list-item-time">{relativeTime(e.time)}</span>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ))}
        </div>
        {entries.length > 0 && (
          <div className="list-foot">
            <span className="muted small">{entries.length} 条</span>
            <ConfirmButton className="link" confirm="再点一下清空" onConfirm={() => act("clear_history", {})}>
              清空记录
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
                {SOURCE_LABEL[current.source]} · {current.time.replace("T", " ").slice(0, 16)}
                {ACTION_LABEL[current.action] ? ` · ${ACTION_LABEL[current.action]}` : ""}
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
            {current.cwd && <div className="detail-cwd">在 <span className="mono">{shortPath(current.cwd)}</span> 运行</div>}

            {error && <Banner onClose={() => setError("")}>{error}</Banner>}

            <div className="toolbar">
              {qItem && (
                <>
                  <span className="toolbar-note">
                    <Icon.lock size={14} /> 已移入隔离区
                  </span>
                  <button onClick={() => act("restore_quarantine", { id: qItem.id })}>恢复</button>
                  <ConfirmButton confirm="确认彻底删除" onConfirm={() => act("delete_quarantine", { id: qItem.id })}>
                    彻底删除
                  </ConfirmButton>
                </>
              )}
              {isDeleted && (
                <span className="toolbar-note">
                  <Icon.trash size={14} /> 文件已删除
                </span>
              )}
              {!qItem && !isDeleted && PATH_SOURCES.includes(current.source) && current.report.verdict !== "allow" && current.action !== "quarantined" && (
                <>
                  <button className="primary" onClick={() => act("quarantine_path", { path: current.title, reason: current.report.summary, entryId: current.id })}>
                    移入隔离区
                  </button>
                  <button onClick={() => act("trust_item", { key: current.title })}>我确认它安全</button>
                </>
              )}
              {FILE_SOURCES.includes(current.source) && !qItem && !isDeleted && (
                <button onClick={() => invoke("reveal_in_finder", { path: current.title })}>在 Finder 中显示</button>
              )}
              {current.source === "scan" && isScript && (
                <button disabled={sandboxing} onClick={() => runSandbox(current.title)}>
                  {sandboxing ? <Spinner /> : null}
                  {sandboxing ? "沙箱运行中" : "沙箱试运行"}
                </button>
              )}
              {isFolder && (
                <>
                  <button disabled={sandboxing} onClick={() => runSandbox(current.title)}>
                    {sandboxing ? "沙箱运行中…" : "沙箱试运行项目"}
                  </button>
                  <button disabled={sandboxing} onClick={() => runSandbox(current.title, true)} title="在沙箱里 npm install，看依赖的安装脚本做了什么">
                    沙箱试装依赖
                  </button>
                </>
              )}
              {/* 删不回来的操作放在最右边，和其他按钮隔开 */}
              {FILE_SOURCES.includes(current.source) && !qItem && !isDeleted && (
                <span className="toolbar-end">
                  <ConfirmButton confirm="再点一下，永久删除" onConfirm={() => act("delete_entry_file", { entryId: current.id })}>
                    <Icon.trash size={14} />
                    删除文件
                  </ConfirmButton>
                </span>
              )}
            </div>

            {sandbox && <SandboxPanel r={sandbox} />}
            <ReportView report={current.report} />
          </article>
        ) : (
          <Empty icon="history" title="选择一条记录">
            左边选一条，看 Tsuba 为什么这样判断。
          </Empty>
        )}
      </main>
    </div>
  );
}
