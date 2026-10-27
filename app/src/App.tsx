import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import {
  ACTION_LABEL,
  Config,
  ExtensionScan,
  Finding,
  IntelManifest,
  LogEntry,
  Overview,
  QuarantineItem,
  Report,
  SOURCE_LABEL,
  VERDICT_LABEL,
  Verdict,
} from "./types";
import "./App.css";

type Page = "overview" | "history" | "doctor" | "settings";

const PAGES: { id: Page; label: string }[] = [
  { id: "overview", label: "概览" },
  { id: "history", label: "检查记录" },
  { id: "doctor", label: "体检" },
  { id: "settings", label: "设置" },
];

function errText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

function VerdictBadge({ v }: { v: Verdict }) {
  return <span className={`badge badge-${v}`}>{VERDICT_LABEL[v]}</span>;
}

function Toggle({ on, onChange, disabled }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      className={`toggle ${on ? "on" : ""}`}
      onClick={() => onChange(!on)}
    >
      <span />
    </button>
  );
}

function FindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <p className="muted">离线规则没有命中。</p>;
  const order = { high: 0, medium: 1, low: 2 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  return (
    <ul className="findings">
      {sorted.map((f, i) => (
        <li key={i}>
          <span className={`sev sev-${f.severity}`}>{{ high: "高", medium: "中", low: "低" }[f.severity]}</span>
          <div>
            <div>{f.message}</div>
            {f.where && <div className="muted small mono">{f.where}</div>}
            {f.snippet && <pre className="snippet">{f.snippet}</pre>}
          </div>
        </li>
      ))}
    </ul>
  );
}

function ReportView({ report }: { report: Report }) {
  return (
    <div className="report">
      <div className="report-head">
        <VerdictBadge v={report.verdict} />
        <span className="muted small">{report.source === "ai" ? `AI 判断 · ${report.model}` : "离线规则"}</span>
      </div>
      {report.summary && <p className="summary">{report.summary}</p>}
      {report.reasons.length > 0 && (
        <ul className="reasons">
          {report.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
      {report.advice && report.verdict !== "allow" && (
        <p className="advice">
          <strong>建议：</strong>
          {report.advice}
        </p>
      )}
      <h4>证据</h4>
      <FindingList findings={report.findings} />
    </div>
  );
}

/* ---------- 概览 ---------- */

function OverviewPage({ overview, reload, onScanned }: { overview: Overview | null; reload: () => void; onScanned: (e: LogEntry) => void }) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    const un = getCurrentWebview().onDragDropEvent(async (event) => {
      const p = event.payload;
      if (p.type === "enter" || p.type === "over") setDragging(true);
      else if (p.type === "leave") setDragging(false);
      else if (p.type === "drop") {
        setDragging(false);
        const path = p.paths[0];
        if (!path) return;
        setBusy(`正在检查 ${path.split("/").pop()} …`);
        setError("");
        try {
          onScanned(await invoke<LogEntry>("scan_path", { path }));
        } catch (e) {
          setError(errText(e));
        } finally {
          setBusy("");
        }
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, [onScanned]);

  if (!overview) return null;

  const act = async (cmd: string, args?: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  const setWatch = async (key: "watch_downloads" | "watch_extensions", on: boolean) => {
    const cfg = await invoke<Config>("get_config");
    await act("save_config", { config: { ...cfg, [key]: on } });
  };

  const hook = overview.shell_hook;

  return (
    <div className="page">
      <header className={`hero ${overview.paused ? "paused" : ""}`}>
        <div>
          <h1>{overview.paused ? "守护已暂停" : "守护中"}</h1>
          <p>{overview.paused ? "终端检查和后台监控都已暂停，记得恢复。" : "陌生代码第一次运行之前，Tsuba 会先替你看一眼。"}</p>
        </div>
        <button className={overview.paused ? "primary" : ""} onClick={() => act("set_paused", { paused: !overview.paused })}>
          {overview.paused ? "恢复守护" : "暂停守护"}
        </button>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="card">
        <div className="row">
          <div>
            <h3>终端检查</h3>
            <p className="muted">
              在 zsh 里执行 <code>curl | bash</code>、<code>npm install</code>、<code>code .</code> 等命令前检查；粘贴命令时也会先提醒。
              {hook.installed && " 新开的终端窗口生效。"}
            </p>
            {!hook.cli_found && <p className="error-text">找不到 Tsuba 检查程序，请重新安装 Tsuba。</p>}
          </div>
          {hook.installed ? (
            <button onClick={() => act("uninstall_shell_hook")}>移除</button>
          ) : (
            <button className="primary" disabled={!hook.cli_found} onClick={() => act("install_shell_hook")}>
              接入终端
            </button>
          )}
        </div>
        <div className="row">
          <div>
            <h3>安装包监控</h3>
            <p className="muted">
              <code>{overview.downloads_dir}</code> 里新出现的 .dmg、.pkg、.vsix 会自动检查；打开安装镜像时再查一次，判为高危会立刻把它弹出。
            </p>
          </div>
          <Toggle on={overview.watch_downloads} onChange={(v) => setWatch("watch_downloads", v)} />
        </div>
        <div className="row">
          <div>
            <h3>编辑器扩展监控</h3>
            <p className="muted">
              {overview.extension_dirs.length > 0
                ? `监控 ${overview.extension_dirs.map((d) => d.split("/").slice(-2, -1)[0]).join("、")} 的扩展目录。在扩展商店里装的扩展只能装完马上查，判为拦截时会移入隔离区。`
                : "没有找到 VS Code、Cursor、Windsurf 的扩展目录。"}
            </p>
          </div>
          <Toggle on={overview.watch_extensions} onChange={(v) => setWatch("watch_extensions", v)} />
        </div>
        <div className="row">
          <div>
            <h3>AI 判断</h3>
            <p className="muted">
              {overview.provider_label}
              {overview.provider !== "offline" && !overview.ai_available && " · 还没配置好，目前只用离线规则"}
            </p>
          </div>
        </div>
      </section>

      <div className="stats">
        <div className="stat">
          <span>{overview.recent.total}</span>
          <label>检查记录</label>
        </div>
        <div className="stat warn">
          <span>{overview.recent.warned}</span>
          <label>需要注意</label>
        </div>
        <div className="stat block">
          <span>{overview.recent.blocked}</span>
          <label>建议拦截</label>
        </div>
        <div className="stat">
          <span>{overview.quarantined}</span>
          <label>隔离中的扩展</label>
        </div>
      </div>

      <div className={`dropzone ${dragging ? "active" : ""}`}>
        {busy || "把安装包、项目文件夹、扩展或脚本拖到这里检查"}
      </div>
    </div>
  );
}

/* ---------- 检查记录 ---------- */

function HistoryPage({ focusId, quarantine, reload }: { focusId: string | null; quarantine: QuarantineItem[]; reload: () => void }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [selected, setSelected] = useState<string | null>(focusId);
  const [filter, setFilter] = useState<"all" | "risky">("risky");
  const [error, setError] = useState("");

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

  const shown = entries.filter((e) => filter === "all" || e.report.verdict !== "allow");
  const current = entries.find((e) => e.id === selected) ?? shown[0];
  const qItem = current?.quarantine_id ? quarantine.find((q) => q.id === current.quarantine_id) : undefined;

  const act = async (cmd: string, args: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="split">
      <aside className="list">
        <div className="list-head">
          <div className="segmented">
            <button className={filter === "risky" ? "on" : ""} onClick={() => setFilter("risky")}>
              有风险
            </button>
            <button className={filter === "all" ? "on" : ""} onClick={() => setFilter("all")}>
              全部
            </button>
          </div>
        </div>
        {shown.length === 0 && <p className="muted pad">{filter === "risky" ? "没有需要注意的记录。" : "还没有检查记录。"}</p>}
        {shown.map((e) => (
          <button key={e.id} className={`list-item ${current?.id === e.id ? "selected" : ""}`} onClick={() => setSelected(e.id)}>
            <span className={`dot dot-${e.report.verdict}`} />
            <div>
              <div className="ellipsis mono small">{e.title}</div>
              <div className="muted small">
                {SOURCE_LABEL[e.source]} · {e.time.replace("T", " ").slice(5, 16)}
                {ACTION_LABEL[e.action] ? ` · ${ACTION_LABEL[e.action]}` : ""}
              </div>
            </div>
          </button>
        ))}
        {entries.length > 0 && (
          <button className="link pad" onClick={() => act("clear_history", {}).then(load)}>
            清空记录
          </button>
        )}
      </aside>
      <main className="detail">
        {current ? (
          <>
            <div className="detail-meta">
              <span className="muted small">
                {SOURCE_LABEL[current.source]} · {current.time.replace("T", " ")}
                {ACTION_LABEL[current.action] ? ` · ${ACTION_LABEL[current.action]}` : ""}
              </span>
              <pre className="command">{current.title}</pre>
              {current.cwd && <div className="muted small mono">目录：{current.cwd}</div>}
            </div>
            {error && <div className="error">{error}</div>}
            <div className="actions">
              {qItem && (
                <>
                  <span className="muted small">这个扩展已移入隔离区。</span>
                  <button onClick={() => act("restore_quarantine", { id: qItem.id })}>恢复</button>
                  <button className="danger" onClick={() => act("delete_quarantine", { id: qItem.id })}>
                    彻底删除
                  </button>
                </>
              )}
              {!qItem && current.source === "extension" && current.report.verdict !== "allow" && current.action !== "quarantined" && (
                <button onClick={() => act("quarantine_extension", { path: current.title, reason: current.report.summary })}>移入隔离区</button>
              )}
              {["download", "mount", "extension", "scan"].includes(current.source) && !qItem && (
                <button onClick={() => invoke("reveal_in_finder", { path: current.title })}>在 Finder 中显示</button>
              )}
            </div>
            <ReportView report={current.report} />
          </>
        ) : (
          <p className="muted pad">选择一条记录查看详情。</p>
        )}
      </main>
    </div>
  );
}

/* ---------- 体检 ---------- */

function DoctorPage({ quarantine, reload }: { quarantine: QuarantineItem[]; reload: () => void }) {
  const [doctor, setDoctor] = useState<{ findings: Finding[]; advice: string } | null>(null);
  const [exts, setExts] = useState<ExtensionScan[] | null>(null);
  const [busy, setBusy] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState("");

  const runDoctor = async () => {
    setBusy("doctor");
    setDoctor(await invoke("run_doctor"));
    setBusy("");
  };
  const runExts = async () => {
    setBusy("exts");
    setExts(await invoke("scan_installed_extensions"));
    setBusy("");
  };
  const act = async (cmd: string, args: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      reload();
      if (cmd === "quarantine_extension") setExts((xs) => xs?.filter((x) => x.path !== args.path) ?? null);
    } catch (e) {
      setError(errText(e));
    }
  };

  const risky = exts?.filter((x) => x.verdict !== "allow") ?? [];

  return (
    <div className="page">
      {error && <div className="error">{error}</div>}
      <section className="card">
        <div className="row">
          <div>
            <h3>已经中招了吗？</h3>
            <p className="muted">检查已知攻击留下的痕迹：隐藏的 Node 依赖目录、可疑的开机自启项等。</p>
          </div>
          <button className="primary" disabled={busy === "doctor"} onClick={runDoctor}>
            {busy === "doctor" ? "检查中…" : "开始体检"}
          </button>
        </div>
        {doctor && (
          <div className="result">
            {doctor.findings.length === 0 ? (
              <p className="ok-text">✓ 没有发现已知的感染痕迹</p>
            ) : (
              <>
                <FindingList findings={doctor.findings} />
                <p className="advice">
                  <strong>建议：</strong>
                  {doctor.advice}
                </p>
              </>
            )}
          </div>
        )}
      </section>

      <section className="card">
        <div className="row">
          <div>
            <h3>已装的编辑器扩展</h3>
            <p className="muted">用离线规则快速扫一遍所有已装扩展。可疑的可以拖到概览页做一次带 AI 的深度检查。</p>
          </div>
          <button disabled={busy === "exts"} onClick={runExts}>
            {busy === "exts" ? "扫描中…" : "扫描扩展"}
          </button>
        </div>
        {exts && (
          <div className="result">
            <p className="muted small">
              共 {exts.length} 个扩展，{risky.length === 0 ? "都没有发现问题。" : `${risky.length} 个需要看一下：`}
            </p>
            {risky.map((x) => (
              <div key={x.path} className="ext">
                <button className="ext-head" onClick={() => setOpen(open === x.path ? null : x.path)}>
                  <VerdictBadge v={x.verdict} />
                  <span className="mono small">{x.id}</span>
                  <span className="muted small">{x.findings.length} 条命中</span>
                </button>
                {open === x.path && (
                  <div className="ext-body">
                    <FindingList findings={x.findings} />
                    <div className="actions">
                      <button onClick={() => act("quarantine_extension", { path: x.path, reason: "体检时手动隔离" })}>移入隔离区</button>
                      <button onClick={() => invoke("reveal_in_finder", { path: x.path })}>在 Finder 中显示</button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <h3>隔离区</h3>
        {quarantine.length === 0 ? (
          <p className="muted">隔离区是空的。</p>
        ) : (
          quarantine.map((q) => (
            <div key={q.id} className="row">
              <div>
                <div className="mono small">{q.original.split("/").pop()}</div>
                <div className="muted small">
                  {q.time.replace("T", " ")} · {q.reason}
                </div>
              </div>
              <div className="actions">
                <button onClick={() => act("restore_quarantine", { id: q.id })}>恢复</button>
                <button className="danger" onClick={() => act("delete_quarantine", { id: q.id })}>
                  删除
                </button>
              </div>
            </div>
          ))
        )}
      </section>
    </div>
  );
}

/* ---------- 威胁情报 ---------- */

function IntelCard({ cfg, onChange }: { cfg: Config; onChange: (c: Config) => void }) {
  const [m, setM] = useState<IntelManifest | null>(null);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    invoke<IntelManifest>("intel_status").then(setM);
    const uns = [
      listen<string>("intel-progress", (e) => setProgress(e.payload)),
      listen("intel-updated", () => {
        setProgress("");
        invoke<IntelManifest>("intel_status").then(setM);
      }),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, []);

  const update = async () => {
    setError("");
    setProgress("开始更新");
    try {
      setM(await invoke<IntelManifest>("intel_update"));
    } catch (e) {
      setError(errText(e));
    } finally {
      setProgress("");
    }
  };
  const setIntel = (patch: Partial<Config["intel"]>) => onChange({ ...cfg, intel: { ...cfg.intel, ...patch } });

  return (
    <section className="card">
      <div className="row">
        <div>
          <h3>威胁情报</h3>
          <p className="muted">
            从公开来源下载的恶意包名单、恶意扩展名单和 YARA 规则，每天自动更新。
            {m?.updated ? ` 上次更新：${m.updated.replace("T", " ")}` : " 还没有更新过。"}
          </p>
        </div>
        <button className="primary" disabled={!!progress} onClick={update}>
          {progress ? `${progress}…` : "立即更新"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {m && m.sources.length > 0 && (
        <table className="sources">
          <tbody>
            {m.sources.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td className={s.error ? "error-text small" : "small"}>{s.error ? s.error : `${s.count.toLocaleString()} 条`}</td>
                <td className="muted small">{s.license}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="form">
        <label className="check">
          <input type="checkbox" checked={cfg.intel.auto_update} onChange={(e) => setIntel({ auto_update: e.target.checked })} />
          每天自动更新
        </label>
        <label className="check">
          <input type="checkbox" checked={cfg.intel.online_lookup} onChange={(e) => setIntel({ online_lookup: e.target.checked })} />
          检查 npm / PyPI 包时在线查询 OSV.dev（比本地名单更新得更快，只发送包名和版本）
        </label>
        <label>
          abuse.ch Auth-Key（可选，免费注册：auth.abuse.ch；免费版仅限非营利使用）
          <input type="password" value={cfg.intel.abusech_key} onChange={(e) => setIntel({ abusech_key: e.target.value.trim() })} />
        </label>
      </div>
    </section>
  );
}

/* ---------- 设置 ---------- */

// 都走 OpenAI 兼容接口。前沿模型默认信任，其他默认只能给“提醒”
const PRESETS = [
  { id: "openai", name: "OpenAI", group: "前沿模型", url: "https://api.openai.com/v1", trusted: true, key: true },
  { id: "gemini", name: "Google Gemini", group: "前沿模型", url: "https://generativelanguage.googleapis.com/v1beta/openai", trusted: true, key: true },
  { id: "deepseek", name: "DeepSeek", group: "其他云端", url: "https://api.deepseek.com/v1", trusted: false, key: true },
  { id: "qwen", name: "通义千问", group: "其他云端", url: "https://dashscope.aliyuncs.com/compatible-mode/v1", trusted: false, key: true },
  { id: "ollama", name: "Ollama", group: "本地", url: "http://127.0.0.1:11434/v1", trusted: false, key: false },
  { id: "lmstudio", name: "LM Studio", group: "本地", url: "http://127.0.0.1:1234/v1", trusted: false, key: false },
  { id: "custom", name: "自定义", group: "自定义", url: "", trusted: false, key: true },
];

function SettingsPage({ reload }: { reload: () => void }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [listing, setListing] = useState(false);
  const [cliPath, setCliPath] = useState<string | null>(null);

  useEffect(() => {
    invoke<Config>("get_config").then((c) => {
      setCfg(c);
      invoke<string | null>("detect_claude_cli", { configured: c.claude.cli_path }).then(setCliPath);
    });
  }, []);
  if (!cfg) return null;

  const set = (patch: Partial<Config>) => setCfg({ ...cfg, ...patch });
  const oc = cfg.openai_compatible;
  const setOc = (patch: Partial<Config["openai_compatible"]>) => set({ openai_compatible: { ...oc, ...patch } });
  const preset = PRESETS.find((p) => p.id === oc.preset);
  const fetchModels = async () => {
    setListing(true);
    setStatus(null);
    try {
      const list = await invoke<string[]>("list_models", { baseUrl: oc.base_url, apiKey: oc.api_key });
      setModels(list);
      setStatus({ ok: true, text: `找到 ${list.length} 个模型，在“模型名”里选择` });
    } catch (e) {
      setStatus({ ok: false, text: errText(e) });
    } finally {
      setListing(false);
    }
  };
  const save = async () => {
    try {
      await invoke("save_config", { config: cfg });
      setStatus({ ok: true, text: "已保存" });
      reload();
    } catch (e) {
      setStatus({ ok: false, text: errText(e) });
    }
  };
  const test = async () => {
    setTesting(true);
    setStatus(null);
    try {
      setStatus({ ok: true, text: await invoke<string>("test_ai", { config: cfg }) });
    } catch (e) {
      setStatus({ ok: false, text: errText(e) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="page">
      <section className="card">
        <h3>AI 判断</h3>
        <p className="muted">离线规则总是先跑。AI 结合上下文判断，减少误报、补上规则漏掉的情况。</p>
        <div className="radio-group">
          {(
            [
              ["claude_cli", "Claude Code 账号", "用本机 Claude Code 登录的账号，不需要 API Key。适合个人使用"],
              ["claude", "Claude API", "用 Anthropic API Key，按用量计费"],
              ["openai_compatible", "其他模型", "OpenAI、Gemini、DeepSeek、通义千问、本地模型，或任何兼容 OpenAI 接口的地址"],
              ["offline", "仅离线规则", "不联网、不调用任何模型"],
            ] as const
          ).map(([id, label, desc]) => (
            <label key={id} className={`radio ${cfg.provider === id ? "on" : ""}`}>
              <input type="radio" checked={cfg.provider === id} onChange={() => set({ provider: id })} />
              <div>
                <div>{label}</div>
                <div className="muted small">{desc}</div>
              </div>
            </label>
          ))}
        </div>

        {cfg.provider === "claude_cli" && (
          <div className="form">
            <p className={cliPath ? "ok-text" : "error-text"}>
              {cliPath ? `已找到 Claude Code：${cliPath}` : "没有找到 claude 命令。请先安装 Claude Code 并在终端里运行 claude 登录一次，或在下面填写它的位置。"}
            </p>
            <label>
              claude 命令的位置（留空自动查找）
              <input
                value={cfg.claude.cli_path}
                placeholder="~/.local/bin/claude"
                onChange={(e) => set({ claude: { ...cfg.claude, cli_path: e.target.value.trim() } })}
                onBlur={() => invoke<string | null>("detect_claude_cli", { configured: cfg.claude.cli_path }).then(setCliPath)}
              />
            </label>
          </div>
        )}

        {(cfg.provider === "claude" || cfg.provider === "claude_cli") && (
          <div className="form">
            {cfg.provider === "claude" && (
            <label>
              API Key
              <input
                type="password"
                value={cfg.claude.api_key}
                placeholder="sk-ant-…"
                onChange={(e) => set({ claude: { ...cfg.claude, api_key: e.target.value.trim() } })}
              />
            </label>
            )}
            <label>
              模型
              <select value={cfg.claude.model} onChange={(e) => set({ claude: { ...cfg.claude, model: e.target.value } })}>
                <option value="claude-opus-5-5">Claude Opus 5.5（推荐）</option>
                <option value="claude-sonnet-5-5">Claude Sonnet 5.5（更快更省）</option>
                <option value="claude-haiku-4-5">Claude Haiku 4.5（最快最省）</option>
              </select>
            </label>
            {!cfg.claude.model.startsWith("claude-haiku") && (
              <label>
                思考深度
                <select value={cfg.claude.effort} onChange={(e) => set({ claude: { ...cfg.claude, effort: e.target.value } })}>
                  <option value="low">低（快，日常够用）</option>
                  <option value="medium">中</option>
                  <option value="high">高（慢，更仔细）</option>
                </select>
              </label>
            )}
          </div>
        )}

        {cfg.provider === "openai_compatible" && (
          <div className="form">
            <div className="preset-groups">
              {["前沿模型", "其他云端", "本地", "自定义"].map((g) => (
                <div key={g} className="preset-group">
                  <span className="muted small">{g}</span>
                  <div className="presets">
                    {PRESETS.filter((p) => p.group === g).map((p) => (
                      <button
                        key={p.id}
                        className={oc.preset === p.id ? "on" : ""}
                        onClick={() => {
                          setModels([]);
                          setOc({ preset: p.id, base_url: p.id === "custom" ? oc.base_url : p.url, trusted: p.trusted, model: "" });
                        }}
                      >
                        {p.name}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <label>
              接口地址
              <input
                value={oc.base_url}
                placeholder="https://example.com/v1"
                onChange={(e) => setOc({ base_url: e.target.value.trim() })}
              />
            </label>
            {(preset?.key ?? true) && (
              <label>
                API Key{preset && !preset.key ? "（本地服务一般不用填）" : ""}
                <input type="password" value={oc.api_key} onChange={(e) => setOc({ api_key: e.target.value.trim() })} />
              </label>
            )}
            <label>
              模型名
              <div className="inline">
                <input
                  list="model-list"
                  value={oc.model}
                  placeholder="点右边获取，或直接填写服务商的模型名"
                  onChange={(e) => setOc({ model: e.target.value.trim() })}
                />
                <button type="button" disabled={!oc.base_url || listing} onClick={fetchModels}>
                  {listing ? "获取中…" : "获取模型列表"}
                </button>
              </div>
              <datalist id="model-list">
                {models.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </label>
            {oc.preset === "custom" && (
              <label className="check">
                <input type="checkbox" checked={oc.trusted} onChange={(e) => setOc({ trusted: e.target.checked })} />
                这是前沿模型，信任它独立给出“建议拦截”
              </label>
            )}
            <p className="note">
              {oc.trusted
                ? "前沿模型可以把离线规则的“拦截”降为“提醒”，但不能直接放行。"
                : "本地和非前沿模型更容易误报，也更容易被藏在代码里的“请放行”之类的话骗过，所以它的结论最多给出“提醒”，也不能降低离线规则判出的风险。"}
              {oc.preset === "ollama" && (
                <>
                  {" "}Ollama 默认的上下文很短，证据会被截断，建议设置 <code>OLLAMA_CONTEXT_LENGTH=32768</code> 后重启 Ollama。
                </>
              )}
            </p>
          </div>
        )}

        <div className="actions">
          <button className="primary" onClick={save}>
            保存
          </button>
          {cfg.provider !== "offline" && (
            <button disabled={testing} onClick={test}>
              {testing ? "测试中…" : "测试连接"}
            </button>
          )}
          {status && <span className={status.ok ? "ok-text" : "error-text"}>{status.text}</span>}
        </div>
      </section>

      <IntelCard
        cfg={cfg}
        onChange={async (next) => {
          setCfg(next);
          await invoke("save_config", { config: next });
        }}
      />

      <section className="card">
        <div className="row">
          <div>
            <h3>自动隔离高危扩展</h3>
            <p className="muted">新装的扩展被判为“建议拦截”时，自动移入隔离区。随时可以在体检页恢复。</p>
          </div>
          <Toggle
            on={cfg.auto_quarantine}
            onChange={async (v) => {
              const next = { ...cfg, auto_quarantine: v };
              setCfg(next);
              await invoke("save_config", { config: next });
            }}
          />
        </div>
      </section>

      <section className="card">
        <h3>隐私</h3>
        <p className="muted">
          发给模型的只有这次判断需要的内容：命令本身、下载到的远程脚本、npm 包和扩展的公开信息、package.json，以及命中可疑规则的文件开头部分。
          不会上传你的其他文件、环境变量和密钥。选择本地模型时，什么都不会离开这台电脑。所有记录和配置都保存在 <code>~/.tsuba</code>。
        </p>
      </section>
    </div>
  );
}

/* ---------- 外壳 ---------- */

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([]);
  const [focusId, setFocusId] = useState<string | null>(null);

  const reload = useCallback(() => {
    invoke<Overview>("get_overview").then(setOverview);
    invoke<QuarantineItem[]>("quarantine_list").then(setQuarantine);
  }, []);

  useEffect(() => {
    reload();
    const uns = [
      listen("status-changed", reload),
      listen("history-updated", reload),
      listen<string>("navigate", (e) => setPage(e.payload as Page)),
      listen<string>("focus-entry", (e) => {
        setFocusId(e.payload);
        setPage("history");
      }),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, [reload]);

  const onScanned = useCallback((e: LogEntry) => {
    setFocusId(e.id);
    setPage("history");
  }, []);

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          <span className="mark" aria-hidden>
            鍔
          </span>
          Tsuba
        </div>
        {PAGES.map((p) => (
          <button key={p.id} className={`nav ${page === p.id ? "on" : ""}`} onClick={() => setPage(p.id)}>
            {p.label}
            {p.id === "history" && overview && overview.recent.blocked > 0 && <span className="count">{overview.recent.blocked}</span>}
          </button>
        ))}
        <div className="sidebar-foot muted small">{overview?.paused ? "已暂停" : "守护中"}</div>
      </nav>
      <div className="content">
        {page === "overview" && <OverviewPage overview={overview} reload={reload} onScanned={onScanned} />}
        {page === "history" && <HistoryPage focusId={focusId} quarantine={quarantine} reload={reload} />}
        {page === "doctor" && <DoctorPage quarantine={quarantine} reload={reload} />}
        {page === "settings" && <SettingsPage reload={reload} />}
      </div>
    </div>
  );
}
