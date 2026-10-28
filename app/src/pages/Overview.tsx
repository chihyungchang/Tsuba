import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Icon, KatanaGlyph, type IconName } from "../icons";
import { IntelManifest, LogEntry, Overview } from "../types";
import { Banner, Spinner, baseName, errText, relativeTime } from "../ui";

type Go = (page: "history" | "scan" | "doctor" | "settings") => void;

/** 记录的简称：命令原样显示（截断），文件只显示文件名 */
const entryName = (e: LogEntry) => (e.source === "terminal" || e.source === "paste" ? (e.title.length > 42 ? `${e.title.slice(0, 40)}…` : e.title) : baseName(e.title));

/** 仪表盘的主图：一台屏幕上跑着陌生命令的电脑，中间是刀镡形状的守护标志。暂停时标志变红、打叉。 */
function HeroArt({ paused }: { paused: boolean }) {
  return (
    <svg className="hero-art" viewBox="0 0 210 140" aria-hidden>
      <defs>
        <linearGradient id="hero-screen" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor={paused ? "#6b3a36" : "#2f6f86"} />
          <stop offset="1" stopColor={paused ? "#2c1716" : "#1a3446"} />
        </linearGradient>
        <radialGradient id="hero-glow" cx=".5" cy=".5" r=".5">
          <stop offset="0" stopColor={paused ? "#ff8a7a" : "#7cd6c6"} stopOpacity=".55" />
          <stop offset="1" stopColor={paused ? "#ff8a7a" : "#7cd6c6"} stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect x="22" y="8" width="166" height="104" rx="8" fill="#0d0e12" />
      <rect x="27" y="13" width="156" height="94" rx="4" fill="url(#hero-screen)" />
      <g fontFamily="ui-monospace, Menlo, monospace" fontSize="6.5" fill={paused ? "#f3c2bb" : "#a9d9e6"} opacity=".55">
        <text x="34" y="26">$ git clone interview-task</text>
        <text x="34" y="36">$ npm install</text>
        <text x="34" y="96">$ curl -fsSL get.sh | bash</text>
      </g>
      <circle cx="105" cy="60" r="34" fill="url(#hero-glow)" />
      {/* 屏幕中央是品牌的刀：守护中旁边一枚勾，暂停时一枚叉 */}
      <g transform="translate(80 34) scale(0.78)">
        <KatanaGlyph fill="#eef7f8" />
      </g>
      <circle cx="128" cy="78" r="11" fill={paused ? "#d0392b" : "#2f9e6e"} stroke="#0d0e12" strokeWidth="2" />
      {paused ? (
        <path d="M124 74l8 8M132 74l-8 8" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" />
      ) : (
        <path d="M123 78l3.5 3.5 6.5-7" stroke="#fff" strokeWidth="2.4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      )}
      <path d="M8 114h194l-6 8H14z" fill="#3a3c44" />
      <rect x="88" y="114" width="34" height="3" rx="1.5" fill="#24252b" />
    </svg>
  );
}

function Tile({ icon, title, detail, tone, onClick, children }: { icon: IconName; title: string; detail: string; tone?: "alert" | "intel"; onClick: () => void; children?: React.ReactNode }) {
  const I = Icon[icon];
  return (
    <button type="button" className={`tile ${tone ? `tile-${tone}` : ""}`} onClick={onClick}>
      <span className="tile-title">
        <I size={14} strokeWidth={1.8} />
        {title}
      </span>
      <span className="tile-detail">{detail}</span>
      {children}
    </button>
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
  const [risky, setRisky] = useState<LogEntry[]>([]);
  const [intel, setIntel] = useState<IntelManifest | null>(null);

  useEffect(() => {
    const load = () => invoke<LogEntry[]>("get_history", { limit: 200 }).then((all) => setRisky(all.filter((e) => e.report.verdict !== "allow")));
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
  const layers = [
    { label: "终端命令", on: overview.shell_hook.installed },
    { label: "安装包", on: overview.watch_downloads },
    { label: "编辑器扩展", on: overview.watch_extensions },
    { label: "AI 编程工具", on: overview.watch_ai_tools },
  ];
  const active = layers.filter((l) => l.on).length;
  const latest = risky[0];
  const intelCount = intel?.sources.reduce((n, s) => n + s.count, 0) ?? 0;

  return (
    <div className={`dashboard ${dragging ? "is-dragging" : ""}`}>
      <section className={`dash-hero ${paused ? "is-paused" : active < layers.length ? "is-partial" : ""}`} data-tauri-drag-region>
        <HeroArt paused={paused} />
        <div className="dash-hero-text">
          <span className="status-pill">{paused ? "守护已暂停 · 现在没有保护" : active === layers.length ? "守护中 · 四道防线都在工作" : `守护中 · ${active} / ${layers.length} 道防线在工作`}</span>
          <h1>{paused ? "保护已关闭。" : "陌生代码，先过这一关。"}</h1>
          {paused ? (
            <p className="dash-hero-warning">现在运行的命令、下载的安装包、新装的扩展和 AI 工具都不会被检查。处理完手头的事，马上恢复。</p>
          ) : (
            <button type="button" className="layer-checks" onClick={() => go("settings")} title="在设置里管理防线">
              {layers.map((l) => (
                <span key={l.label} className={l.on ? "is-on" : "is-off"}>
                  {l.label}
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
            {!paused && (
              <button className="link" onClick={() => setPaused(true)}>
                暂停守护
              </button>
            )}
          </div>
          <div className="dash-hero-meta">
            {dragging
              ? "松开就开始检查"
              : latest
                ? `上次提醒：${relativeTime(latest.time)} · ${entryName(latest)}`
                : "也可以把安装包、项目文件夹或脚本直接拖进窗口"}
          </div>
        </div>
      </section>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      <section className="quick" aria-label="快速操作">
        <span className="quick-label">快速操作</span>
        <button className="quick-button" onClick={() => go("scan")}>
          <Icon.scan size={15} />
          扫描文件夹
        </button>
        <button
          className="quick-button"
          onClick={() => {
            go("doctor");
            window.dispatchEvent(new Event("tsuba-run-doctor"));
          }}
        >
          <Icon.doctor size={15} />
          全面体检
        </button>
        <button className="quick-button" onClick={() => go("history")}>
          <Icon.history size={15} />
          检查记录
        </button>
      </section>

      <section className="tiles">
        {risky.length > 0 ? (
          <Tile icon="alert" tone="alert" title={`${risky.length} 条需要看一下`} detail={`最近：${entryName(risky[0])}`} onClick={() => openEntry(risky[0].id)} />
        ) : (
          <Tile icon="check" title="没有待处理的提醒" detail={`共检查 ${overview.recent.total.toLocaleString()} 次`} onClick={() => go("history")} />
        )}
        <Tile icon="lock" title="隔离区" detail={overview.quarantined > 0 ? `${overview.quarantined} 项，随时可以恢复或删除` : "空的。高危的扩展和安装包会放在这里"} onClick={() => go("scan")} />
        <Tile icon="check" title="白名单" detail={overview.trusted > 0 ? `${overview.trusted} 项，内容变了会重新检查` : "你确认安全的东西会记在这里"} onClick={() => go("scan")} />
        <Tile icon="refresh" tone="intel" title="威胁情报" detail={intel?.updated ? `${relativeTime(intel.updated)} 更新` : "还没有下载"} onClick={() => go("settings")}>
          {intelCount > 0 && <span className="tile-badge">{intelCount.toLocaleString()} 条恶意包和规则</span>}
        </Tile>
      </section>
    </div>
  );
}
