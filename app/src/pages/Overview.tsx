import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Icon } from "../icons";
import { Config, LogEntry, Overview, SOURCE_LABEL } from "../types";
import { Banner, Group, toastDone, Row, Section, Spinner, Toggle, VerdictBadge, baseName, errText, relativeTime, shortPath } from "../ui";

type WatchKey = "watch_downloads" | "watch_extensions" | "watch_ai_tools";

export function OverviewPage({
  overview,
  reload,
  onScanned,
  openEntry,
  goSettings,
}: {
  overview: Overview | null;
  reload: () => void;
  onScanned: (e: LogEntry) => void;
  openEntry: (id: string) => void;
  goSettings: () => void;
}) {
  const [checking, setChecking] = useState("");
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [recent, setRecent] = useState<LogEntry[]>([]);

  useEffect(() => {
    const load = () => invoke<LogEntry[]>("get_history", { limit: 200 }).then((all) => setRecent(all.filter((e) => e.report.verdict !== "allow").slice(0, 4)));
    load();
    const un = listen("history-updated", load);
    return () => {
      un.then((f) => f());
    };
  }, []);

  useEffect(() => {
    const un = getCurrentWebview().onDragDropEvent(async (event) => {
      const p = event.payload;
      if (p.type === "enter" || p.type === "over") setDragging(true);
      else if (p.type === "leave") setDragging(false);
      else if (p.type === "drop") {
        setDragging(false);
        const path = p.paths[0];
        if (!path) return;
        setChecking(baseName(path));
        setError("");
        try {
          onScanned(await invoke<LogEntry>("scan_path", { path }));
        } catch (e) {
          setError(errText(e));
        } finally {
          setChecking("");
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
      toastDone(cmd);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  const setWatch = async (key: WatchKey, on: boolean) => {
    const cfg = await invoke<Config>("get_config");
    await act("save_config", { config: { ...cfg, [key]: on } });
  };

  const hook = overview.shell_hook;
  const layers = [hook.installed, overview.watch_downloads, overview.watch_extensions, overview.watch_ai_tools];
  const active = layers.filter(Boolean).length;
  const paused = overview.paused;
  const editors = overview.extension_dirs.map((d) => d.split("/").slice(-2, -1)[0].replace(/^\./, "")).map((n) => ({ vscode: "VS Code", cursor: "Cursor", windsurf: "Windsurf", "vscode-oss": "VSCodium" })[n] ?? n);

  return (
    <div className="page page-overview">
      <header className={`hero ${paused ? "is-paused" : active < layers.length ? "is-partial" : "is-on"}`} data-tauri-drag-region>
        <div className="hero-emblem">{paused ? <Icon.shieldOff size={30} strokeWidth={1.6} /> : <Icon.overview size={30} strokeWidth={1.6} />}</div>
        <div className="hero-text" data-tauri-drag-region>
          <div className="eyebrow">{paused ? "保护已关闭" : "守护状态"}</div>
          <h1>{paused ? "守护已暂停" : "守护中"}</h1>
          <p>
            {paused
              ? "现在运行的命令、下载的安装包、新装的扩展和 AI 工具都不会被检查。处理完手头的事，马上恢复。"
              : active === layers.length
                ? "四道防线都在工作。陌生代码第一次运行之前，先过这里。"
                : `${active} / ${layers.length} 道防线在工作，下面还有没开的。`}
          </p>
        </div>
        <button className={paused ? "primary large" : ""} onClick={() => act("set_paused", { paused: !paused })}>
          {paused ? <Icon.play size={14} /> : <Icon.pause size={14} />}
          {paused ? "恢复守护" : "暂停守护"}
        </button>
      </header>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      <div className="metrics">
        <div className="metric">
          <span className="metric-value">{overview.recent.total.toLocaleString()}</span>
          <span className="metric-label">次检查</span>
        </div>
        <div className="metric">
          <span className="metric-value tone-warn">{overview.recent.warned}</span>
          <span className="metric-label">需要注意</span>
        </div>
        <div className="metric">
          <span className="metric-value tone-block">{overview.recent.blocked}</span>
          <span className="metric-label">建议拦截</span>
        </div>
        <div className="metric">
          <span className="metric-value">{overview.quarantined}</span>
          <span className="metric-label">在隔离区</span>
        </div>
      </div>

      <Section title="防线" aside={paused && <span className="section-aside tone-block">暂停期间全部不生效</span>}>
        <Group className={paused ? "is-suspended" : ""}>
          <Row
            icon="terminal"
                        title="终端命令"
            detail={
              hook.cli_found ? (
                <>
                  运行 <code>curl | bash</code>、<code>npm install</code>、<code>git clone</code> 之前检查，粘贴命令时先提醒
                </>
              ) : (
                <span className="tone-block">找不到 Tsuba 检查程序，请重新安装 Tsuba</span>
              )
            }
            trailing={
              hook.installed ? (
                <span className="trailing-status">
                  <span className="status-dot" />
                  已接入
                  <button className="link" onClick={() => act("uninstall_shell_hook")}>
                    移除
                  </button>
                </span>
              ) : (
                <button className="primary" disabled={!hook.cli_found} onClick={() => act("install_shell_hook")}>
                  接入 zsh
                </button>
              )
            }
          />
          <Row
            icon="package"
                        title="安装包"
            detail={
              <>
                {shortPath(overview.downloads_dir)} 里新出现的 .dmg、.pkg、.vsix；打开安装镜像时高危的直接弹出
              </>
            }
            trailing={<Toggle label="安装包" on={overview.watch_downloads} onChange={(v) => setWatch("watch_downloads", v)} />}
          />
          <Row
            icon="extension"
                        title="编辑器扩展"
            detail={editors.length > 0 ? `${editors.join("、")} 新装或更新的扩展，高危的移入隔离区` : "没有找到 VS Code、Cursor、Windsurf"}
            trailing={<Toggle label="编辑器扩展" on={overview.watch_extensions} onChange={(v) => setWatch("watch_extensions", v)} />}
          />
          <Row
            icon="plug"
                        title="AI 编程工具"
            detail="新增的 MCP server、skill、插件 hooks，以及项目自带的 .mcp.json 和 CLAUDE.md"
            trailing={<Toggle label="AI 编程工具" on={overview.watch_ai_tools} onChange={(v) => setWatch("watch_ai_tools", v)} />}
          />
          <Row
            icon="brain"
            title="判断方式"
            detail={
              overview.provider === "offline"
                ? "只用离线规则"
                : overview.ai_available
                  ? `离线规则 + ${overview.provider_label}`
                  : `${overview.provider_label} 还没配置好，目前只用离线规则`
            }
            trailing={<Icon.chevron size={14} className="chevron" />}
            onClick={goSettings}
          />
        </Group>
      </Section>

      {recent.length > 0 && (
        <Section title="最近的提醒">
          <Group>
            {recent.map((e) => (
              <Row
                key={e.id}
                title={<span className="mono-title">{e.source === "terminal" || e.source === "paste" ? e.title : baseName(e.title)}</span>}
                detail={`${SOURCE_LABEL[e.source]} · ${relativeTime(e.time)}`}
                trailing={
                  <>
                    <VerdictBadge v={e.report.verdict} />
                    <Icon.chevron size={14} className="chevron" />
                  </>
                }
                onClick={() => openEntry(e.id)}
              />
            ))}
          </Group>
        </Section>
      )}

      <div className={`dropzone ${dragging ? "is-active" : ""} ${checking ? "is-busy" : ""}`}>
        {checking ? (
          <>
            <Spinner />
            <div className="dropzone-title">正在检查 {checking}</div>
            <div className="dropzone-detail">离线规则先跑，AI 随后给出结论</div>
          </>
        ) : (
          <>
            <Icon.arrowDown size={22} />
            <div className="dropzone-title">{dragging ? "松开开始检查" : "拖进来检查"}</div>
            <div className="dropzone-detail">安装包、项目文件夹、扩展或脚本</div>
          </>
        )}
      </div>
    </div>
  );
}
