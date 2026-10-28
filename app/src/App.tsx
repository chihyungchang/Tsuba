import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Splash } from "./brand";
import { useLang } from "./i18n";
import { Icon, TsubaMark, type IconName } from "./icons";
import { DoctorPage } from "./pages/Doctor";
import { HistoryPage } from "./pages/History";
import { OverviewPage } from "./pages/Overview";
import { ScanPage } from "./pages/Scan";
import { SettingsPage } from "./pages/Settings";
import { LogEntry, Overview, QuarantineItem } from "./types";
import { GoHome, Toaster } from "./ui";
import "./App.css";

type Page = "overview" | "history" | "scan" | "doctor" | "settings";

const PAGES: { id: Page; label: string; icon: IconName; key: string }[] = [
  { id: "overview", label: "概览", icon: "overview", key: "1" },
  { id: "history", label: "检查记录", icon: "history", key: "2" },
  { id: "scan", label: "扫描", icon: "scan", key: "3" },
  { id: "doctor", label: "体检", icon: "doctor", key: "4" },
  { id: "settings", label: "设置", icon: "settings", key: "," },
];

const isPage = (s: string): s is Page => PAGES.some((p) => p.id === s);

export default function App() {
  // Re-render the whole tree when the language changes; every t() below picks up the new language
  useLang();
  // 地址里的 #history 之类可以直接打开某一页（托盘菜单和开发预览用）
  const [page, setPageState] = useState<Page>(() => {
    const h = location.hash.slice(1);
    return isPage(h) ? h : "overview";
  });
  const [overview, setOverview] = useState<Overview | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([]);
  const [focusId, setFocusId] = useState<string | null>(null);

  const setPage = useCallback((p: Page) => {
    setPageState(p);
    history.replaceState(null, "", `#${p}`);
  }, []);

  const reload = useCallback(() => {
    invoke<Overview>("get_overview").then(setOverview);
    invoke<QuarantineItem[]>("quarantine_list").then(setQuarantine);
  }, []);

  useEffect(() => {
    reload();
    const uns = [
      listen("status-changed", reload),
      listen("history-updated", reload),
      listen<string>("navigate", (e) => isPage(e.payload) && setPage(e.payload)),
      listen<string>("focus-entry", (e) => {
        setFocusId(e.payload);
        setPage("history");
      }),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, [reload, setPage]);

  // ⌘1–4 切换页面，⌘, 打开设置：Mac 软件的习惯；Esc 回首页（输入框里除外）
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement;
      if (e.key === "Escape" && !typing && !e.metaKey) {
        setPage("overview");
        return;
      }
      if (!e.metaKey || e.altKey || e.ctrlKey) return;
      const p = PAGES.find((x) => x.key === e.key);
      if (p) {
        e.preventDefault();
        setPage(p.id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setPage]);

  const openEntry = useCallback(
    (id: string) => {
      setFocusId(id);
      setPage("history");
    },
    [setPage],
  );
  const onScanned = useCallback((e: LogEntry) => openEntry(e.id), [openEntry]);

  const paused = overview?.paused ?? false;
  const resume = () => invoke("set_paused", { paused: false }).then(reload);
  const current = PAGES.find((p) => p.id === page);
  const goHome = useCallback(() => setPage("overview"), [setPage]);

  // 暂停时整个界面换成警示色：用户在哪一页都该感觉到“现在没有保护”
  useEffect(() => {
    document.documentElement.toggleAttribute("data-paused", paused);
  }, [paused]);

  return (
    <GoHome.Provider value={goHome}>
    <div className={`shell ${paused ? "is-paused" : ""}`}>
      {/* 标题栏：只有红绿灯、居中的页面名和右边的刀标；返回放在内容里的面包屑 */}
      <header className="titlebar" data-tauri-drag-region>
        <span className="titlebar-title" data-tauri-drag-region>
          {page === "overview" ? "" : current?.label}
        </span>
        {paused ? (
          <button className="titlebar-status is-paused" onClick={resume} title="终端检查和后台监控都停了，点一下恢复">
            <Icon.shieldOff size={13} />
            守护已暂停 · 点击恢复
          </button>
        ) : (
          <span className="titlebar-status" data-tauri-drag-region>
            <TsubaMark size={16} />
            Tsuba
          </span>
        )}
      </header>
      <main className={`content content-${page}`}>
        {page === "overview" && <OverviewPage overview={overview} reload={reload} onScanned={onScanned} openEntry={openEntry} go={setPage} />}
        {page === "history" && <HistoryPage focusId={focusId} quarantine={quarantine} reload={reload} />}
        {page === "scan" && <ScanPage quarantine={quarantine} reload={reload} onScanned={onScanned} />}
        {/* 体检可能要跑几十秒：切到别的页面时不卸载，回来进度和结果都还在 */}
        <div className="page-host" hidden={page !== "doctor"}>
          <DoctorPage reload={reload} />
        </div>
        {page === "settings" && <SettingsPage overview={overview} reload={reload} />}
      </main>
      <footer className="footbar">
        <span className="footbar-brand">
          <TsubaMark size={15} />
          TSUBA
        </span>
        <span className="footbar-meta">{overview ? (overview.provider === "offline" ? "只用离线规则" : overview.ai_available ? `离线规则 + ${overview.provider_label.split(" · ")[0]}` : "离线规则（AI 还没配置好）") : "连接中"}</span>
        <span className="footbar-keys">
          {PAGES.filter((p) => p.id !== "overview" && p.id !== "settings").map((p) => (
            <button key={p.id} className="footbar-key" onClick={() => setPage(p.id)}>
              <kbd>⌘{p.key}</kbd>
              {p.label}
            </button>
          ))}
        </span>
        <button className="footbar-settings" onClick={() => setPage("settings")} title="设置  ⌘,">
          <Icon.settings size={14} />
          设置
        </button>
      </footer>
      <Toaster />
      <Splash status={overview ? (overview.paused ? "已暂停 0/4" : `守护中 ${[overview.shell_hook.installed, overview.watch_downloads, overview.watch_extensions, overview.watch_ai_tools].filter(Boolean).length}/4`) : "启动中"} />
    </div>
    </GoHome.Provider>
  );
}
