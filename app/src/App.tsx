import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon, TsubaMark, type IconName } from "./icons";
import { DoctorPage } from "./pages/Doctor";
import { HistoryPage } from "./pages/History";
import { OverviewPage } from "./pages/Overview";
import { ScanPage } from "./pages/Scan";
import { SettingsPage } from "./pages/Settings";
import { LogEntry, Overview, QuarantineItem } from "./types";
import { Toaster } from "./ui";
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

  // ⌘1–4 切换页面，⌘, 打开设置：Mac 软件的习惯
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
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

  const blocked = overview?.recent.blocked ?? 0;
  const paused = overview?.paused ?? false;
  const resume = () => invoke("set_paused", { paused: false }).then(reload);

  // 暂停时整个界面褪色、换成警示色：用户在哪一页都该感觉到“现在没有保护”
  useEffect(() => {
    document.documentElement.toggleAttribute("data-paused", paused);
  }, [paused]);

  return (
    <div className={`shell ${paused ? "is-paused" : ""}`}>
      <nav className="sidebar" aria-label="主导航">
        <div className="sidebar-top" data-tauri-drag-region />
        <div className="brand" data-tauri-drag-region>
          <TsubaMark size={26} />
          <span className="brand-name">Tsuba</span>
        </div>
        <div className="nav-list">
          {PAGES.map((p) => {
            const I = Icon[p.icon];
            return (
              <button
                key={p.id}
                className={`nav ${page === p.id ? "on" : ""}`}
                aria-current={page === p.id ? "page" : undefined}
                title={`${p.label}  ⌘${p.key}`}
                onClick={() => setPage(p.id)}
              >
                <I size={17} />
                <span className="nav-label">{p.label}</span>
                {p.id === "history" && blocked > 0 && <span className="nav-count">{blocked}</span>}
              </button>
            );
          })}
        </div>
        {paused ? (
          <button className="sidebar-status is-paused" title="终端检查和后台监控都停了，点一下恢复" onClick={resume}>
            <Icon.shieldOff size={15} />
            <span className="sidebar-status-text">
              守护已暂停
              <span className="sidebar-status-action">点击恢复守护</span>
            </span>
          </button>
        ) : (
          <div className="sidebar-status">
            <span className="status-dot" />
            {overview ? "守护中" : "连接中"}
          </div>
        )}
      </nav>
      <div className="content">
        {page === "overview" && <OverviewPage overview={overview} reload={reload} onScanned={onScanned} openEntry={openEntry} goSettings={() => setPage("settings")} />}
        {page === "history" && <HistoryPage focusId={focusId} quarantine={quarantine} reload={reload} />}
        {page === "scan" && <ScanPage quarantine={quarantine} reload={reload} onScanned={onScanned} />}
        {/* 体检可能要跑几十秒：切到别的页面时不卸载，回来进度和结果都还在 */}
        <div className="page-host" hidden={page !== "doctor"}>
          <DoctorPage reload={reload} />
        </div>
        {page === "settings" && <SettingsPage reload={reload} />}
      </div>
      <Toaster />
    </div>
  );
}
