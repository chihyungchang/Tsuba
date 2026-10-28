import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Splash } from "./brand";
import { t, useLang } from "./i18n";
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

// A function, not a constant: labels must be translated at render time, after the language is known
const pages = (): { id: Page; label: string; icon: IconName; key: string }[] => [
  { id: "overview", label: t("Overview"), icon: "overview", key: "1" },
  { id: "history", label: t("History"), icon: "history", key: "2" },
  { id: "scan", label: t("Scan"), icon: "scan", key: "3" },
  { id: "doctor", label: t("Health Check"), icon: "doctor", key: "4" },
  { id: "settings", label: t("Settings"), icon: "settings", key: "," },
];

const isPage = (s: string): s is Page => pages().some((p) => p.id === s);

export default function App() {
  // Re-render the whole tree when the language changes; every t() below picks up the new language
  useLang();
  // A hash such as #history opens that page directly (used by the tray menu and the dev preview)
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

  // ⌘1–4 switch pages and ⌘, opens Settings, as Mac apps do; Esc goes home (except while typing)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement;
      if (e.key === "Escape" && !typing && !e.metaKey) {
        setPage("overview");
        return;
      }
      if (!e.metaKey || e.altKey || e.ctrlKey) return;
      const p = pages().find((x) => x.key === e.key);
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
  const current = pages().find((p) => p.id === page);
  const goHome = useCallback(() => setPage("overview"), [setPage]);

  // While paused the whole window takes the warning color: on every page the user should feel "nothing is protecting me now"
  useEffect(() => {
    document.documentElement.toggleAttribute("data-paused", paused);
  }, [paused]);

  return (
    <GoHome.Provider value={goHome}>
    <div className={`shell ${paused ? "is-paused" : ""}`}>
      {/* Title bar: only the traffic lights, the centered page name and the sword mark on the right; going back lives in the breadcrumb inside the content */}
      <header className="titlebar" data-tauri-drag-region>
        <span className="titlebar-title" data-tauri-drag-region>
          {page === "overview" ? "" : current?.label}
        </span>
        {paused ? (
          <button className="titlebar-status is-paused" onClick={resume} title={t("Terminal checks and background monitoring are stopped. Click to resume.")}>
            <Icon.shieldOff size={13} />
            {t("Protection paused · Click to resume")}
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
        {/* A Health Check can take tens of seconds: keep it mounted while on other pages so progress and results are still there on return */}
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
        <span className="footbar-meta">{overview ? (overview.provider === "offline" ? t("Offline rules only") : overview.ai_available ? t("Offline rules + {provider}", { provider: overview.provider_label.split(" · ")[0] }) : t("Offline rules (AI not set up yet)")) : t("Connecting…")}</span>
        <span className="footbar-keys">
          {pages().filter((p) => p.id !== "overview" && p.id !== "settings").map((p) => (
            <button key={p.id} className="footbar-key" onClick={() => setPage(p.id)}>
              <kbd>⌘{p.key}</kbd>
              {p.label}
            </button>
          ))}
        </span>
        <button className="footbar-settings" onClick={() => setPage("settings")} title={`${t("Settings")}  ⌘,`}>
          <Icon.settings size={14} />
          {t("Settings")}
        </button>
      </footer>
      <Toaster />
      <Splash status={overview ? (overview.paused ? t("paused 0/4") : t("protecting {on}/4", { on: [overview.shell_hook.installed, overview.watch_downloads, overview.watch_extensions, overview.watch_ai_tools].filter(Boolean).length })) : t("starting")} />
    </div>
    </GoHome.Provider>
  );
}
