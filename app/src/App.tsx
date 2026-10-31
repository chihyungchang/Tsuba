import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Splash } from "./brand";
import { t, useLang } from "./i18n";
import { Icon, Kamon, type IconName } from "./icons";
import { DoctorPage } from "./pages/Doctor";
import { HistoryPage } from "./pages/History";
import { OverviewPage } from "./pages/Overview";
import { ScanPage } from "./pages/Scan";
import { SettingsPage, type SettingsTab } from "./pages/Settings";
import { LogEntry, Overview, QuarantineItem } from "./types";
import { runningTasks, useRunningTasks } from "./tasks";
import { GoHome, Spinner, Toaster, modeLabel, toast } from "./ui";
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

/** The footer icon is the logo of whoever makes the call: the coding tool, the API provider, or a lock for offline only */
function modeIcon(overview: Overview | null): IconName {
  switch (overview?.provider) {
    case "claude_cli":
    case "claude":
      return "claude";
    case "codex_cli":
      return "openai";
    case "openai_compatible":
      return overview.provider_preset === "openai" ? "openai" : overview.provider_preset === "gemini" ? "gemini" : "globe";
    default:
      return "lock";
  }
}

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

  const pageRef = useRef(page);
  const setPage = useCallback((p: Page) => {
    // Leaving a page whose task is still running: say it carries on, so leaving doesn't feel like cancelling
    const left = runningTasks().filter((task) => task.page === pageRef.current && p !== pageRef.current);
    for (const task of left) toast(t("{task} keeps running in the background. Its progress is at the bottom left.", { task: task.label }));
    pageRef.current = p;
    setPageState(p);
    history.replaceState(null, "", `#${p}`);
  }, []);

  // Tell the user when a task finishes while they are on another page
  const tasks = useRunningTasks();
  const previousTasks = useRef(tasks);
  useEffect(() => {
    for (const task of previousTasks.current) {
      if (!tasks.some((x) => x.id === task.id) && task.page !== pageRef.current) toast(t("{task} finished", { task: task.label }));
    }
    previousTasks.current = tasks;
  }, [tasks]);
  const elsewhere = tasks.filter((task) => task.page !== page);

  // One quiet check at launch: a new version shows as a pill in the footer, and failures (offline, rate limits) stay silent
  const [newVersion, setNewVersion] = useState<string | null>(null);
  useEffect(() => {
    invoke<{ version: string } | null>("check_update")
      .then((u) => setNewVersion(u?.version ?? null))
      .catch(() => {});
  }, []);

  const [settingsTab, setSettingsTab] = useState<SettingsTab>("protection");
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
      listen<SettingsTab>("open-settings", (e) => {
        setSettingsTab(e.payload);
        setPage("settings");
      }),
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
  const riskyCount = overview ? overview.recent.warned + overview.recent.blocked : 0;
  const goHome = useCallback(() => setPage("overview"), [setPage]);

  // While paused the whole window takes the warning color: on every page the user should feel "nothing is protecting me now"
  useEffect(() => {
    document.documentElement.toggleAttribute("data-paused", paused);
  }, [paused]);

  return (
    <GoHome.Provider value={goHome}>
    <div className={`shell ${paused ? "is-paused" : ""}`}>
      {/* Title bar: the traffic lights, the mark centered and the bell at the right; each page carries its own heading, and going back lives in the breadcrumb inside the content. Running tasks show in the footer. */}
      <header className="titlebar" data-tauri-drag-region>
        <span className="titlebar-status" data-tauri-drag-region>
          <Kamon size={17} />
          Tsuba
        </span>
        <button className="titlebar-bell" title={t("Needs attention")} aria-label={t("Needs attention")} onClick={() => setPage("history")}>
          <Icon.bell size={15} />
          {riskyCount > 0 && <span className="titlebar-badge">{riskyCount > 99 ? "99+" : riskyCount}</span>}
        </button>
      </header>
      <main className={`content content-${page}`}>
        {/* Pages with long tasks stay mounted behind the others: switching away must not drop a running check's result */}
        <div className="page-host" hidden={page !== "overview"}>
          <OverviewPage overview={overview} reload={reload} onScanned={onScanned} openEntry={openEntry} go={setPage} visible={page === "overview"} />
        </div>
        <div className="page-host" hidden={page !== "history"}>
          <HistoryPage focusId={focusId} quarantine={quarantine} reload={reload} />
        </div>
        <div className="page-host" hidden={page !== "scan"}>
          <ScanPage quarantine={quarantine} reload={reload} onScanned={onScanned} />
        </div>
        <div className="page-host" hidden={page !== "doctor"}>
          <DoctorPage reload={reload} />
        </div>
        {page === "settings" && <SettingsPage overview={overview} reload={reload} tab={settingsTab} onTab={setSettingsTab} />}
      </main>
      <footer className="footbar">
        <button className="footbar-icon" title="GitHub" aria-label="GitHub" onClick={() => invoke("open_link", { url: "https://github.com/chihyungchang/Tsuba" })}>
          <Icon.github size={14} />
        </button>
        <button
          className="footbar-icon"
          onClick={() => {
            setSettingsTab("judgment");
            setPage("settings");
          }}
          aria-label={modeLabel(overview)}
          title={overview ? (overview.provider === "offline" ? t("Offline rules only") : overview.ai_available ? t("Offline rules + {provider}", { provider: overview.provider_label }) : t("Offline rules (AI not set up yet)")) : undefined}
        >
          {(() => {
            const ModeIcon = Icon[modeIcon(overview)];
            return <ModeIcon size={15} />;
          })()}
        </button>
        {elsewhere.length > 0 && (
          <button className="footbar-task" onClick={() => setPage(elsewhere[0].page as Page)} title={t("Go to it")}>
            <Spinner />
            {elsewhere.length === 1 ? t("{task} running…", { task: elsewhere[0].label }) : t("{n} tasks running…", { n: elsewhere.length })}
          </button>
        )}
        {newVersion && (
          <button
            className="footbar-task footbar-update"
            onClick={() => {
              setSettingsTab("about");
              setPage("settings");
            }}
          >
            <Icon.arrowDown size={12} />
            {t("Version {version} is available", { version: newVersion })}
          </button>
        )}
        <span className="footbar-spacer" />
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
