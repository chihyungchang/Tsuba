// UI parts shared by every page: page header, grouped lists, verdict badges, evidence lists, empty states.

import { Fragment, createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { lang, t } from "./i18n";
import { Icon, type IconName } from "./icons";
import { Finding, Overview, Report, Verdict, VERDICT_LABEL } from "./types";

export function errText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

/** Home directory shown as ~: long paths are tiring to read */
export function shortPath(p: string): string {
  return p.replace(/^\/Users\/[^/]+/, "~");
}

export function baseName(p: string): string {
  return p.replace(/\/+$/, "").split("/").pop() || p;
}

/**
 * Fills `{name}` placeholders in already-translated text with elements, such as a <code> inside a sentence.
 * The sentence stays whole in the catalog, so each language can put the element where its grammar wants it.
 */
export function interpolate(text: string, nodes: Record<string, ReactNode>): ReactNode {
  return text.split(/\{(\w+)\}/).map((part, i) => (i % 2 === 1 ? <Fragment key={i}>{nodes[part] ?? `{${part}}`}</Fragment> : part));
}

/** A number with the current language's digit grouping: "12,345" */
export function formatNumber(n: number): string {
  return n.toLocaleString(lang());
}

/** A large count kept short: "23.4K" in English, "2.3 万" in Chinese (Chinese groups by ten thousand) */
export function formatCompact(n: number): string {
  if (n < 10000) return formatNumber(n);
  if (lang() === "zh-Hans") return `${(n / 10000).toFixed(1)} 万`;
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

/**
 * Times like "3 min ago" or "yesterday at 2:20 PM": quicker to scan in a list than full timestamps.
 * `short` is for narrow fixed columns (the terminal log): English drops "today at" and the clock on older days,
 * since "today at 9:02 AM" is twice as wide as "今天 09:02".
 */
export function relativeTime(iso: string, { short = false } = {}): string {
  const time = new Date(iso.replace(" ", "T"));
  if (Number.isNaN(time.getTime())) return iso;
  const isChinese = lang() === "zh-Hans";
  const diff = (Date.now() - time.getTime()) / 1000;
  // Chinese keeps the 24-hour clock it always had; English follows the usual "2:20 PM"
  const clock = isChinese
    ? `${String(time.getHours()).padStart(2, "0")}:${String(time.getMinutes()).padStart(2, "0")}`
    : time.toLocaleTimeString("en", { hour: "numeric", minute: "2-digit" });
  if (diff < 60) return t("just now");
  if (diff < 3600) return t("{n} min ago", { n: Math.floor(diff / 60) });
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86400_000);
  const isToday = time.toDateString() === today.toDateString();
  const isYesterday = time.toDateString() === yesterday.toDateString();
  const date = isChinese ? `${time.getMonth() + 1}月${time.getDate()}日` : time.toLocaleDateString("en", { month: "short", day: "numeric" });
  if (short && !isChinese) return isToday ? clock : isYesterday ? "Yesterday" : date;
  if (isToday) return t("today at {time}", { time: clock });
  if (isYesterday) return t("yesterday at {time}", { time: clock });
  return t("{date} at {time}", { date, time: clock });
}

/** Go back to the dashboard. Used by the breadcrumb on detail pages; App provides it so pages don't pass it down */
export const GoHome = createContext<() => void>(() => {});

/** The "‹ Home" at the top left of detail pages: going back lives in the content, not crammed next to the traffic lights */
export function BackLink() {
  const goHome = useContext(GoHome);
  return (
    <button type="button" className="crumb" onClick={goHome} title={`${t("Back to Home")}  Esc / ⌘1`}>
      <Icon.chevron size={12} className="crumb-chevron" />
      {t("Home")}
    </button>
  );
}

export type HeaderStat = { label: string; value: ReactNode; tone?: "allow" | "warn" | "block" };

/**
 * Header card for detail pages, in the same language as the dashboard: large icon + title + status, main action on the right, a row of key numbers below.
 * tone sets the color of the icon tile and the status pill (amber or red when something is wrong).
 */
export function PageHeader({
  title,
  subtitle,
  icon,
  tone = "neutral",
  status,
  stats,
  children,
}: {
  title: string;
  subtitle?: ReactNode;
  icon?: IconName;
  tone?: "neutral" | "allow" | "warn" | "block";
  status?: ReactNode;
  stats?: HeaderStat[];
  children?: ReactNode;
}) {
  const I = icon ? Icon[icon] : null;
  return (
    <header className={`page-header ${I ? "page-hero" : ""} hero-tone-${tone}`} data-tauri-drag-region>
      {I && <BackLink />}
      <div className="page-hero-main" data-tauri-drag-region>
        {I && (
          <span className="page-hero-icon">
            <I size={26} strokeWidth={1.6} />
          </span>
        )}
        <div className="page-hero-text" data-tauri-drag-region>
          {status && <span className="page-hero-status">{status}</span>}
          <h1 data-tauri-drag-region>{title}</h1>
          {subtitle && <p className="page-subtitle">{subtitle}</p>}
        </div>
        {children && <div className="page-header-actions">{children}</div>}
      </div>
      {stats && stats.length > 0 && (
        <div className="page-hero-stats">
          {stats.map((st) => (
            <div key={st.label} className="page-hero-stat">
              <span className={`page-hero-value ${st.tone ? `tone-${st.tone}` : ""}`}>{st.value}</span>
              <span className="page-hero-label">{st.label}</span>
            </div>
          ))}
        </div>
      )}
    </header>
  );
}

export function Section({ title, aside, children }: { title?: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="section">
      {(title || aside) && (
        <div className="section-head">
          {title && <h2>{title}</h2>}
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

/** Grouped list: a rounded container with inset hairlines between rows (the macOS Settings look) */
export function Group({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`group ${className}`}>{children}</div>;
}

export function Row({
  icon,
  tone,
  title,
  detail,
  trailing,
  onClick,
  children,
}: {
  icon?: IconName;
  tone?: "neutral" | "allow" | "warn" | "block" | "brand";
  title: ReactNode;
  detail?: ReactNode;
  trailing?: ReactNode;
  onClick?: () => void;
  children?: ReactNode;
}) {
  const I = icon ? Icon[icon] : null;
  const body = (
    <>
      {I && (
        <span className={`row-icon tone-${tone ?? "neutral"}`}>
          <I size={16} />
        </span>
      )}
      <div className="row-text">
        <div className="row-title">{title}</div>
        {detail && <div className="row-detail">{detail}</div>}
      </div>
      {trailing && <div className="row-trailing">{trailing}</div>}
    </>
  );
  return (
    <div className="row-wrap">
      {onClick ? (
        <button type="button" className="row row-button" onClick={onClick}>
          {body}
        </button>
      ) : (
        <div className="row">{body}</div>
      )}
      {children}
    </div>
  );
}

export function Toggle({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      className={`toggle ${on ? "on" : ""}`}
      onClick={() => onChange(!on)}
    >
      <span />
    </button>
  );
}

const VERDICT_ICON: Record<Verdict, IconName> = { allow: "check", warn: "alert", block: "stop" };

export function VerdictBadge({ v, large }: { v: Verdict; large?: boolean }) {
  const I = Icon[VERDICT_ICON[v]];
  return (
    <span className={`badge badge-${v} ${large ? "badge-large" : ""}`}>
      <I size={large ? 15 : 12} strokeWidth={2} />
      {VERDICT_LABEL[v]}
    </span>
  );
}

export function Spinner() {
  return <span className="spinner" aria-label={t("In progress")} />;
}

export function Empty({ icon, title, children }: { icon: IconName; title: string; children?: ReactNode }) {
  const I = Icon[icon];
  return (
    <div className="empty">
      <I size={28} strokeWidth={1.25} />
      <div className="empty-title">{title}</div>
      {children && <div className="empty-detail">{children}</div>}
    </div>
  );
}

export function Banner({ tone = "block", children, onClose }: { tone?: "block" | "warn" | "allow"; children: ReactNode; onClose?: () => void }) {
  return (
    <div className={`banner banner-${tone}`} role="alert">
      <span>{children}</span>
      {onClose && (
        <button type="button" className="banner-close" aria-label={t("Close")} onClick={onClose}>
          ×
        </button>
      )}
    </div>
  );
}

// The severity tile is a 22px square: one Chinese character fits, so English gets one letter plus the full word as a tooltip
const severityLabel = (s: Finding["severity"]) => ({ high: t("H"), medium: t("M"), low: t("L") })[s];
const severityName = (s: Finding["severity"]) => ({ high: t("High severity"), medium: t("Medium severity"), low: t("Low severity") })[s];

export function FindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <p className="muted">{t("No offline rules matched.")}</p>;
  const order = { high: 0, medium: 1, low: 2 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  return (
    <ol className="findings">
      {sorted.map((f, i) => (
        <li key={i} className={`finding sev-${f.severity}`}>
          <span className="sev" title={severityName(f.severity)}>
            {severityLabel(f.severity)}
          </span>
          <div className="finding-body">
            <div className="finding-message">{f.message}</div>
            {f.where && <div className="finding-where">{f.where}</div>}
            {f.source && <div className="finding-source">{t("Source: {source}", { source: f.source })}</div>}
            {f.snippet && <pre className="snippet">{f.snippet}</pre>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function ReportView({ report }: { report: Report }) {
  const source = report.source === "ai" ? t("AI judgment · {model}", { model: report.model }) : report.source === "trusted" ? t("You marked this as safe") : t("Offline rules");
  return (
    <div className="report">
      {report.summary && <p className="report-summary">{report.summary}</p>}
      <div className="report-source">{source}</div>
      {report.reasons.length > 0 && (
        <div className="report-block">
          <h3>{t("Reasons")}</h3>
          <ul className="reasons">
            {report.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
      {report.advice && report.verdict !== "allow" && (
        <div className="report-block">
          <h3>{t("What to Do")}</h3>
          <p className="advice">{report.advice}</p>
        </div>
      )}
      <div className="report-block">
        <h3>{t("Evidence")}{report.findings.length > 0 && <span className="count-inline">{report.findings.length}</span>}</h3>
        <FindingList findings={report.findings} />
      </div>
    </div>
  );
}

/* ---------- Action feedback ---------- */

/** One line of feedback after each action, so people know the click did something */
function doneMessage(cmd: string): string | undefined {
  const messages: Record<string, string> = {
    quarantine_path: t("Moved to quarantine. You can restore it anytime."),
    restore_quarantine: t("Restored to its original location"),
    delete_quarantine: t("Permanently deleted"),
    delete_entry_file: t("File deleted"),
    trust_item: t("Added to the allowlist. You won't be warned again unless it changes."),
    untrust_item: t("Removed from the allowlist"),
    ignore_command_warning: t("Got it. Next time this command runs without asking, unless something new turns up."),
    clear_history: t("History cleared"),
    install_shell_hook: t("Connected to zsh. Takes effect in new terminal windows."),
    uninstall_shell_hook: t("Removed from zsh"),
  };
  return messages[cmd];
}

export function toast(text: string, tone: "allow" | "block" = "allow") {
  window.dispatchEvent(new CustomEvent("tsuba-toast", { detail: { text, tone } }));
}

export function toastDone(cmd: string) {
  const message = doneMessage(cmd);
  if (message) toast(message);
}

export function Toaster() {
  const [items, setItems] = useState<{ id: number; text: string; tone: string }[]>([]);
  useEffect(() => {
    let n = 0;
    const on = (e: Event) => {
      const { text, tone } = (e as CustomEvent).detail;
      const id = ++n;
      setItems((xs) => [...xs.slice(-2), { id, text, tone }]);
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 2600);
    };
    window.addEventListener("tsuba-toast", on);
    return () => window.removeEventListener("tsuba-toast", on);
  }, []);
  return (
    <div className="toaster" aria-live="polite">
      {items.map((item) => (
        <div key={item.id} className={`toast toast-${item.tone}`}>
          <span className="toast-mark">{item.tone === "block" ? <Icon.alert size={12} strokeWidth={2} /> : <Icon.check size={12} strokeWidth={2} />}</span>
          {item.text}
        </div>
      ))}
    </div>
  );
}

/** Actions that can't be undone take two clicks: the first turns the button into "Confirm…", and only a second click within three seconds runs it */
export function ConfirmButton({ children, confirm, onConfirm, className = "danger", label }: { children: ReactNode; confirm: string; onConfirm: () => void; className?: string; label?: string }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const timer = setTimeout(() => setArmed(false), 3000);
    return () => clearTimeout(timer);
  }, [armed]);
  return (
    <button
      className={`${className} ${armed ? "is-armed" : ""}`}
      aria-label={armed ? confirm : label}
      title={armed ? undefined : label}
      onClick={() => {
        if (armed) {
          setArmed(false);
          onConfirm();
        } else setArmed(true);
      }}
    >
      {armed ? confirm : children}
    </button>
  );
}

/** A button that opens a short list of related actions, so variants of one action take one slot in a toolbar */
export function MenuButton({ label, disabled, items }: { label: ReactNode; disabled?: boolean; items: { label: string; detail?: string; onSelect: () => void }[] }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: Event) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);
  return (
    <span className="menu-button" ref={root}>
      <button type="button" disabled={disabled} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        {label}
        <Icon.chevron size={11} className="menu-chevron" />
      </button>
      {open && (
        <span className="menu" role="menu">
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                item.onSelect();
              }}
            >
              <span>{item.label}</span>
              {item.detail && <span className="menu-detail">{item.detail}</span>}
            </button>
          ))}
        </span>
      )}
    </span>
  );
}

/** A short name for how verdicts are made, for the footer button and the Settings nav */
export function modeLabel(overview: Overview | null): string {
  if (!overview) return t("Connecting…");
  if (overview.provider === "offline") return t("Offline Only");
  if (!overview.ai_available) return t("AI Not Set Up");
  switch (overview.provider) {
    case "claude_cli":
      return "Claude Code";
    case "codex_cli":
      return "Codex";
    case "claude":
      return "Claude API";
    default:
      // "preset · model": the model is what people recognise
      return overview.provider_label.split(" · ")[1] || t("Other Models");
  }
}
