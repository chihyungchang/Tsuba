// 各页面共用的界面零件：页头、分组列表、结论标签、证据列表、空状态。

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./icons";
import { Finding, Report, Verdict, VERDICT_LABEL } from "./types";

export function errText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

/** 家目录换成 ~，路径太长时读起来累 */
export function shortPath(p: string): string {
  return p.replace(/^\/Users\/[^/]+/, "~");
}

export function baseName(p: string): string {
  return p.replace(/\/+$/, "").split("/").pop() || p;
}

/** “3 分钟前”“昨天 14:20”这样的时间，记录列表里比完整时间好扫 */
export function relativeTime(iso: string): string {
  const t = new Date(iso.replace(" ", "T"));
  if (Number.isNaN(t.getTime())) return iso;
  const diff = (Date.now() - t.getTime()) / 1000;
  const hm = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
  if (diff < 60) return "刚刚";
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86400_000);
  if (t.toDateString() === today.toDateString()) return `今天 ${hm}`;
  if (t.toDateString() === yesterday.toDateString()) return `昨天 ${hm}`;
  return `${t.getMonth() + 1}月${t.getDate()}日 ${hm}`;
}

/** 回到首页。详情页的面包屑用；由 App 提供，页面不用一层层传 */
export const GoHome = createContext<() => void>(() => {});

/** 详情页左上角的“‹ 首页”：返回放在内容里，不挤在标题栏的红绿灯旁边 */
export function BackLink() {
  const goHome = useContext(GoHome);
  return (
    <button type="button" className="crumb" onClick={goHome} title="回到首页  Esc / ⌘1">
      <Icon.chevron size={12} className="crumb-chevron" />
      首页
    </button>
  );
}

export type HeaderStat = { label: string; value: ReactNode; tone?: "allow" | "warn" | "block" };

/**
 * 详情页的头部卡片，和首页仪表盘一个语言：大图标 + 标题 + 状态，右边主操作，下面一排关键数字。
 * tone 决定图标底块和状态胶囊的颜色（有问题时变琥珀或红）。
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

/** 分组列表：圆角容器，行与行之间是内缩的细线（macOS 设置的样子） */
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
  return <span className="spinner" aria-label="进行中" />;
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
        <button type="button" className="banner-close" aria-label="关闭" onClick={onClose}>
          ×
        </button>
      )}
    </div>
  );
}

const SEV_LABEL = { high: "高", medium: "中", low: "低" } as const;

export function FindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <p className="muted">离线规则没有命中。</p>;
  const order = { high: 0, medium: 1, low: 2 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  return (
    <ol className="findings">
      {sorted.map((f, i) => (
        <li key={i} className={`finding sev-${f.severity}`}>
          <span className="sev">{SEV_LABEL[f.severity]}</span>
          <div className="finding-body">
            <div className="finding-message">{f.message}</div>
            {f.where && <div className="finding-where">{f.where}</div>}
            {f.source && <div className="finding-source">来源：{f.source}</div>}
            {f.snippet && <pre className="snippet">{f.snippet}</pre>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function ReportView({ report }: { report: Report }) {
  const source = report.source === "ai" ? `AI 判断 · ${report.model}` : report.source === "trusted" ? "你标记过安全" : "离线规则";
  return (
    <div className="report">
      {report.summary && <p className="report-summary">{report.summary}</p>}
      <div className="report-source">{source}</div>
      {report.reasons.length > 0 && (
        <div className="report-block">
          <h3>依据</h3>
          <ul className="reasons">
            {report.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
      {report.advice && report.verdict !== "allow" && (
        <div className="report-block">
          <h3>建议</h3>
          <p className="advice">{report.advice}</p>
        </div>
      )}
      <div className="report-block">
        <h3>证据{report.findings.length > 0 && <span className="count-inline">{report.findings.length}</span>}</h3>
        <FindingList findings={report.findings} />
      </div>
    </div>
  );
}

/* ---------- 操作反馈 ---------- */

/** 每个操作做完给一句话反馈，让人知道点了有用 */
const DONE: Record<string, string> = {
  quarantine_path: "已移入隔离区，随时可以恢复",
  restore_quarantine: "已放回原来的位置",
  delete_quarantine: "已彻底删除",
  delete_entry_file: "文件已删除",
  trust_item: "已加入白名单，内容不变就不再提醒",
  untrust_item: "已从白名单移除",
  clear_history: "检查记录已清空",
  install_shell_hook: "已接入 zsh，新开的终端窗口生效",
  uninstall_shell_hook: "已从 zsh 移除",
};

export function toast(text: string, tone: "allow" | "block" = "allow") {
  window.dispatchEvent(new CustomEvent("tsuba-toast", { detail: { text, tone } }));
}

export function toastDone(cmd: string) {
  if (DONE[cmd]) toast(DONE[cmd]);
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
      {items.map((t) => (
        <div key={t.id} className={`toast toast-${t.tone}`}>
          {t.tone === "block" ? <Icon.alert size={14} strokeWidth={2} /> : <Icon.check size={14} strokeWidth={2} />}
          {t.text}
        </div>
      ))}
    </div>
  );
}

/** 删不回来的操作点两下：第一下变成“确认…”，三秒内再点才执行 */
export function ConfirmButton({ children, confirm, onConfirm, className = "danger" }: { children: ReactNode; confirm: string; onConfirm: () => void; className?: string }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 3000);
    return () => clearTimeout(t);
  }, [armed]);
  return (
    <button
      className={`${className} ${armed ? "is-armed" : ""}`}
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
