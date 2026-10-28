import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, type IconName } from "../icons";
import { AiScanItem, ExtensionScan, Finding } from "../types";
import { Banner, FindingList, toastDone, Group, PageHeader, Row, Section, Spinner, VerdictBadge, errText, relativeTime } from "../ui";
import { t } from "../i18n";

type Check = "doctor" | "exts" | "ai";

function CheckCard({
  icon,
  title,
  detail,
  done,
  issue,
  points,
  error,
  busy,
  onRun,
}: {
  icon: IconName;
  title: string;
  detail: string;
  points: string[];
  done: string | null;
  issue?: boolean;
  error?: string;
  busy: boolean;
  onRun: () => void;
}) {
  const I = Icon[icon];
  const state = busy ? "is-running" : error ? "is-failed" : done ? (issue ? "is-issue" : "is-ok") : "";
  return (
    <div className={`check-card ${state}`} aria-busy={busy}>
      <span className="check-icon">
        <I size={18} />
      </span>
      <div className="check-text">
        <h3>{title}</h3>
        <p>{detail}</p>
        <ul className="check-points">
          {points.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
        {busy && <div className="check-done muted">{t("Checking…")}</div>}
        {!busy && error && <div className="check-done tone-block">{t("Did not finish: {error}", { error })}</div>}
        {!busy && !error && done && <div className={`check-done ${issue ? "tone-warn" : "tone-allow"}`}>{done}</div>}
      </div>
      <button disabled={busy} onClick={onRun}>
        {busy ? <Spinner /> : null}
        {busy ? t("Checking") : done || error ? t("Check Again") : t("Start")}
      </button>
      {busy && <span className="check-progress" />}
    </div>
  );
}

/**
 * When the last full run finished and how it went, kept on this Mac, so the header can say so before a new run.
 * Stored as an ISO time and a count only, so it reads the same in any language.
 */
const LAST_RUN_KEY = "tsuba-doctor-last";
type LastRun = { time: string; issues: number };

function loadLastRun(): LastRun | null {
  try {
    return JSON.parse(localStorage.getItem(LAST_RUN_KEY) ?? "null");
  } catch {
    return null;
  }
}

const issuesToReview = (n: number) => (n === 1 ? t("1 issue to review") : t("{n} issues to review", { n }));

export function DoctorPage({ reload }: { reload: () => void }) {
  const [lastRun, setLastRun] = useState<LastRun | null>(loadLastRun);
  const [doctor, setDoctor] = useState<{ findings: Finding[]; advice: string } | null>(null);
  const [exts, setExts] = useState<ExtensionScan[] | null>(null);
  const [ai, setAi] = useState<AiScanItem[] | null>(null);
  // The three checks are independent and track running and failure separately, so they can run at once: starting one does not interrupt another
  const [running, setRunning] = useState<ReadonlySet<Check>>(new Set());
  const [failed, setFailed] = useState<Partial<Record<Check, string>>>({});
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState("");

  const CHECKS: Record<Check, () => Promise<void>> = {
    doctor: async () => setDoctor(await invoke("run_doctor")),
    exts: async () => setExts(await invoke("scan_installed_extensions")),
    ai: async () => setAi(await invoke("scan_ai_tools")),
  };
  const run = async (which: Check) => {
    setRunning((s) => new Set(s).add(which));
    setFailed((f) => ({ ...f, [which]: undefined }));
    try {
      await CHECKS[which]();
    } catch (e) {
      setFailed((f) => ({ ...f, [which]: errText(e) }));
    } finally {
      setRunning((s) => {
        const next = new Set(s);
        next.delete(which);
        return next;
      });
    }
  };
  // Start everything that is not already running
  const runAll = () => (Object.keys(CHECKS) as Check[]).filter((c) => !running.has(c)).forEach(run);

  // "Health Check" on the dashboard: jump to this page and start every check
  const runAllRef = useRef(runAll);
  runAllRef.current = runAll;
  useEffect(() => {
    const onRun = () => runAllRef.current();
    window.addEventListener("tsuba-run-doctor", onRun);
    return () => window.removeEventListener("tsuba-run-doctor", onRun);
  }, []);
  const act = async (cmd: string, args: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      toastDone(cmd);
      reload();
      if (cmd === "quarantine_path" || cmd === "trust_item") setExts((xs) => xs?.filter((x) => x.path !== args.path && x.path !== args.key) ?? null);
      if (cmd === "trust_item") setAi((xs) => xs?.filter((x) => x.trust_key !== args.key) ?? null);
    } catch (e) {
      setError(errText(e));
    }
  };

  const risky = exts?.filter((x) => x.verdict !== "allow") ?? [];
  const aiRisky = ai?.filter((x) => x.verdict !== "allow") ?? [];
  const aiCount = (k: AiScanItem["kind"]) => ai?.filter((x) => x.kind === k).length ?? 0;
  const issues = (doctor?.findings.length ?? 0) + risky.length + aiRisky.length;
  const allDone = !!(doctor && exts && ai) && running.size === 0;

  useEffect(() => {
    if (!allDone) return;
    const run = { time: new Date().toISOString(), issues };
    setLastRun(run);
    try {
      localStorage.setItem(LAST_RUN_KEY, JSON.stringify(run));
    } catch {
      // Not remembered: next time there is just no "last Health Check", the checks are unaffected
    }
  }, [allDone, issues]);

  const status =
    running.size > 0
      ? t("Running Health Check…")
      : allDone
        ? issues === 0
          ? t("Nothing found this time")
          : issuesToReview(issues)
        : lastRun
          ? `${t("Last Health Check {time}", { time: relativeTime(lastRun.time) })} · ${lastRun.issues === 0 ? t("no problems found") : issuesToReview(lastRun.issues)}`
          : t("No Health Check yet");
  const tone = running.size > 0 ? "neutral" : allDone ? (issues === 0 ? "allow" : "warn") : lastRun && lastRun.issues > 0 ? "warn" : "neutral";

  return (
    <div className="page">
      <PageHeader
        title={t("Health Check")}
        subtitle={t("Already compromised? Looks for traces of known attacks and checks installed extensions and AI tools.")}
        icon="doctor"
        tone={tone}
        status={status}
        stats={[
          { label: t("Infection Traces"), value: doctor ? (doctor.findings.length === 0 ? t("None") : t("{n} found", { n: doctor.findings.length })) : "—", tone: doctor ? (doctor.findings.length ? "block" : "allow") : undefined },
          { label: t("Editor Extensions"), value: exts ? t("{n} · {suspicious} suspicious", { n: exts.length, suspicious: risky.length }) : "—", tone: exts ? (risky.length ? "warn" : "allow") : undefined },
          { label: t("AI Coding Tools"), value: ai ? `${t("{mcp} MCP · {skills} skill", { mcp: aiCount("mcp"), skills: aiCount("skill") })}${aiRisky.length ? ` · ${t("{n} suspicious", { n: aiRisky.length })}` : ""}` : "—", tone: ai ? (aiRisky.length ? "warn" : "allow") : undefined },
        ]}
      >
        <button className="primary" disabled={running.size === 3} onClick={runAll}>
          {running.size > 0 ? <Spinner /> : <Icon.doctor size={14} />}
          {running.size === 0 ? t("Check All") : running.size === 3 ? t("Checking") : t("Check Remaining {n}", { n: 3 - running.size })}
        </button>
      </PageHeader>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      <div className="check-grid">
        <CheckCard
          icon="overview"
          title={t("Infection Traces")}
          detail={t("Files known attacks leave behind. Takes a few seconds.")}
          points={[t("Drop folders attack groups favor in your home folder, such as ~/.node_modules, ~/.task and ~/.n2"), t("Suspicious commands in login items (node, curl, base64 decoding)"), t("The trace list updates daily with the rule pack")]}
          done={doctor ? (doctor.findings.length === 0 ? t("No known traces found") : doctor.findings.length === 1 ? t("Found 1 trace") : t("Found {n} traces", { n: doctor.findings.length })) : null}
          issue={!!doctor && doctor.findings.length > 0}
          error={failed.doctor}
          busy={running.has("doctor")}
          onRun={() => run("doctor")}
        />
        <CheckCard
          icon="extension"
          title={t("Editor Extensions")}
          detail={t("Installed extensions, offline rules only. Takes a few seconds.")}
          points={[t("Every extension in VS Code, Cursor, Windsurf and VSCodium"), t("Official malicious extension lists, code hidden in invisible characters"), t("Activation on startup, suspicious network and file access")]}
          done={exts ? (risky.length === 0 ? t("{n} extensions, all clean", { n: exts.length }) : t("{n} extensions, {suspicious} suspicious", { n: exts.length, suspicious: risky.length })) : null}
          issue={risky.length > 0}
          error={failed.exts}
          busy={running.has("exts")}
          onRun={() => run("exts")}
        />
        <CheckCard
          icon="plug"
          title={t("AI Coding Tools")}
          detail={t("Configuration and add-ons of AI coding tools")}
          points={[t("MCP servers in Claude Code, Cursor, Codex and more"), t("Installed skills and plugin hooks"), t("Tool poisoning, instructions to hide things from you, reading private keys")]}
          done={ai ? (aiRisky.length === 0 ? t("{n} items, all clean", { n: ai.length }) : t("{n} items, {suspicious} suspicious", { n: ai.length, suspicious: aiRisky.length })) : null}
          issue={aiRisky.length > 0}
          error={failed.ai}
          busy={running.has("ai")}
          onRun={() => run("ai")}
        />
      </div>

      {doctor && doctor.findings.length > 0 && (
        <Section title={t("Infection Traces")}>
          <div className="panel">
            <FindingList findings={doctor.findings} />
            {doctor.advice && <p className="advice">{doctor.advice}</p>}
          </div>
        </Section>
      )}

      {risky.length > 0 && (
        <Section title={t("Suspicious Extensions")}>
          <Group>
            {risky.map((x) => (
              <Row
                key={x.path}
                icon="extension"
                tone={x.verdict === "block" ? "block" : "warn"}
                title={<span className="mono-title">{x.id}</span>}
                detail={x.findings[0]?.message}
                trailing={
                  <>
                    <VerdictBadge v={x.verdict} />
                    <Icon.chevron size={14} className={`chevron ${open === x.path ? "is-open" : ""}`} />
                  </>
                }
                onClick={() => setOpen(open === x.path ? null : x.path)}
              >
                {open === x.path && (
                  <div className="row-expand">
                    <FindingList findings={x.findings} />
                    <div className="toolbar">
                      <button className="primary" onClick={() => act("quarantine_path", { path: x.path, reason: t("Quarantined manually during Health Check") })}>
                        {t("Move to Quarantine")}
                      </button>
                      <button onClick={() => act("trust_item", { key: x.path })}>{t("Mark as Safe")}</button>
                      <button className="link" onClick={() => invoke("reveal_in_finder", { path: x.path })}>
                        {t("Show in Finder")}
                      </button>
                    </div>
                  </div>
                )}
              </Row>
            ))}
          </Group>
        </Section>
      )}

      {aiRisky.length > 0 && (
        <Section title={t("Suspicious AI Tool Configurations")}>
          <Group>
            {aiRisky.map((x) => (
              <Row
                key={x.kind + x.detail}
                icon="plug"
                tone={x.verdict === "block" ? "block" : "warn"}
                title={x.title}
                detail={<span className="mono">{x.detail}</span>}
                trailing={
                  <>
                    <VerdictBadge v={x.verdict} />
                    <Icon.chevron size={14} className={`chevron ${open === x.detail ? "is-open" : ""}`} />
                  </>
                }
                onClick={() => setOpen(open === x.detail ? null : x.detail)}
              >
                {open === x.detail && (
                  <div className="row-expand">
                    <FindingList findings={x.findings} />
                    <div className="toolbar">
                      <button onClick={() => act("trust_item", { key: x.trust_key })}>{t("Mark as Safe")}</button>
                    </div>
                  </div>
                )}
              </Row>
            ))}
          </Group>
        </Section>
      )}

    </div>
  );
}
