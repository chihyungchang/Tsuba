import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../icons";
import { AiScanItem, ExtensionScan, Finding } from "../types";
import { BackLink, Banner, FindingList, toastDone, Group, Row, Section, Spinner, VerdictBadge, errText, relativeTime } from "../ui";
import { t } from "../i18n";
import { useTask } from "../tasks";

type Check = "doctor" | "exts" | "ai";

type CheckState = "idle" | "running" | "ok" | "issue" | "failed";

/** One line of the checklist: what it looks at, then its state and result on the right */
function CheckRow({ title, detail, state, result, onRun }: { title: string; detail: string; state: CheckState; result?: string; onRun: () => void }) {
  return (
    <li className={`checklist-row is-${state}`} aria-busy={state === "running"}>
      <span className="checklist-mark" aria-hidden>
        {state === "running" ? <Spinner /> : state === "ok" ? <Icon.check size={14} /> : state === "issue" || state === "failed" ? <Icon.alert size={14} /> : null}
      </span>
      <div className="checklist-text">
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
      <span className="checklist-result">{state === "running" ? t("Checking…") : result}</span>
      {state !== "running" && state !== "idle" && (
        <button className="link checklist-again" onClick={onRun}>
          {t("Check Again")}
        </button>
      )}
    </li>
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
  useTask("doctor", t("Health Check"), "doctor", running.size > 0);
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

  const stateOf = (which: Check, done: boolean, issue: boolean): CheckState => (running.has(which) ? "running" : failed[which] ? "failed" : done ? (issue ? "issue" : "ok") : "idle");
  const failedText = (which: Check) => (failed[which] ? t("Did not finish: {error}", { error: failed[which] }) : undefined);
  const heroState = running.size > 0 ? "is-running" : allDone ? (issues === 0 ? "is-ok" : "is-issue") : "";

  return (
    <div className="page doctor-page">
      <div className="doctor-top" data-tauri-drag-region>
        <BackLink />
      </div>

      {/* One big button does the whole check; the list below says what is looked at and fills in as each part finishes */}
      <section className={`doctor-hero ${heroState}`} data-tauri-drag-region>
        <button className="doctor-start" disabled={running.size > 0} onClick={runAll} aria-label={t("Start Health Check")}>
          <span className="doctor-ring" aria-hidden />
          {running.size > 0 ? <Icon.doctor size={34} /> : allDone && issues > 0 ? <Icon.alert size={34} /> : allDone ? <Icon.check size={34} /> : <Icon.doctor size={34} />}
          <span className="doctor-start-label">{running.size > 0 ? t("Checking") : allDone || lastRun ? t("Check Again") : t("Start")}</span>
        </button>
        <h1 data-tauri-drag-region>{t("Health Check")}</h1>
        <p className={`doctor-status tone-${tone}`}>{status}</p>
        <p className="doctor-lede">{t("Already compromised? Looks for traces of known attacks and checks installed extensions and AI tools.")}</p>
      </section>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      <ul className="checklist panel">
        <CheckRow
          title={t("Infection Traces")}
          detail={t("Files known attacks leave in your personal folder, and suspicious commands in login items")}
          state={stateOf("doctor", !!doctor, !!doctor && doctor.findings.length > 0)}
          result={failedText("doctor") ?? (doctor ? (doctor.findings.length === 0 ? t("No known traces found") : doctor.findings.length === 1 ? t("Found 1 trace") : t("Found {n} traces", { n: doctor.findings.length })) : undefined)}
          onRun={() => run("doctor")}
        />
        <CheckRow
          title={t("Editor Extensions")}
          detail={t("Every extension in VS Code, Cursor, Windsurf and VSCodium, against the official malicious list and hidden-code checks")}
          state={stateOf("exts", !!exts, risky.length > 0)}
          result={failedText("exts") ?? (exts ? (risky.length === 0 ? t("{n} extensions, all clean", { n: exts.length }) : t("{n} extensions, {suspicious} suspicious", { n: exts.length, suspicious: risky.length })) : undefined)}
          onRun={() => run("exts")}
        />
        <CheckRow
          title={t("AI Coding Tools")}
          detail={t("MCP servers, skills and plugin hooks in Claude Code, Cursor, Codex and more")}
          state={stateOf("ai", !!ai, aiRisky.length > 0)}
          result={failedText("ai") ?? (ai ? (aiRisky.length === 0 ? t("{n} items, all clean", { n: ai.length }) : t("{n} items, {suspicious} suspicious", { n: ai.length, suspicious: aiRisky.length })) : undefined)}
          onRun={() => run("ai")}
        />
      </ul>

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
