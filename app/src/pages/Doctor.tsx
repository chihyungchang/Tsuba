import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, type IconName } from "../icons";
import { AiScanItem, ExtensionScan, Finding } from "../types";
import { Banner, FindingList, toastDone, Group, PageHeader, Row, Section, Spinner, VerdictBadge, errText } from "../ui";

type Check = "doctor" | "exts" | "ai";

function CheckCard({
  icon,
  title,
  detail,
  done,
  issue,
  error,
  busy,
  onRun,
}: {
  icon: IconName;
  title: string;
  detail: string;
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
        {busy && <div className="check-done muted">正在检查…</div>}
        {!busy && error && <div className="check-done tone-block">没查完：{error}</div>}
        {!busy && !error && done && <div className={`check-done ${issue ? "tone-warn" : "tone-allow"}`}>{done}</div>}
      </div>
      <button disabled={busy} onClick={onRun}>
        {busy ? <Spinner /> : null}
        {busy ? "检查中" : done || error ? "再查一次" : "开始"}
      </button>
      {busy && <span className="check-progress" />}
    </div>
  );
}

export function DoctorPage({ reload }: { reload: () => void }) {
  const [doctor, setDoctor] = useState<{ findings: Finding[]; advice: string } | null>(null);
  const [exts, setExts] = useState<ExtensionScan[] | null>(null);
  const [ai, setAi] = useState<AiScanItem[] | null>(null);
  // 三项检查互不相干，各自记进行中和出错，可以同时跑：点了一项再点另一项，前一项照常跑完
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
  // 已经在跑的不重复启动，其余的一起开始
  const runAll = () => (Object.keys(CHECKS) as Check[]).filter((c) => !running.has(c)).forEach(run);
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
  const allDone = doctor && exts && ai && running.size === 0;

  return (
    <div className="page">
      <PageHeader title="体检" subtitle="已经中招了吗？查一遍已知攻击留下的痕迹、已装的扩展和 AI 工具。">
        <button className="primary" disabled={running.size === 3} onClick={runAll}>
          {running.size > 0 ? <Spinner /> : <Icon.doctor size={14} />}
          {running.size === 0 ? "全部检查" : running.size === 3 ? "体检中" : `检查其余 ${3 - running.size} 项`}
        </button>
      </PageHeader>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      {allDone && (
        <div className={`verdict-panel ${issues === 0 ? "is-ok" : "is-issue"}`}>
          {issues === 0 ? <Icon.check size={22} strokeWidth={2} /> : <Icon.alert size={22} strokeWidth={2} />}
          <div>
            <div className="verdict-panel-title">{issues === 0 ? "没有发现问题" : `${issues} 处需要看一下`}</div>
            <div className="verdict-panel-detail">
              {exts.length} 个扩展、{aiCount("mcp")} 个 MCP server、{aiCount("skill")} 个 skill 都查过了
            </div>
          </div>
        </div>
      )}

      <div className="check-grid">
        <CheckCard
          icon="overview"
          title="感染痕迹"
          detail="隐藏的 Node 依赖目录、可疑的开机自启项、被改写的启动脚本"
          done={doctor ? (doctor.findings.length === 0 ? "没有发现已知痕迹" : `发现 ${doctor.findings.length} 处痕迹`) : null}
          issue={!!doctor && doctor.findings.length > 0}
          error={failed.doctor}
          busy={running.has("doctor")}
          onRun={() => run("doctor")}
        />
        <CheckCard
          icon="extension"
          title="编辑器扩展"
          detail="VS Code、Cursor、Windsurf 里已装的扩展，只用离线规则，几秒钟"
          done={exts ? `${exts.length} 个扩展，${risky.length === 0 ? "都正常" : `${risky.length} 个可疑`}` : null}
          issue={risky.length > 0}
          error={failed.exts}
          busy={running.has("exts")}
          onRun={() => run("exts")}
        />
        <CheckCard
          icon="plug"
          title="AI 编程工具"
          detail="Claude Code、Cursor、Codex 装的 MCP server、skill 和插件 hooks"
          done={ai ? `${ai.length} 项，${aiRisky.length === 0 ? "都正常" : `${aiRisky.length} 项可疑`}` : null}
          issue={aiRisky.length > 0}
          error={failed.ai}
          busy={running.has("ai")}
          onRun={() => run("ai")}
        />
      </div>

      {doctor && doctor.findings.length > 0 && (
        <Section title="感染痕迹">
          <div className="panel">
            <FindingList findings={doctor.findings} />
            {doctor.advice && <p className="advice">{doctor.advice}</p>}
          </div>
        </Section>
      )}

      {risky.length > 0 && (
        <Section title="可疑的扩展">
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
                      <button className="primary" onClick={() => act("quarantine_path", { path: x.path, reason: "体检时手动隔离" })}>
                        移入隔离区
                      </button>
                      <button onClick={() => act("trust_item", { key: x.path })}>我确认它安全</button>
                      <button className="link" onClick={() => invoke("reveal_in_finder", { path: x.path })}>
                        在 Finder 中显示
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
        <Section title="可疑的 AI 工具配置">
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
                      <button onClick={() => act("trust_item", { key: x.trust_key })}>我确认它安全</button>
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
