import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, type IconName } from "../icons";
import { AiScanItem, ExtensionScan, Finding } from "../types";
import { Banner, FindingList, toastDone, Group, PageHeader, Row, Section, Spinner, VerdictBadge, errText, relativeTime } from "../ui";

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

/** 上次全部检查完的时间和结论，记在本机：没跑过体检时，页面头部也能告诉用户上次是什么时候、结果如何 */
const LAST_RUN_KEY = "tsuba-doctor-last";
type LastRun = { time: string; issues: number };

function loadLastRun(): LastRun | null {
  try {
    return JSON.parse(localStorage.getItem(LAST_RUN_KEY) ?? "null");
  } catch {
    return null;
  }
}

export function DoctorPage({ reload }: { reload: () => void }) {
  const [lastRun, setLastRun] = useState<LastRun | null>(loadLastRun);
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

  // 仪表盘上的“全面体检”：跳到这一页并开始全部检查
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
      // 记不住只是下次看不到“上次体检”，不影响检查
    }
  }, [allDone, issues]);

  const status =
    running.size > 0
      ? "体检中…"
      : allDone
        ? issues === 0
          ? "这次没有发现问题"
          : `${issues} 处需要看一下`
        : lastRun
          ? `上次体检 ${relativeTime(lastRun.time)} · ${lastRun.issues === 0 ? "没有发现问题" : `${lastRun.issues} 处需要看一下`}`
          : "还没有体检过";
  const tone = running.size > 0 ? "neutral" : allDone ? (issues === 0 ? "allow" : "warn") : lastRun && lastRun.issues > 0 ? "warn" : "neutral";

  return (
    <div className="page">
      <PageHeader
        title="体检"
        subtitle="已经中招了吗？查一遍已知攻击留下的痕迹、已装的扩展和 AI 工具。"
        icon="doctor"
        tone={tone}
        status={status}
        stats={[
          { label: "感染痕迹", value: doctor ? (doctor.findings.length === 0 ? "未发现" : `${doctor.findings.length} 处`) : "—", tone: doctor ? (doctor.findings.length ? "block" : "allow") : undefined },
          { label: "编辑器扩展", value: exts ? `${exts.length} 个 · ${risky.length} 个可疑` : "—", tone: exts ? (risky.length ? "warn" : "allow") : undefined },
          { label: "AI 编程工具", value: ai ? `${aiCount("mcp")} 个 MCP · ${aiCount("skill")} 个 skill${aiRisky.length ? ` · ${aiRisky.length} 项可疑` : ""}` : "—", tone: ai ? (aiRisky.length ? "warn" : "allow") : undefined },
        ]}
      >
        <button className="primary" disabled={running.size === 3} onClick={runAll}>
          {running.size > 0 ? <Spinner /> : <Icon.doctor size={14} />}
          {running.size === 0 ? "全部检查" : running.size === 3 ? "体检中" : `检查其余 ${3 - running.size} 项`}
        </button>
      </PageHeader>

      {error && <Banner onClose={() => setError("")}>{error}</Banner>}

      <div className="check-grid">
        <CheckCard
          icon="overview"
          title="感染痕迹"
          detail="已知攻击留下的落地痕迹，几秒钟"
          points={["家目录里攻击组织常用的落地目录，如 ~/.node_modules、~/.task、~/.n2", "开机自启项里的可疑命令（node、curl、base64 解码）", "痕迹清单随规则包每天更新"]}
          done={doctor ? (doctor.findings.length === 0 ? "没有发现已知痕迹" : `发现 ${doctor.findings.length} 处痕迹`) : null}
          issue={!!doctor && doctor.findings.length > 0}
          error={failed.doctor}
          busy={running.has("doctor")}
          onRun={() => run("doctor")}
        />
        <CheckCard
          icon="extension"
          title="编辑器扩展"
          detail="已装的扩展，只用离线规则，几秒钟"
          points={["VS Code、Cursor、Windsurf、VSCodium 里所有扩展", "官方恶意扩展名单、不可见字符藏代码", "启动即激活、可疑的网络和文件访问"]}
          done={exts ? `${exts.length} 个扩展，${risky.length === 0 ? "都正常" : `${risky.length} 个可疑`}` : null}
          issue={risky.length > 0}
          error={failed.exts}
          busy={running.has("exts")}
          onRun={() => run("exts")}
        />
        <CheckCard
          icon="plug"
          title="AI 编程工具"
          detail="AI 编程工具的配置和扩展"
          points={["Claude Code、Cursor、Codex 等的 MCP server", "已安装的 skill 和插件 hooks", "工具投毒、要求对用户隐瞒、读取私钥"]}
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
