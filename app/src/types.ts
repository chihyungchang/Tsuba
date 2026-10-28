// 与 Rust 端 tsuba-engine 的数据结构一一对应

export type Verdict = "allow" | "warn" | "block";
export type Severity = "low" | "medium" | "high";
export type Provider = "claude_cli" | "claude" | "openai_compatible" | "offline";

export interface Finding {
  severity: Severity;
  message: string;
  where?: string;
  snippet?: string;
  /** 来自哪份情报、按什么授权（“OpenSSF Malicious Packages · Apache-2.0”） */
  source?: string;
}

export interface Report {
  verdict: Verdict;
  summary: string;
  reasons: string[];
  advice: string;
  source: "ai" | "offline" | "trusted";
  model: string;
  findings: Finding[];
}

export interface LogEntry {
  id: string;
  time: string;
  source: "terminal" | "paste" | "download" | "mount" | "extension" | "ai_tool" | "scan";
  title: string;
  cwd: string;
  report: Report;
  action: string;
  quarantine_id?: string | null;
}

export interface Config {
  provider: Provider;
  claude: { api_key: string; model: string; effort: string; cli_path: string };
  openai_compatible: { base_url: string; model: string; api_key: string; preset: string; trusted: boolean };
  watch_downloads: boolean;
  watch_extensions: boolean;
  auto_quarantine: boolean;
  watch_ai_tools: boolean;
  intel: { auto_update: boolean; abusech_key: string; online_lookup: boolean; rules_url: string; virustotal_key: string };
  scan: { scheduled: boolean; folders: string[]; interval_days: number };
}

export interface IntelSource {
  id: string;
  name: string;
  license: string;
  url: string;
  version: string;
  updated: string;
  count: number;
  error?: string | null;
}

export interface IntelManifest {
  updated: string;
  sources: IntelSource[];
}

export interface Overview {
  paused: boolean;
  shell_hook: { installed: boolean; cli_found: boolean; cli_path: string };
  watch_downloads: boolean;
  watch_extensions: boolean;
  watch_ai_tools: boolean;
  downloads_dir: string;
  extension_dirs: string[];
  provider: Provider;
  provider_label: string;
  ai_available: boolean;
  sandbox_available: boolean;
  recent: { total: number; warned: number; blocked: number };
  quarantined: number;
  trusted: number;
}

export interface QuarantineItem {
  id: string;
  original: string;
  stored: string;
  time: string;
  reason: string;
}

export interface TrustItem {
  key: string;
  fingerprint: string;
  label: string;
  time: string;
}

export interface ScanHit {
  path: string;
  kind: "installer" | "extension" | "skill" | "project" | "file" | "trusted";
  verdict: Verdict;
  summary: string;
  findings: Finding[];
  fresh: boolean;
}

export interface FolderScan {
  root: string;
  checked: number;
  unchanged: number;
  hits: ScanHit[];
  truncated: boolean;
}

export interface NetEvent {
  target: string;
  request?: string;
  leaked?: string[];
  /** 明文请求里出现的真实格式密钥，只有种类 */
  secrets?: string[];
  forwarded?: boolean;
}

export interface Behavior {
  exit_code: number | null;
  timed_out: boolean;
  seconds: number;
  network: NetEvent[];
  new_files: string[];
  output: string;
  /** 被沙箱拦下的越权操作（来自系统日志） */
  denied?: { process: string; operation: string; target: string }[];
}

export interface SandboxResult {
  behavior: Behavior;
  findings: Finding[];
  verdict: Verdict;
}

export interface AiScanItem {
  kind: "mcp" | "skill" | "hooks";
  title: string;
  detail: string;
  verdict: Verdict;
  findings: Finding[];
  trust_key: string;
}

export interface ExtensionScan {
  id: string;
  path: string;
  verdict: Verdict;
  findings: Finding[];
}

export const VERDICT_LABEL: Record<Verdict, string> = { allow: "放行", warn: "需要注意", block: "建议拦截" };
export const SOURCE_LABEL: Record<LogEntry["source"], string> = {
  terminal: "终端命令",
  paste: "粘贴的命令",
  download: "下载",
  mount: "打开安装镜像",
  extension: "编辑器扩展",
  ai_tool: "AI 工具",
  scan: "手动检查",
};
export const ACTION_LABEL: Record<string, string> = {
  executed: "已执行",
  cancelled: "已取消",
  quarantined: "已隔离",
  ejected: "已阻止打开",
  notified: "已提醒",
  allowed: "已放行",
  deleted: "已删除",
  scanned: "",
};
