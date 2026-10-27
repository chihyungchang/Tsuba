// 与 Rust 端 tsuba-engine 的数据结构一一对应

export type Verdict = "allow" | "warn" | "block";
export type Severity = "low" | "medium" | "high";
export type Provider = "claude" | "openai_compatible" | "offline";

export interface Finding {
  severity: Severity;
  message: string;
  where?: string;
  snippet?: string;
}

export interface Report {
  verdict: Verdict;
  summary: string;
  reasons: string[];
  advice: string;
  source: "ai" | "offline";
  model: string;
  findings: Finding[];
}

export interface LogEntry {
  id: string;
  time: string;
  source: "terminal" | "paste" | "download" | "extension" | "scan";
  title: string;
  cwd: string;
  report: Report;
  action: string;
  quarantine_id?: string | null;
}

export interface Config {
  provider: Provider;
  claude: { api_key: string; model: string; effort: string };
  openai_compatible: { base_url: string; model: string; api_key: string; preset: string; trusted: boolean };
  watch_downloads: boolean;
  watch_extensions: boolean;
  auto_quarantine: boolean;
}

export interface Overview {
  paused: boolean;
  shell_hook: { installed: boolean; cli_found: boolean; cli_path: string };
  watch_downloads: boolean;
  watch_extensions: boolean;
  downloads_dir: string;
  extension_dirs: string[];
  provider: Provider;
  provider_label: string;
  ai_available: boolean;
  recent: { total: number; warned: number; blocked: number };
  quarantined: number;
}

export interface QuarantineItem {
  id: string;
  original: string;
  stored: string;
  time: string;
  reason: string;
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
  extension: "编辑器扩展",
  scan: "手动检查",
};
export const ACTION_LABEL: Record<string, string> = {
  executed: "已执行",
  cancelled: "已取消",
  quarantined: "已隔离",
  notified: "已提醒",
  allowed: "已放行",
  scanned: "",
};
