// Mirrors the data structures of the Rust tsuba-engine one to one

import { t } from "./i18n";

export type Verdict = "allow" | "warn" | "block";
export type Severity = "low" | "medium" | "high";
export type Provider = "claude_cli" | "codex_cli" | "claude" | "openai_compatible" | "offline";

export interface Finding {
  severity: Severity;
  message: string;
  where?: string;
  snippet?: string;
  /** Which intel source it came from and under what license ("OpenSSF Malicious Packages · Apache-2.0") */
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
  /** Looked at and ignored: kept in history, no longer counted as risky */
  dismissed?: boolean;
}

export interface Config {
  provider: Provider;
  claude: { api_key: string; model: string; effort: string; cli_path: string };
  codex: { model: string; effort: string; cli_path: string };
  openai_compatible: { base_url: string; model: string; api_key: string; preset: string; trusted: boolean };
  watch_downloads: boolean;
  watch_extensions: boolean;
  auto_quarantine: boolean;
  watch_ai_tools: boolean;
  notify_warn: boolean;
  notify_scheduled_scan: boolean;
  notify_sound: boolean;
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
  provider_preset: string;
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
  /** Real-looking secrets seen in a plaintext request, kinds only */
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
  /** Operations the sandbox denied (from the system log) */
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

// Getters, not plain values: each label is translated when it is read, after the language is known
export const VERDICT_LABEL: Record<Verdict, string> = {
  get allow() { return t("Allow"); },
  get warn() { return t("Needs Attention"); },
  get block() { return t("Block Recommended"); },
};
