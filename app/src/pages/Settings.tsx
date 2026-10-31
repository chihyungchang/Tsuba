import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon, TsubaMark, type IconName } from "../icons";
import { LANGS, loadLangPreference, setLangPreference, t, type LangPreference } from "../i18n";
import { loadThemePreference, setThemePreference, type ThemePreference } from "../theme";
import { Config, IntelManifest, Overview } from "../types";
import { BackLink, Banner, Group, Row, modeLabel, Section, Spinner, Toggle, errText, formatNumber, interpolate, listSeparator, relativeTime, shortPath, toast, toastDone } from "../ui";

type PresetGroup = "frontier" | "cloud" | "router" | "local" | "custom";

type Preset = { id: string; name: string; group: PresetGroup; url: string; trusted: boolean; key: boolean; help?: string };

// All use the OpenAI-compatible API. Frontier models are trusted by default; the rest can only Warn by default.
// Routers serve many vendors' models behind one key, so like Custom they let the user mark the chosen model as frontier.
// `id` is saved in the config file, so it never changes; names are proper nouns except the translated ones.
// `help` is where to get an API key (or, for local servers, how to install one).
const presets = (): Preset[] => [
  { id: "openai", name: "OpenAI", group: "frontier", url: "https://api.openai.com/v1", trusted: true, key: true, help: "https://platform.openai.com/api-keys" },
  { id: "gemini", name: "Gemini", group: "frontier", url: "https://generativelanguage.googleapis.com/v1beta/openai", trusted: true, key: true, help: "https://aistudio.google.com/apikey" },
  { id: "deepseek", name: "DeepSeek", group: "cloud", url: "https://api.deepseek.com/v1", trusted: false, key: true, help: "https://platform.deepseek.com/api_keys" },
  { id: "qwen", name: t("Qwen"), group: "cloud", url: "https://dashscope.aliyuncs.com/compatible-mode/v1", trusted: false, key: true, help: "https://bailian.console.aliyun.com/" },
  { id: "moonshot", name: t("Kimi (Moonshot)"), group: "cloud", url: "https://api.moonshot.cn/v1", trusted: false, key: true, help: "https://platform.moonshot.cn/console/api-keys" },
  { id: "zhipu", name: t("Zhipu GLM"), group: "cloud", url: "https://open.bigmodel.cn/api/paas/v4", trusted: false, key: true, help: "https://open.bigmodel.cn/usercenter/apikeys" },
  { id: "minimax", name: "MiniMax", group: "cloud", url: "https://api.minimax.io/v1", trusted: false, key: true, help: "https://platform.minimax.io/" },
  { id: "volcengine", name: t("Doubao (Volcengine Ark)"), group: "cloud", url: "https://ark.cn-beijing.volces.com/api/v3", trusted: false, key: true, help: "https://console.volcengine.com/ark" },
  { id: "qianfan", name: t("Baidu Qianfan"), group: "cloud", url: "https://qianfan.baidubce.com/v2", trusted: false, key: true, help: "https://console.bce.baidu.com/qianfan/" },
  { id: "stepfun", name: "StepFun", group: "cloud", url: "https://api.stepfun.ai/v1", trusted: false, key: true, help: "https://platform.stepfun.ai/" },
  { id: "xai", name: "xAI Grok", group: "cloud", url: "https://api.x.ai/v1", trusted: false, key: true, help: "https://console.x.ai/" },
  { id: "mistral", name: "Mistral", group: "cloud", url: "https://api.mistral.ai/v1", trusted: false, key: true, help: "https://console.mistral.ai/api-keys" },
  { id: "openrouter", name: "OpenRouter", group: "router", url: "https://openrouter.ai/api/v1", trusted: false, key: true, help: "https://openrouter.ai/settings/keys" },
  { id: "siliconflow", name: t("SiliconFlow (China)"), group: "router", url: "https://api.siliconflow.cn/v1", trusted: false, key: true, help: "https://cloud.siliconflow.cn/account/ak" },
  { id: "siliconflow_global", name: t("SiliconFlow (Global)"), group: "router", url: "https://api.siliconflow.com/v1", trusted: false, key: true, help: "https://cloud.siliconflow.com/account/ak" },
  { id: "together", name: "Together AI", group: "router", url: "https://api.together.xyz/v1", trusted: false, key: true, help: "https://api.together.ai/settings/api-keys" },
  { id: "nvidia", name: "NVIDIA NIM", group: "router", url: "https://integrate.api.nvidia.com/v1", trusted: false, key: true, help: "https://build.nvidia.com/" },
  { id: "huggingface", name: "Hugging Face", group: "router", url: "https://router.huggingface.co/v1", trusted: false, key: true, help: "https://huggingface.co/settings/tokens" },
  { id: "novita", name: "Novita AI", group: "router", url: "https://api.novita.ai/openai", trusted: false, key: true, help: "https://novita.ai/settings/key-management" },
  { id: "aihubmix", name: "AIHubMix", group: "router", url: "https://aihubmix.com/v1", trusted: false, key: true, help: "https://aihubmix.com/" },
  { id: "ollama", name: "Ollama", group: "local", url: "http://127.0.0.1:11434/v1", trusted: false, key: false, help: "https://ollama.com/download" },
  { id: "lmstudio", name: "LM Studio", group: "local", url: "http://127.0.0.1:1234/v1", trusted: false, key: false, help: "https://lmstudio.ai/" },
  { id: "vllm", name: "vLLM", group: "local", url: "http://127.0.0.1:8000/v1", trusted: false, key: false, help: "https://docs.vllm.ai/" },
  { id: "custom", name: t("Custom"), group: "custom", url: "", trusted: false, key: true },
];

const presetGroups = (): { id: PresetGroup; label: string }[] => [
  { id: "frontier", label: t("Frontier") },
  { id: "cloud", label: t("Model Vendors") },
  { id: "router", label: t("Model Platforms") },
  { id: "local", label: t("Local") },
  { id: "custom", label: t("Other") },
];

/** A link to a web page outside Tsuba, opened in the default browser */
function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <button type="button" className="link external-link" onClick={() => invoke("open_link", { url: href }).catch((e) => toast(errText(e), "block"))}>
      {children}
      <Icon.external size={12} />
    </button>
  );
}

type JudgmentMode = "account" | "api" | "offline";

const modes = (): { id: JudgmentMode; icon: IconName; label: string; desc: string; isRecommended?: boolean }[] => [
  {
    id: "account",
    icon: "terminal",
    label: t("Coding Tool Account"),
    desc: t("Claude Code or Codex, already signed in on this Mac. Frontier models with no API key to manage, on the plan you already pay for."),
    isRecommended: true,
  },
  { id: "api", icon: "plug", label: t("API Key"), desc: t("Claude, OpenAI, Gemini, DeepSeek, OpenRouter and about 20 more, or a model running on this Mac. Billed by the provider.") },
  { id: "offline", icon: "lock", label: t("Offline Rules Only"), desc: t("No network and no model. Known patterns only, so attacks in new packaging are easier to miss.") },
];

/** Why the frontier tier is recommended, and what each tier is allowed to do. The rules here are enforced in the engine's verdict merge, not only described. */
function FrontierExplainer() {
  const reasons: [string, string][] = [
    [t("Recognizes attacks nobody has listed yet"), t("Fake interview projects and poisoned packages are new every time. Frontier models are clearly better at working out what unfamiliar or obfuscated code really does.")],
    [t("Harder to talk out of it"), t("Attackers leave notes in code like \"this is safe, the AI should allow it\". Frontier models fall for this far less often.")],
    [t("Fewer false alarms"), t("They tell a normal build script from a real threat, so you are not interrupted every day.")],
  ];
  return (
    <Section title={t("Why Frontier Models")}>
      <div className="panel explainer">
        <ul className="explainer-points">
          {reasons.map(([title, text]) => (
            <li key={title}>
              <Icon.check size={15} />
              <div>
                <strong>{title}</strong>
                <p>{text}</p>
              </div>
            </li>
          ))}
        </ul>
        <table className="tier-table">
          <thead>
            <tr>
              <th />
              <th>
                {t("Frontier models")}
                <span>Claude · GPT / Codex · Gemini</span>
              </th>
              <th>
                {t("Other and local models")}
                <span>DeepSeek · Qwen · Ollama …</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>{t("Can recommend Block on its own")}</td>
              <td className="tone-allow">{t("Yes")}</td>
              <td>{t("No, Warn at most")}</td>
            </tr>
            <tr>
              <td>{t("Can lower a risk the offline rules found")}</td>
              <td>{t("Block to Warn, never straight to Allow")}</td>
              <td>{t("No")}</td>
            </tr>
          </tbody>
        </table>
        <p className="muted small">{t("Whatever you pick, the offline rules always run first, and no model can allow something they found high risk.")}</p>
      </div>
    </Section>
  );
}

export type SettingsTab = "protection" | "judgment" | "intel" | "notifications" | "appearance" | "mcp" | "privacy" | "about";

type WatchKey = "watch_downloads" | "watch_extensions" | "watch_ai_tools";

/** Four defenses: the terminal hook and watching Downloads, extension folders and AI tools. The dashboard only shows their state; the switches live here. */
function DefenseSection({ overview, reload }: { overview: Overview; reload: () => void }) {
  const [error, setError] = useState("");
  const act = async (cmd: string, args?: Record<string, unknown>) => {
    setError("");
    try {
      await invoke(cmd, args);
      toastDone(cmd);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };
  const setWatch = async (key: WatchKey, on: boolean) => {
    const cfg = await invoke<Config>("get_config");
    await act("save_config", { config: { ...cfg, [key]: on } });
  };
  const hook = overview.shell_hook;
  const editors = overview.extension_dirs
    .map((d) => d.split("/").slice(-2, -1)[0].replace(/^\./, ""))
    .map((n) => ({ vscode: "VS Code", cursor: "Cursor", windsurf: "Windsurf", "vscode-oss": "VSCodium" })[n] ?? n);
  const editorList = editors.join(listSeparator());
  return (
    <Section title={t("Defenses")}>
      {error && <Banner onClose={() => setError("")}>{error}</Banner>}
      <Group>
        <Row
          icon="terminal"
          title={t("Terminal Commands")}
          detail={
            hook.cli_found ? (
              interpolate(t("Checks {curl}, {npm} and {git} before they run, and warns when you paste a command"), {
                curl: <code>curl | bash</code>,
                npm: <code>npm install</code>,
                git: <code>git clone</code>,
              })
            ) : (
              <span className="tone-block">{t("Can't find the Tsuba checker. Reinstall Tsuba.")}</span>
            )
          }
          trailing={
            hook.installed ? (
              <span className="trailing-status">
                <span className="status-dot" />
                {t("Connected")}
                <button className="link" onClick={() => act("uninstall_shell_hook")}>
                  {t("Remove")}
                </button>
              </span>
            ) : (
              <button className="primary" disabled={!hook.cli_found} onClick={() => act("install_shell_hook")}>
                {t("Connect to zsh")}
              </button>
            )
          }
        />
        <Row
          icon="package"
          title={t("Installers")}
          detail={t("New .dmg, .pkg and .vsix files in {dir}; high-risk disk images are ejected as soon as they're opened", { dir: shortPath(overview.downloads_dir) })}
          trailing={<Toggle label={t("Installers")} on={overview.watch_downloads} onChange={(v) => setWatch("watch_downloads", v)} />}
        />
        <Row
          icon="extension"
          title={t("Editor Extensions")}
          detail={editors.length > 0 ? t("New or updated extensions in {editors}; high-risk ones are moved to quarantine", { editors: editorList }) : t("No VS Code, Cursor or Windsurf found")}
          trailing={<Toggle label={t("Editor Extensions")} on={overview.watch_extensions} onChange={(v) => setWatch("watch_extensions", v)} />}
        />
        <Row
          icon="plug"
          title={t("AI Coding Tools")}
          detail={t("New MCP servers, skills and plugin hooks, plus the .mcp.json and CLAUDE.md that come with projects")}
          trailing={<Toggle label={t("AI Coding Tools")} on={overview.watch_ai_tools} onChange={(v) => setWatch("watch_ai_tools", v)} />}
        />
      </Group>
    </Section>
  );
}

/** Opens check history to Claude Code and similar tools (tsuba mcp). It's read-only, so we only show the command and never edit the user's AI tool config for them. */
function McpSection({ cliPath }: { cliPath: string }) {
  const command = `claude mcp add tsuba -- ${cliPath.includes(" ") ? `"${cliPath}"` : cliPath} mcp`;
  const copy = () => navigator.clipboard.writeText(command).then(() => toast(t("Command copied. Paste it into Terminal to run it.")));
  return (
    <Section title={t("Let AI Coding Tools Query Tsuba")}>
      <div className="panel prose">
        <p>
          {interpolate(
            t("Ask Claude Code things like \"why was this blocked?\" or \"what's in quarantine?\". Run the command below in Terminal to connect it; for Cursor and other tools, enter {command} in their MCP settings."),
            { command: <code>{cliPath} mcp</code> },
          )}
        </p>
        <div className="copy-line">
          <code className="mono">{command}</code>
          <button onClick={copy}>{t("Copy")}</button>
        </div>
        <p className="muted">{t("Read-only: it can look up history and quarantine, but can't quarantine, delete or allow anything. Commands and summaries it returns are marked as untrusted data, and secrets are always hidden.")}</p>
      </div>
    </Section>
  );
}

// Functions, not constants: labels must be translated at render time, after the language is known
const themes = (): { id: ThemePreference; label: string }[] => [
  { id: "system", label: t("System") },
  { id: "light", label: t("Light") },
  { id: "dark", label: t("Dark") },
];


function Segmented<T extends string>({ label, options, value, onChange }: { label: string; options: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="segmented segmented-inline" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" role="radio" aria-checked={value === o.id} className={value === o.id ? "on" : ""} onClick={() => onChange(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

function AppearanceSection() {
  const [theme, setTheme] = useState(loadThemePreference);
  const [lang, setLang] = useState(loadLangPreference);
  return (
    <Section title={t("Appearance")}>
      <Group>
        <Row
          title={t("Color Mode")}
          detail={t("When following the system, Tsuba switches along with macOS dark mode")}
          trailing={
            <Segmented
              label={t("Color Mode")}
              options={themes()}
              value={theme}
              onChange={(v) => {
                setTheme(v);
                setThemePreference(v);
              }}
            />
          }
        />
        <Row
          title={t("Language")}
          detail={t("Also used for notifications, the menu bar menu and new check results. Past results keep the language they were checked in.")}
          trailing={
            // Ten languages don't fit a segmented control; language names stay in their own language (LANGS)
            <select
              className="lang-select"
              aria-label={t("Language")}
              value={lang}
              onChange={(e) => {
                const v = e.target.value as LangPreference;
                setLang(v);
                setLangPreference(v);
              }}
            >
              <option value="system">{t("System")}</option>
              {LANGS.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          }
        />
      </Group>
    </Section>
  );
}

function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <span className="field-control">
        {children}
        {hint && <span className="field-hint">{hint}</span>}
      </span>
    </label>
  );
}

/** What each intel source is for, in plain words, and where to read about it. Keyed by the source ID the engine reports. */
function sourceAbout(id: string): { text: string; link?: string } | undefined {
  const repo = "https://github.com/chihyungchang/Tsuba";
  return (
    {
      tsuba: { text: t("Tsuba's own patterns for fake interview projects, poisoned packages and attacks on AI tools"), link: `${repo}/blob/main/crates/engine/rules/tsuba.yar` },
      ossf: { text: t("Confirmed malicious npm and PyPI packages, checked before installs and across lockfiles") },
      vscode: { text: t("Extensions Microsoft has taken down from the Marketplace"), link: "https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md" },
      abusech: { text: t("Domains, IPs and download links currently used by malware") },
      elastic: { text: t("Signatures of known malware families") },
      reversinglabs: { text: t("Signatures of known malware families") },
      guarddog: { text: t("Patterns common in malicious packages; evidence only, never blocks on its own") },
      xprotect: { text: t("Apple's built-in malware signatures, read from this Mac"), link: "https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web" },
      yara: { text: t("All the signatures above, compiled together for fast checks") },
    } as Record<string, { text: string; link?: string }>
  )[id];
}

type UpdateState =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "latest" }
  | { kind: "available"; version: string }
  | { kind: "installing"; version: string; done: number; total: number | null }
  | { kind: "failed"; error: string };

/** The running version and updates from GitHub Releases. Installing restarts Tsuba into the new version. */
function AboutSection() {
  const [version, setVersion] = useState("");
  const [state, setState] = useState<UpdateState>({ kind: "idle" });

  const check = async () => {
    setState({ kind: "checking" });
    try {
      const u = await invoke<{ version: string } | null>("check_update");
      setState(u ? { kind: "available", version: u.version } : { kind: "latest" });
    } catch (e) {
      setState({ kind: "failed", error: errText(e) });
    }
  };
  useEffect(() => {
    invoke<string>("app_version").then(setVersion);
    check();
    const un = listen<[number, number | null]>("update-progress", (e) =>
      setState((s) => (s.kind === "installing" ? { ...s, done: e.payload[0], total: e.payload[1] } : s)),
    );
    return () => {
      un.then((f) => f());
    };
  }, []);

  const install = async (next: string) => {
    setState({ kind: "installing", version: next, done: 0, total: null });
    try {
      // On success the App restarts and this never returns
      await invoke("install_update");
    } catch (e) {
      setState({ kind: "failed", error: errText(e) });
    }
  };
  const megabytes = (n: number) => (n / 1048576).toFixed(1);

  return (
    <Section title={t("About & Updates")}>
      <div className="panel about">
        <div className="about-head">
          <TsubaMark size={44} />
          <div>
            <strong>Tsuba</strong>
            <span className="muted">{version ? t("Version {version}", { version }) : "…"}</span>
          </div>
          <span className="about-action">
            {state.kind === "available" ? (
              <button className="primary" onClick={() => install(state.version)}>
                {t("Update and Restart")}
              </button>
            ) : (
              <button disabled={state.kind === "checking" || state.kind === "installing"} onClick={check}>
                {state.kind === "checking" ? <Spinner /> : null}
                {state.kind === "checking" ? t("Checking") : t("Check for Updates")}
              </button>
            )}
          </span>
        </div>
        <div className="about-status">
          {state.kind === "latest" && (
            <span className="tone-allow">
              <Icon.check size={14} /> {t("You're on the latest version")}
            </span>
          )}
          {state.kind === "available" && (
            <span>
              <span className="tone-warn">{t("Version {version} is available", { version: state.version })}</span>{" "}
              <ExternalLink href={`https://github.com/chihyungchang/Tsuba/releases/tag/v${state.version}`}>{t("What's New")}</ExternalLink>
            </span>
          )}
          {state.kind === "installing" && (
            <div className="about-progress">
              <span>
                {state.total ? t("Downloading {done} of {total} MB", { done: megabytes(state.done), total: megabytes(state.total) }) : t("Downloading {done} MB", { done: megabytes(state.done) })}
              </span>
              <span className="about-bar">
                <span style={{ width: state.total ? `${Math.min(100, (state.done / state.total) * 100)}%` : "30%" }} />
              </span>
            </div>
          )}
          {state.kind === "failed" && <span className="tone-block">{state.error}</span>}
        </div>
        <p className="muted small">{t("Updates come from Tsuba's GitHub Releases and are installed only if their signature matches Tsuba's signing key, so a tampered download is refused.")}</p>
      </div>
    </Section>
  );
}

function IntelSection({ cfg, onChange }: { cfg: Config; onChange: (c: Config) => void }) {
  const [m, setM] = useState<IntelManifest | null>(null);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    invoke<IntelManifest>("intel_status").then(setM);
    const uns = [
      listen<string>("intel-progress", (e) => setProgress(e.payload)),
      listen("intel-updated", () => {
        setProgress("");
        invoke<IntelManifest>("intel_status").then(setM);
      }),
    ];
    return () => {
      uns.forEach((u) => u.then((f) => f()));
    };
  }, []);

  const update = async () => {
    setError("");
    setProgress(t("Starting update"));
    try {
      setM(await invoke<IntelManifest>("intel_update"));
    } catch (e) {
      setError(errText(e));
    } finally {
      setProgress("");
    }
  };
  const setIntel = (patch: Partial<Config["intel"]>) => onChange({ ...cfg, intel: { ...cfg.intel, ...patch } });

  return (
    <Section
      title={t("Threat Intel")}
      aside={
        <span className="section-aside">
          {progress ? (
            <>
              <Spinner /> {progress}
            </>
          ) : m?.updated ? (
            t("Updated {time}", { time: relativeTime(m.updated) })
          ) : (
            t("Never updated")
          )}
          <button className="link" disabled={!!progress} onClick={update}>
            {t("Update Now")}
          </button>
        </span>
      }
    >
      {error && <Banner onClose={() => setError("")}>{error}</Banner>}
      <p className="section-lede">
        {t("Free public lists of known malicious packages, extensions and addresses, plus malware signatures. Tsuba downloads them to this Mac and checks against them locally.")}
      </p>
      <Group>
        {m?.sources.map((s) => {
          const about = sourceAbout(s.id);
          // abuse.ch is skipped until the user adds a key; say so in the current language instead of showing the stored message
          const needsKey = s.id === "abusech" && !cfg.intel.abusech_key;
          const link = s.url.startsWith("https://") ? s.url : about?.link;
          return (
            <Row
              key={s.id}
              title={s.name}
              detail={
                <>
                  {about?.text}
                  {about?.text && s.license !== "-" ? " · " : ""}
                  {s.license !== "-" && s.license}
                  {s.error && !needsKey && <span className="tone-block"> · {s.error}</span>}
                  {(link || needsKey) && (
                    <span className="intel-links">
                      {needsKey && <ExternalLink href="https://auth.abuse.ch/">{t("Get a free Auth-Key")}</ExternalLink>}
                      {link && <ExternalLink href={link}>{t("Learn More")}</ExternalLink>}
                    </span>
                  )}
                </>
              }
              trailing={needsKey ? <span className="tone-warn small">{t("Needs an Auth-Key")}</span> : s.error ? <span className="tone-block small">{t("Not updated")}</span> : <span className="num">{t("{count} entries", { count: formatNumber(s.count) })}</span>}
            />
          );
        })}
        <Row title={t("Update Daily")} trailing={<Toggle label={t("Update Daily")} on={cfg.intel.auto_update} onChange={(v) => setIntel({ auto_update: v })} />} />
        <Row
          title={t("Look Up OSV.dev Online")}
          detail={t("Queries live while checking npm and PyPI packages, so new reports reach you sooner than the local list. Sends only the package name and version.")}
          trailing={<Toggle label={t("Look Up OSV.dev Online")} on={cfg.intel.online_lookup} onChange={(v) => setIntel({ online_lookup: v })} />}
        />
      </Group>
      <div className="panel form">
        <Field
          label="VirusTotal API Key"
          hint={
            <>
              {t("Optional. Sends only the file's SHA-256 to get verdicts from 70+ engines; files are never uploaded.")}{" "}
              {t("Sign up for free, then copy the key from your profile's API Key page.")}
              <ExternalLink href="https://www.virustotal.com/gui/my-apikey">{t("Get a free key")}</ExternalLink>
            </>
          }
        >
          <input type="password" placeholder={t("Not set")} value={cfg.intel.virustotal_key} onChange={(e) => setIntel({ virustotal_key: e.target.value.trim() })} />
        </Field>
        <Field
          label="abuse.ch Auth-Key"
          hint={
            <>
              {t("Optional. The free tier is for non-profit use only.")} {t("Sign in at auth.abuse.ch, then copy the Auth-Key from your profile.")}
              <ExternalLink href="https://auth.abuse.ch/">{t("Get a free Auth-Key")}</ExternalLink>
            </>
          }
        >
          <input type="password" placeholder={t("Not set")} value={cfg.intel.abusech_key} onChange={(e) => setIntel({ abusech_key: e.target.value.trim() })} />
        </Field>
      </div>
    </Section>
  );
}

/** The open category is held by the App, so other places (the footer's model icon) can open Settings at a given one */
export function SettingsPage({ overview, reload, tab, onTab }: { overview: Overview | null; reload: () => void; tab: SettingsTab; onTab: (tab: SettingsTab) => void }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [listing, setListing] = useState(false);
  const [cliPath, setCliPath] = useState<string | null>(null);
  const [codexPath, setCodexPath] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    invoke<Config>("get_config").then((c) => {
      setCfg(c);
      invoke<string | null>("detect_claude_cli", { configured: c.claude.cli_path }).then(setCliPath);
      invoke<string | null>("detect_codex_cli", { configured: c.codex.cli_path }).then(setCodexPath);
    });
  }, []);
  if (!cfg) return null;

  const set = (patch: Partial<Config>) => {
    setCfg({ ...cfg, ...patch });
    setDirty(true);
    setStatus(null);
  };
  const saveNow = async (next: Config) => {
    // Switches save immediately; unsaved edits in the form are saved along with them
    setCfg(next);
    await invoke("save_config", { config: next });
    setDirty(false);
    reload();
  };
  const oc = cfg.openai_compatible;
  const setOc = (patch: Partial<Config["openai_compatible"]>) => set({ openai_compatible: { ...oc, ...patch } });
  const presetList = presets();
  const preset = presetList.find((p) => p.id === oc.preset);
  const mode: JudgmentMode = cfg.provider === "offline" ? "offline" : cfg.provider === "claude_cli" || cfg.provider === "codex_cli" ? "account" : "api";
  const pickMode = (m: JudgmentMode) => {
    if (m === mode) return;
    // Account: Codex only when Claude Code isn't installed. API key: back to whichever kind was set up before, Claude first.
    if (m === "account") set({ provider: !cliPath && codexPath ? "codex_cli" : "claude_cli" });
    else if (m === "api") set({ provider: !cfg.claude.api_key && (oc.api_key || oc.model) ? "openai_compatible" : "claude" });
    else set({ provider: "offline" });
  };

  const fetchModels = async () => {
    setListing(true);
    setStatus(null);
    try {
      const list = await invoke<string[]>("list_models", { baseUrl: oc.base_url, apiKey: oc.api_key });
      setModels(list);
      setStatus({ ok: true, text: list.length === 1 ? t("Found 1 model") : t("Found {count} models", { count: list.length }) });
    } catch (e) {
      setStatus({ ok: false, text: errText(e) });
    } finally {
      setListing(false);
    }
  };
  const save = async () => {
    try {
      await invoke("save_config", { config: cfg });
      setDirty(false);
      setStatus({ ok: true, text: t("Saved") });
      reload();
    } catch (e) {
      setStatus({ ok: false, text: errText(e) });
    }
  };
  const test = async () => {
    setTesting(true);
    setStatus(null);
    try {
      setStatus({ ok: true, text: await invoke<string>("test_ai", { config: cfg }) });
    } catch (e) {
      setStatus({ ok: false, text: errText(e) });
    } finally {
      setTesting(false);
    }
  };

  const defensesOn = overview ? [overview.shell_hook.installed, overview.watch_downloads, overview.watch_extensions, overview.watch_ai_tools].filter(Boolean).length : 0;
  const tabs: { id: SettingsTab; icon: IconName; label: string; hint?: string; tone?: "warn" | "block" }[] = [
    { id: "protection", icon: "overview", label: t("Protection"), hint: overview ? t("{on} / 4", { on: defensesOn }) : undefined, tone: overview?.paused ? "block" : undefined },
    {
      id: "judgment",
      icon: "brain",
      label: t("Judgment"),
      hint: overview ? modeLabel(overview) : undefined,
      tone: overview && overview.provider !== "offline" && !overview.ai_available ? "warn" : undefined,
    },
    { id: "intel", icon: "globe", label: t("Threat Intel") },
    { id: "notifications", icon: "bell", label: t("Notifications") },
    { id: "appearance", icon: "settings", label: t("Appearance") },
    ...(overview?.shell_hook.cli_found ? [{ id: "mcp" as const, icon: "plug" as const, label: t("Connect AI Tools") }] : []),
    { id: "privacy", icon: "lock", label: t("Privacy") },
    { id: "about", icon: "refresh", label: t("About & Updates") },
  ];

  return (
    <div className="split">
      <aside className="list-pane settings-nav">
        <div className="list-head" data-tauri-drag-region>
          <BackLink />
          <h1 data-tauri-drag-region>{t("Settings")}</h1>
          {overview && (
            <span className={`settings-state ${overview.paused ? "tone-block" : "tone-allow"}`}>
              <span className="status-dot" />
              {overview.paused ? t("Protection is paused") : t("Protection is on")}
            </span>
          )}
        </div>
        <nav className="list-scroll" aria-label={t("Settings")}>
          {tabs.map((x) => {
            const I = Icon[x.icon];
            return (
              <button key={x.id} className={`settings-tab ${tab === x.id ? "selected" : ""}`} aria-current={tab === x.id ? "page" : undefined} onClick={() => onTab(x.id)}>
                <I size={16} />
                <span className="settings-tab-label">{x.label}</span>
                {x.hint && <span className={`settings-tab-hint ${x.tone ? `tone-${x.tone}` : ""}`}>{x.hint}</span>}
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="detail-pane">
        <div className="detail-drag" data-tauri-drag-region />
        <div className="settings-body" key={tab}>
      {tab === "protection" && overview && <DefenseSection overview={overview} reload={reload} />}

      {tab === "judgment" && (
      <>
      <Section title={t("Judgment")}>
        <p className="section-lede">{t("Offline rules always run first. A model then reads the evidence in context: it cuts false alarms and catches attacks in packaging no rule has seen yet.")}</p>
        <div className="mode-list" role="radiogroup" aria-label={t("Judgment")}>
          {modes().map((m) => {
            const I = Icon[m.icon];
            const on = mode === m.id;
            return (
              <button key={m.id} type="button" role="radio" aria-checked={on} className={`mode ${on ? "on" : ""}`} onClick={() => pickMode(m.id)}>
                <span className="mode-radio" />
                <span className="mode-icon">
                  <I size={17} />
                </span>
                <span className="mode-text">
                  <span className="mode-title">
                    {m.label}
                    {m.isRecommended && <span className="mode-badge">{t("Recommended")}</span>}
                  </span>
                  <span className="mode-desc">{m.desc}</span>
                </span>
              </button>
            );
          })}
        </div>

        {cfg.provider !== "offline" && (
          <div className="panel form">
            {(cfg.provider === "claude_cli" || cfg.provider === "codex_cli") && (
              <Field label={t("Coding Tool")}>
                <div className="segmented segmented-inline" role="radiogroup" aria-label={t("Coding Tool")}>
                  {(
                    [
                      ["claude_cli", "Claude Code"],
                      ["codex_cli", "Codex"],
                    ] as const
                  ).map(([v, l]) => (
                    <button key={v} type="button" role="radio" aria-checked={cfg.provider === v} className={cfg.provider === v ? "on" : ""} onClick={() => set({ provider: v })}>
                      {l}
                    </button>
                  ))}
                </div>
              </Field>
            )}
            {cfg.provider === "codex_cli" && (
              <>
                <Field
                  label={t("codex Command")}
                  hint={
                    codexPath ? (
                      <span className="tone-allow">{t("Found at {path}", { path: codexPath })}</span>
                    ) : (
                      <span className="tone-block">{t("Not found. Install Codex or the ChatGPT app and sign in, or enter its location here.")}</span>
                    )
                  }
                >
                  <input
                    value={cfg.codex.cli_path}
                    placeholder={t("Find automatically")}
                    onChange={(e) => set({ codex: { ...cfg.codex, cli_path: e.target.value.trim() } })}
                    onBlur={() => invoke<string | null>("detect_codex_cli", { configured: cfg.codex.cli_path }).then(setCodexPath)}
                  />
                </Field>
                <Field label={t("Model")} hint={t("Leave empty to use Codex's default model")}>
                  <input value={cfg.codex.model} placeholder={t("Codex default")} onChange={(e) => set({ codex: { ...cfg.codex, model: e.target.value.trim() } })} />
                </Field>
                <Field label={t("Thinking Effort")}>
                  <div className="segmented segmented-inline">
                    {(
                      [
                        ["low", t("Fast")],
                        ["medium", t("Medium")],
                        ["high", t("Thorough")],
                      ] as const
                    ).map(([v, l]) => (
                      <button key={v} type="button" className={cfg.codex.effort === v ? "on" : ""} onClick={() => set({ codex: { ...cfg.codex, effort: v } })}>
                        {l}
                      </button>
                    ))}
                  </div>
                </Field>
              </>
            )}
            {cfg.provider === "claude_cli" && (
              <Field
                label={t("claude Command")}
                hint={
                  cliPath ? (
                    <span className="tone-allow">{t("Found at {path}", { path: cliPath })}</span>
                  ) : (
                    <span className="tone-block">{t("Not found. Install Claude Code and run claude once in Terminal to sign in, or enter its location here.")}</span>
                  )
                }
              >
                <input
                  value={cfg.claude.cli_path}
                  placeholder={t("Find automatically")}
                  onChange={(e) => set({ claude: { ...cfg.claude, cli_path: e.target.value.trim() } })}
                  onBlur={() => invoke<string | null>("detect_claude_cli", { configured: cfg.claude.cli_path }).then(setCliPath)}
                />
              </Field>
            )}
            {mode === "api" && (
                <Field
                  label={t("Provider")}
                  hint={
                    cfg.provider === "claude" ? (
                      <ExternalLink href="https://console.anthropic.com/settings/keys">{t("Get a {name} API key", { name: "Claude" })}</ExternalLink>
                    ) : (
                      preset?.help && <ExternalLink href={preset.help}>{preset.key ? t("Get a {name} API key", { name: preset.name }) : t("Install {name}", { name: preset.name })}</ExternalLink>
                    )
                  }
                >
                  <div className="preset-groups">
                    {presetGroups().map((g) => (
                      <div key={g.id} className="preset-group">
                        <span className="preset-group-label">{g.label}</span>
                        <div className="chips">
                          {/* Claude speaks its own API rather than the OpenAI-compatible one, but to the user it is just another provider */}
                          {g.id === "frontier" && (
                            <button type="button" className={`chip ${cfg.provider === "claude" ? "on" : ""}`} onClick={() => set({ provider: "claude" })}>
                              Claude
                            </button>
                          )}
                          {presetList
                            .filter((p) => p.group === g.id)
                            .map((p) => (
                              <button
                                key={p.id}
                                type="button"
                                className={`chip ${cfg.provider === "openai_compatible" && oc.preset === p.id ? "on" : ""}`}
                                onClick={() => {
                                  setModels([]);
                                  set({ provider: "openai_compatible", openai_compatible: { ...oc, preset: p.id, base_url: p.id === "custom" ? oc.base_url : p.url, trusted: p.trusted, model: "" } });
                                }}
                              >
                                {p.name}
                              </button>
                            ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Field>
            )}
            {cfg.provider === "claude" && (
              <Field label="API Key">
                <input type="password" value={cfg.claude.api_key} placeholder="sk-ant-…" onChange={(e) => set({ claude: { ...cfg.claude, api_key: e.target.value.trim() } })} />
              </Field>
            )}
            {(cfg.provider === "claude" || cfg.provider === "claude_cli") && (
              <>
                <Field label={t("Model")}>
                  <select value={cfg.claude.model} onChange={(e) => set({ claude: { ...cfg.claude, model: e.target.value } })}>
                    <option value="claude-opus-5-5">{t("Claude Opus 5.5 (Recommended)")}</option>
                    <option value="claude-sonnet-5-5">{t("Claude Sonnet 5.5 (Faster, Cheaper)")}</option>
                    <option value="claude-haiku-4-5">{t("Claude Haiku 4.5 (Fastest, Cheapest)")}</option>
                  </select>
                </Field>
                {!cfg.claude.model.startsWith("claude-haiku") && (
                  <Field label={t("Thinking Effort")}>
                    <div className="segmented segmented-inline">
                      {(
                        [
                          ["low", t("Fast")],
                          ["medium", t("Medium")],
                          ["high", t("Thorough")],
                        ] as const
                      ).map(([v, l]) => (
                        <button key={v} type="button" className={cfg.claude.effort === v ? "on" : ""} onClick={() => set({ claude: { ...cfg.claude, effort: v } })}>
                          {l}
                        </button>
                      ))}
                    </div>
                  </Field>
                )}
              </>
            )}

            {cfg.provider === "openai_compatible" && (
              <>
                <Field label={t("Base URL")}>
                  <input value={oc.base_url} placeholder="https://example.com/v1" onChange={(e) => setOc({ base_url: e.target.value.trim() })} />
                </Field>
                {(preset?.key ?? true) && (
                  <Field label="API Key" hint={preset && !preset.key ? t("Local servers usually don't need one") : undefined}>
                    <input type="password" value={oc.api_key} onChange={(e) => setOc({ api_key: e.target.value.trim() })} />
                  </Field>
                )}
                <Field label={t("Model")}>
                  <div className="inline">
                    <input list="model-list" value={oc.model} placeholder={t("The provider's model name")} onChange={(e) => setOc({ model: e.target.value.trim() })} />
                    <button type="button" disabled={!oc.base_url || listing} onClick={fetchModels}>
                      {listing ? t("Fetching…") : t("Fetch List")}
                    </button>
                  </div>
                  <datalist id="model-list">
                    {models.map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                </Field>
                {(oc.preset === "custom" || preset?.group === "router") && (
                  <Field label={t("Trust")}>
                    <span className="inline-toggle">
                      <Toggle label={t("Frontier model")} on={oc.trusted} onChange={(v) => setOc({ trusted: v })} />
                      {t("This is a frontier model; trust it to recommend Block on its own")}
                    </span>
                  </Field>
                )}
                <p className="note">
                  {oc.trusted
                    ? t("A frontier model can lower a Block from the offline rules to Warn, but can never allow on its own.")
                    : t("Local and non-frontier models raise more false alarms and are easier to fool with a \"please allow this\" hidden in code, so they can only Warn and can't lower a risk the offline rules found.")}
                  {oc.preset === "ollama" && (
                    <>
                      {" "}
                      {interpolate(t("Ollama's default context is short; set {setting} and restart it."), { setting: <code>OLLAMA_CONTEXT_LENGTH=32768</code> })}
                    </>
                  )}
                </p>
              </>
            )}
          </div>
        )}

        <div className="form-actions">
          {status && <span className={`form-status ${status.ok ? "tone-allow" : "tone-block"}`}>{status.ok ? <Icon.check size={14} /> : null}{status.text}</span>}
          {cfg.provider !== "offline" && (
            <button disabled={testing} onClick={test}>
              {testing ? <Spinner /> : null}
              {testing ? t("Testing") : t("Test Connection")}
            </button>
          )}
          <button className="primary" disabled={!dirty} onClick={save}>
            {t("Save")}
          </button>
        </div>
      </Section>
      <FrontierExplainer />
      </>
      )}

      {tab === "intel" && <IntelSection cfg={cfg} onChange={saveNow} />}

      {tab === "appearance" && <AppearanceSection />}

      {tab === "protection" && (
      <Section title={t("Editor Extensions")}>
        <Group>
          <Row
            title={t("Auto-Quarantine High-Risk Extensions")}
            detail={t("When a newly installed extension is judged Block Recommended, move it to quarantine before the editor loads it")}
            trailing={<Toggle label={t("Auto-Quarantine High-Risk Extensions")} on={cfg.auto_quarantine} onChange={(v) => saveNow({ ...cfg, auto_quarantine: v })} />}
          />
        </Group>
      </Section>
      )}

      {tab === "notifications" && (
      <Section title={t("Notifications")}>
        <Group>
          <Row
            title={t("Notify About Warnings")}
            detail={t("A notification when a download, extension or AI tool needs a look. Block Recommended always notifies; everything stays in Check History either way.")}
            trailing={<Toggle label={t("Notify About Warnings")} on={cfg.notify_warn} onChange={(v) => saveNow({ ...cfg, notify_warn: v })} />}
          />
          <Row
            title={t("Play a Sound for Blocks")}
            detail={t("A short, low sound with Block Recommended notifications. Warnings stay silent.")}
            trailing={<Toggle label={t("Play a Sound for Blocks")} on={cfg.notify_sound} onChange={(v) => saveNow({ ...cfg, notify_sound: v })} />}
          />
          <Row
            title={t("Notify After Scheduled Scans")}
            detail={t("A notification when the regular rescan of your folders finds something")}
            trailing={<Toggle label={t("Notify After Scheduled Scans")} on={cfg.notify_scheduled_scan} onChange={(v) => saveNow({ ...cfg, notify_scheduled_scan: v })} />}
          />
        </Group>
      </Section>
      )}

      {tab === "mcp" && overview?.shell_hook.cli_found && <McpSection cliPath={overview.shell_hook.cli_path} />}

      {tab === "privacy" && (
      <Section title={t("Privacy")}>
        <div className="panel prose">
          <p>{t("Models receive only what a judgment needs: the command itself, downloaded remote scripts, public info about npm packages and extensions, package.json, and the file snippets that matched rules. Your other files, environment variables and secrets are never uploaded. With a local model, nothing leaves this Mac.")}</p>
          <p className="muted">{interpolate(t("History and settings are stored in {dir}."), { dir: <code>~/.tsuba</code> })}</p>
        </div>
      </Section>
      )}
      {tab === "about" && <AboutSection />}
        </div>
      </main>
    </div>
  );
}
