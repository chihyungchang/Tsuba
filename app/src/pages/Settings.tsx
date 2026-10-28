import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon, type IconName } from "../icons";
import { lang, loadLangPreference, setLangPreference, t, type LangPreference } from "../i18n";
import { loadThemePreference, setThemePreference, type ThemePreference } from "../theme";
import { Config, IntelManifest, Overview, Provider } from "../types";
import { Banner, Group, PageHeader, Row, Section, Spinner, Toggle, errText, formatNumber, interpolate, relativeTime, shortPath, toast, toastDone } from "../ui";

type PresetGroup = "frontier" | "cloud" | "local" | "custom";

// All use the OpenAI-compatible API. Frontier models are trusted by default; the rest can only Warn by default.
// `id` is saved in the config file, so it never changes; names are proper nouns except the two translated ones.
const presets = (): { id: string; name: string; group: PresetGroup; url: string; trusted: boolean; key: boolean }[] => [
  { id: "openai", name: "OpenAI", group: "frontier", url: "https://api.openai.com/v1", trusted: true, key: true },
  { id: "gemini", name: "Gemini", group: "frontier", url: "https://generativelanguage.googleapis.com/v1beta/openai", trusted: true, key: true },
  { id: "deepseek", name: "DeepSeek", group: "cloud", url: "https://api.deepseek.com/v1", trusted: false, key: true },
  { id: "qwen", name: t("Qwen"), group: "cloud", url: "https://dashscope.aliyuncs.com/compatible-mode/v1", trusted: false, key: true },
  { id: "ollama", name: "Ollama", group: "local", url: "http://127.0.0.1:11434/v1", trusted: false, key: false },
  { id: "lmstudio", name: "LM Studio", group: "local", url: "http://127.0.0.1:1234/v1", trusted: false, key: false },
  { id: "custom", name: t("Custom"), group: "custom", url: "", trusted: false, key: true },
];

const providers = (): { id: Provider; icon: IconName; label: string; desc: string }[] => [
  // One card for both coding tools: they work the same way (a signed-in CLI, no API key), and a fifth card wouldn't fit
  { id: "claude_cli", icon: "terminal", label: t("Coding Tool Account"), desc: t("Uses the Claude Code or Codex signed in on this Mac; no API key needed") },
  { id: "claude", icon: "brain", label: "Claude API", desc: t("Anthropic API key, billed by usage") },
  { id: "openai_compatible", icon: "globe", label: t("Other Models"), desc: t("OpenAI, Gemini, DeepSeek or a local model") },
  { id: "offline", icon: "lock", label: t("Offline Rules Only"), desc: t("No network, no model calls") },
];

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
  const editorList = editors.join(lang() === "zh-Hans" ? "、" : ", ");
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

// Language names stay in their own language, so people can find theirs whatever is showing now
const langs = (): { id: LangPreference; label: string }[] => [
  { id: "system", label: t("System") },
  { id: "en", label: "English" },
  { id: "zh-Hans", label: "简体中文" },
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
            <Segmented
              label={t("Language")}
              options={langs()}
              value={lang}
              onChange={(v) => {
                setLang(v);
                setLangPreference(v);
              }}
            />
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
      <Group>
        {m?.sources.map((s) => (
          <Row
            key={s.id}
            title={s.name}
            detail={s.license !== "-" ? s.license : undefined}
            trailing={s.error ? <span className="tone-block small">{s.error}</span> : <span className="num">{t("{count} entries", { count: formatNumber(s.count) })}</span>}
          />
        ))}
        <Row title={t("Update Daily")} trailing={<Toggle label={t("Update Daily")} on={cfg.intel.auto_update} onChange={(v) => setIntel({ auto_update: v })} />} />
        <Row
          title={t("Look Up OSV.dev Online")}
          detail={t("Queries live while checking npm and PyPI packages, so new reports reach you sooner than the local list. Sends only the package name and version.")}
          trailing={<Toggle label={t("Look Up OSV.dev Online")} on={cfg.intel.online_lookup} onChange={(v) => setIntel({ online_lookup: v })} />}
        />
      </Group>
      <div className="panel form">
        <Field label="VirusTotal API Key" hint={t("Optional. Sends only the file's SHA-256 to get verdicts from 70+ engines; files are never uploaded.")}>
          <input type="password" placeholder={t("Not set")} value={cfg.intel.virustotal_key} onChange={(e) => setIntel({ virustotal_key: e.target.value.trim() })} />
        </Field>
        <Field label="abuse.ch Auth-Key" hint={t("Optional. The free tier is for non-profit use only.")}>
          <input type="password" placeholder={t("Not set")} value={cfg.intel.abusech_key} onChange={(e) => setIntel({ abusech_key: e.target.value.trim() })} />
        </Field>
      </div>
    </Section>
  );
}

export function SettingsPage({ overview, reload }: { overview: Overview | null; reload: () => void }) {
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

  return (
    <div className="page">
      <PageHeader
        title={t("Settings")}
        subtitle={t("Offline rules always run first. AI then weighs the context to cut false alarms and catch what the rules miss.")}
        icon="settings"
        tone={overview ? (overview.paused ? "block" : "allow") : "neutral"}
        status={overview ? (overview.paused ? t("Protection is paused") : t("Protection is on")) : undefined}
        stats={
          overview
            ? [
                { label: t("Defenses"), value: t("{on} / 4", { on: [overview.shell_hook.installed, overview.watch_downloads, overview.watch_extensions, overview.watch_ai_tools].filter(Boolean).length }), tone: overview.paused ? "block" : undefined },
                { label: t("Judgment"), value: overview.provider === "offline" ? t("Offline rules only") : overview.ai_available ? overview.provider_label.split(" · ")[0] : t("AI not set up yet"), tone: overview.provider !== "offline" && !overview.ai_available ? "warn" : undefined },
                { label: t("Allowlist"), value: t("{count} items", { count: formatNumber(overview.trusted) }) },
              ]
            : undefined
        }
      />

      {overview && <DefenseSection overview={overview} reload={reload} />}

      <Section title={t("Judgment")}>
        <div className="choice-grid" role="radiogroup" aria-label={t("Judgment")}>
          {providers().map((p) => {
            const I = Icon[p.icon];
            const isAccount = (v: Provider) => v === "claude_cli" || v === "codex_cli";
            const on = cfg.provider === p.id || (p.id === "claude_cli" && isAccount(cfg.provider));
            // The account card keeps whichever tool was chosen; first time, Codex only when Claude Code isn't installed
            const pick = (): Provider => (p.id !== "claude_cli" ? p.id : isAccount(cfg.provider) ? cfg.provider : !cliPath && codexPath ? "codex_cli" : "claude_cli");
            return (
              <button key={p.id} role="radio" aria-checked={on} className={`choice ${on ? "on" : ""}`} onClick={() => set({ provider: pick() })}>
                <I size={18} />
                <span className="choice-label">{p.label}</span>
                <span className="choice-desc">{p.desc}</span>
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
                <Field label={t("Provider")}>
                  <div className="chips">
                    {presetList.map((p) => (
                      <button
                        key={p.id}
                        type="button"
                        className={`chip ${oc.preset === p.id ? "on" : ""}`}
                        onClick={() => {
                          setModels([]);
                          setOc({ preset: p.id, base_url: p.id === "custom" ? oc.base_url : p.url, trusted: p.trusted, model: "" });
                        }}
                      >
                        {p.name}
                        {p.group === "local" && <span className="chip-tag">{t("Local")}</span>}
                      </button>
                    ))}
                  </div>
                </Field>
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
                {oc.preset === "custom" && (
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

      <IntelSection cfg={cfg} onChange={saveNow} />

      <AppearanceSection />

      <Section title={t("Editor Extensions")}>
        <Group>
          <Row
            title={t("Auto-Quarantine High-Risk Extensions")}
            detail={t("When a newly installed extension is judged Block Recommended, move it to quarantine before the editor loads it")}
            trailing={<Toggle label={t("Auto-Quarantine High-Risk Extensions")} on={cfg.auto_quarantine} onChange={(v) => saveNow({ ...cfg, auto_quarantine: v })} />}
          />
        </Group>
      </Section>

      {overview?.shell_hook.cli_found && <McpSection cliPath={overview.shell_hook.cli_path} />}

      <Section title={t("Privacy")}>
        <div className="panel prose">
          <p>{t("Models receive only what a judgment needs: the command itself, downloaded remote scripts, public info about npm packages and extensions, package.json, and the file snippets that matched rules. Your other files, environment variables and secrets are never uploaded. With a local model, nothing leaves this Mac.")}</p>
          <p className="muted">{interpolate(t("History and settings are stored in {dir}."), { dir: <code>~/.tsuba</code> })}</p>
        </div>
      </Section>
    </div>
  );
}
