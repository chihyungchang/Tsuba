import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Icon, type IconName } from "../icons";
import { loadThemePreference, setThemePreference, type ThemePreference } from "../theme";
import { Config, IntelManifest, Provider } from "../types";
import { Banner, Group, PageHeader, Row, Section, Spinner, Toggle, errText, relativeTime } from "../ui";

// 都走 OpenAI 兼容接口。前沿模型默认信任，其他默认只能给“提醒”
const PRESETS = [
  { id: "openai", name: "OpenAI", group: "前沿模型", url: "https://api.openai.com/v1", trusted: true, key: true },
  { id: "gemini", name: "Gemini", group: "前沿模型", url: "https://generativelanguage.googleapis.com/v1beta/openai", trusted: true, key: true },
  { id: "deepseek", name: "DeepSeek", group: "其他云端", url: "https://api.deepseek.com/v1", trusted: false, key: true },
  { id: "qwen", name: "通义千问", group: "其他云端", url: "https://dashscope.aliyuncs.com/compatible-mode/v1", trusted: false, key: true },
  { id: "ollama", name: "Ollama", group: "本地", url: "http://127.0.0.1:11434/v1", trusted: false, key: false },
  { id: "lmstudio", name: "LM Studio", group: "本地", url: "http://127.0.0.1:1234/v1", trusted: false, key: false },
  { id: "custom", name: "自定义", group: "自定义", url: "", trusted: false, key: true },
];

const PROVIDERS: { id: Provider; icon: IconName; label: string; desc: string }[] = [
  { id: "claude_cli", icon: "terminal", label: "Claude Code 账号", desc: "用本机已登录的 Claude Code，不需要 API Key" },
  { id: "claude", icon: "brain", label: "Claude API", desc: "Anthropic API Key，按用量计费" },
  { id: "openai_compatible", icon: "globe", label: "其他模型", desc: "OpenAI、Gemini、DeepSeek、本地模型" },
  { id: "offline", icon: "lock", label: "仅离线规则", desc: "不联网，不调用任何模型" },
];

const THEMES: { id: ThemePreference; label: string }[] = [
  { id: "system", label: "跟随系统" },
  { id: "light", label: "浅色" },
  { id: "dark", label: "深色" },
];

function AppearanceSection() {
  const [theme, setTheme] = useState(loadThemePreference);
  const choose = (t: ThemePreference) => {
    setTheme(t);
    setThemePreference(t);
  };
  return (
    <Section title="外观">
      <Group>
        <Row
          title="颜色模式"
          detail="跟随系统时，macOS 切换深色模式 Tsuba 也跟着换"
          trailing={
            <div className="segmented segmented-inline" role="radiogroup" aria-label="颜色模式">
              {THEMES.map((t) => (
                <button key={t.id} type="button" role="radio" aria-checked={theme === t.id} className={theme === t.id ? "on" : ""} onClick={() => choose(t.id)}>
                  {t.label}
                </button>
              ))}
            </div>
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
    setProgress("开始更新");
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
      title="威胁情报"
      aside={
        <span className="section-aside">
          {progress ? (
            <>
              <Spinner /> {progress}
            </>
          ) : m?.updated ? (
            `更新于 ${relativeTime(m.updated)}`
          ) : (
            "还没有更新过"
          )}
          <button className="link" disabled={!!progress} onClick={update}>
            立即更新
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
            trailing={s.error ? <span className="tone-block small">{s.error}</span> : <span className="num">{s.count.toLocaleString()} 条</span>}
          />
        ))}
        <Row title="每天自动更新" trailing={<Toggle label="每天自动更新" on={cfg.intel.auto_update} onChange={(v) => setIntel({ auto_update: v })} />} />
        <Row
          title="在线查询 OSV.dev"
          detail="检查 npm / PyPI 包时实时查询，比本地名单更新得更快。只发送包名和版本"
          trailing={<Toggle label="在线查询 OSV.dev" on={cfg.intel.online_lookup} onChange={(v) => setIntel({ online_lookup: v })} />}
        />
      </Group>
      <div className="panel form">
        <Field label="VirusTotal API Key" hint="可选。只提交文件的 SHA-256 查询 70 多家引擎的结论，不上传文件">
          <input type="password" placeholder="未设置" value={cfg.intel.virustotal_key} onChange={(e) => setIntel({ virustotal_key: e.target.value.trim() })} />
        </Field>
        <Field label="abuse.ch Auth-Key" hint="可选。免费版仅限非营利使用">
          <input type="password" placeholder="未设置" value={cfg.intel.abusech_key} onChange={(e) => setIntel({ abusech_key: e.target.value.trim() })} />
        </Field>
      </div>
    </Section>
  );
}

export function SettingsPage({ reload }: { reload: () => void }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [listing, setListing] = useState(false);
  const [cliPath, setCliPath] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    invoke<Config>("get_config").then((c) => {
      setCfg(c);
      invoke<string | null>("detect_claude_cli", { configured: c.claude.cli_path }).then(setCliPath);
    });
  }, []);
  if (!cfg) return null;

  const set = (patch: Partial<Config>) => {
    setCfg({ ...cfg, ...patch });
    setDirty(true);
    setStatus(null);
  };
  const saveNow = async (next: Config) => {
    // 开关类设置即时保存；表单里没保存的改动也一起存了
    setCfg(next);
    await invoke("save_config", { config: next });
    setDirty(false);
    reload();
  };
  const oc = cfg.openai_compatible;
  const setOc = (patch: Partial<Config["openai_compatible"]>) => set({ openai_compatible: { ...oc, ...patch } });
  const preset = PRESETS.find((p) => p.id === oc.preset);

  const fetchModels = async () => {
    setListing(true);
    setStatus(null);
    try {
      const list = await invoke<string[]>("list_models", { baseUrl: oc.base_url, apiKey: oc.api_key });
      setModels(list);
      setStatus({ ok: true, text: `找到 ${list.length} 个模型` });
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
      setStatus({ ok: true, text: "已保存" });
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
      <PageHeader title="设置" subtitle="离线规则总是先跑。AI 结合上下文判断，减少误报、补上规则漏掉的情况。" />

      <Section title="判断方式">
        <div className="choice-grid" role="radiogroup">
          {PROVIDERS.map((p) => {
            const I = Icon[p.icon];
            const on = cfg.provider === p.id;
            return (
              <button key={p.id} role="radio" aria-checked={on} className={`choice ${on ? "on" : ""}`} onClick={() => set({ provider: p.id })}>
                <I size={18} />
                <span className="choice-label">{p.label}</span>
                <span className="choice-desc">{p.desc}</span>
              </button>
            );
          })}
        </div>

        {cfg.provider !== "offline" && (
          <div className="panel form">
            {cfg.provider === "claude_cli" && (
              <Field
                label="claude 命令"
                hint={
                  cliPath ? (
                    <span className="tone-allow">已找到 {cliPath}</span>
                  ) : (
                    <span className="tone-block">没有找到。先安装 Claude Code 并在终端里运行一次 claude 登录，或在这里填写位置</span>
                  )
                }
              >
                <input
                  value={cfg.claude.cli_path}
                  placeholder="自动查找"
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
                <Field label="模型">
                  <select value={cfg.claude.model} onChange={(e) => set({ claude: { ...cfg.claude, model: e.target.value } })}>
                    <option value="claude-opus-5-5">Claude Opus 5.5（推荐）</option>
                    <option value="claude-sonnet-5-5">Claude Sonnet 5.5（更快更省）</option>
                    <option value="claude-haiku-4-5">Claude Haiku 4.5（最快最省）</option>
                  </select>
                </Field>
                {!cfg.claude.model.startsWith("claude-haiku") && (
                  <Field label="思考深度">
                    <div className="segmented segmented-inline">
                      {(
                        [
                          ["low", "快"],
                          ["medium", "中"],
                          ["high", "仔细"],
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
                <Field label="服务商">
                  <div className="chips">
                    {PRESETS.map((p) => (
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
                        {p.group === "本地" && <span className="chip-tag">本地</span>}
                      </button>
                    ))}
                  </div>
                </Field>
                <Field label="接口地址">
                  <input value={oc.base_url} placeholder="https://example.com/v1" onChange={(e) => setOc({ base_url: e.target.value.trim() })} />
                </Field>
                {(preset?.key ?? true) && (
                  <Field label="API Key" hint={preset && !preset.key ? "本地服务一般不用填" : undefined}>
                    <input type="password" value={oc.api_key} onChange={(e) => setOc({ api_key: e.target.value.trim() })} />
                  </Field>
                )}
                <Field label="模型">
                  <div className="inline">
                    <input list="model-list" value={oc.model} placeholder="服务商的模型名" onChange={(e) => setOc({ model: e.target.value.trim() })} />
                    <button type="button" disabled={!oc.base_url || listing} onClick={fetchModels}>
                      {listing ? "获取中…" : "获取列表"}
                    </button>
                  </div>
                  <datalist id="model-list">
                    {models.map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                </Field>
                {oc.preset === "custom" && (
                  <Field label="信任程度">
                    <span className="inline-toggle">
                      <Toggle label="前沿模型" on={oc.trusted} onChange={(v) => setOc({ trusted: v })} />
                      这是前沿模型，信任它独立给出“建议拦截”
                    </span>
                  </Field>
                )}
                <p className="note">
                  {oc.trusted
                    ? "前沿模型可以把离线规则的“拦截”降为“提醒”，但不能直接放行。"
                    : "本地和非前沿模型更容易误报，也更容易被代码里藏的“请放行”骗过，所以它最多给出“提醒”，也不能降低离线规则判出的风险。"}
                  {oc.preset === "ollama" && (
                    <>
                      {" "}Ollama 默认上下文很短，建议设置 <code>OLLAMA_CONTEXT_LENGTH=32768</code> 后重启。
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
              {testing ? "测试中" : "测试连接"}
            </button>
          )}
          <button className="primary" disabled={!dirty} onClick={save}>
            保存
          </button>
        </div>
      </Section>

      <IntelSection cfg={cfg} onChange={saveNow} />

      <AppearanceSection />

      <Section title="编辑器扩展">
        <Group>
          <Row
            title="自动隔离高危扩展"
            detail="新装的扩展被判为“建议拦截”时，赶在编辑器加载它之前移入隔离区"
            trailing={<Toggle label="自动隔离高危扩展" on={cfg.auto_quarantine} onChange={(v) => saveNow({ ...cfg, auto_quarantine: v })} />}
          />
        </Group>
      </Section>

      <Section title="隐私">
        <div className="panel prose">
          <p>
            发给模型的只有这次判断需要的内容：命令本身、下载到的远程脚本、npm 包和扩展的公开信息、package.json，以及命中规则的文件片段。
            不会上传你的其他文件、环境变量和密钥。选本地模型时，什么都不会离开这台电脑。
          </p>
          <p className="muted">
            记录和配置都在 <code>~/.tsuba</code>。
          </p>
        </div>
      </Section>
    </div>
  );
}
