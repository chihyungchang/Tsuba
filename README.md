# Tsuba

**在陌生代码第一次运行之前，先替你看一眼。**

Tsuba（鍔，刀的护手）是一个 macOS 菜单栏应用。假面试项目、假会议软件、npm 投毒、恶意编辑器扩展，这类攻击每次都换包装，用的又是 node、curl、bash 这些正常工具，传统杀毒软件基本不报。Tsuba 在它们第一次运行的入口上拦一下：看清楚它要做什么、从哪来、像不像已知的攻击套路，再决定放行、提醒还是拦截。

产品背景、目标和路线图见 [PRD.md](PRD.md)。

## 它检查什么

| 入口 | 例子 | 检查内容 |
| --- | --- | --- |
| 终端命令 | `curl … \| bash`、`npm install`、`npx`、`npm start`、`code .` | 下载远程脚本（不执行）并追查第二阶段；npm 包的创建时间、版本发布冷却期、安装脚本；项目源码里的隐藏代码、硬编码 C2、读取钱包和密码库；VS Code 打开文件夹就自动执行的任务 |
| 粘贴进终端 | 网页让你“复制这条命令到终端” | 粘贴的瞬间先提醒一次，不联网；base64 混淆后交给 shell 执行的命令直接标为高危 |
| 下载目录 | 新出现的 `.dmg`、`.pkg`、`.vsix` | 只读挂载检查签名、公证、下载来源、主程序是否被替换成隐藏文件、安装脚本 |
| 编辑器扩展 | VS Code、Cursor、Windsurf、VSCodium 新装或更新的扩展 | 官方恶意扩展名单、启动即激活、不可见 Unicode 字符藏代码、可疑网络和文件访问；高危时自动移入隔离区 |
| AI 编程工具 | Claude Code、Cursor、Codex 等的 MCP server、skill、插件 hooks；项目里的 `.mcp.json`、hooks、`CLAUDE.md` | 启动的包是否在恶意名单、是否从临时或隐藏目录启动、拿到了哪些密钥；skill 是否要求 AI 对用户隐瞒、读取私钥、外传数据 |
| 体检 | 菜单栏 → 体检 | 已知攻击留下的落地痕迹、可疑开机自启项、已装扩展快速扫描 |

在扩展商店里装的扩展不经过终端，只能装完马上查；在 Finder 里双击打开的程序目前拦不住，需要苹果的 Endpoint Security 权限（见 PRD 第 12 节）。

## 威胁情报

离线规则之外，Tsuba 每天从公开来源更新一次威胁情报，存放在 `~/.tsuba/intel`（也可以在终端运行 `tsuba intel update`）：

| 来源 | 内容 | 许可 |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | 约 23 万条已确认的恶意 npm / PyPI 包，也会检查 lockfile 里的间接依赖 | Apache-2.0 |
| [OSV.dev](https://osv.dev)（在线，可关闭） | 同上，检查时实时查询，只发送包名和版本 | - |
| VS Code 官方恶意扩展名单 | 微软下架的恶意扩展 | - |
| [Elastic](https://github.com/elastic/protections-artifacts)、[ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) YARA 规则 | 已知恶意软件家族特征 | Elastic License 2.0 / MIT |
| [GuardDog](https://github.com/DataDog/guarddog) YARA 规则 | 恶意包常见的可疑写法（只作为证据，不单独触发提醒） | Apache-2.0 |
| 本机 XProtect 规则 | 苹果自己的恶意软件特征，只在本机使用 | Apple |
| [VirusTotal](https://www.virustotal.com)（可选，用户自己的 Key） | 70 多家杀毒引擎对安装包、程序、远程脚本的结论；只发送哈希，不上传文件 | 免费 API 不允许商用 |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus（可选） | 恶意域名、IP、网址；需要免费 Auth-Key，免费版仅限非营利使用 | - |

规则用 [YARA-X](https://github.com/VirusTotal/yara-x) 编译执行。Tsuba 自己的检测规则也不写在代码里，而是 [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) 和 [tsuba.toml](crates/engine/rules/tsuba.toml)，可以单独更新。

开发守则见 [CLAUDE.md](CLAUDE.md)。

## AI 判断

离线规则总是先跑，AI 在此基础上结合上下文判断。可以在设置里选：

- **Claude**：效果最好，需要 Anthropic API Key。
- **其他模型**：OpenAI、Google Gemini、DeepSeek、通义千问、Ollama、LM Studio，或任何兼容 OpenAI Chat Completions 接口的自定义地址。
- **仅离线规则**：不联网、不调用任何模型。

模型分两档信任。公开研究显示，在识别恶意代码这件事上前沿模型明显领先，非前沿模型更容易误报，也更容易被代码里的提示注入骗过：

| | 前沿模型（Claude、OpenAI、Gemini，或手动标记的自定义模型） | 本地和其他模型 |
| --- | --- | --- |
| 能独立给出“建议拦截” | 能 | 不能，最多“提醒” |
| 能降低离线规则判出的风险 | 能把“拦截”降为“提醒”，不能直接放行 | 不能 |

交给模型之前会去掉代码注释（防止注释里的提示注入）；证据太长时保留每段文本的开头和结尾，离线规则的命中永远完整保留。发给模型的只有这次判断需要的证据，不会上传其他文件、环境变量和密钥。配置和检查记录都在 `~/.tsuba`。

## 目录结构

```
Tsuba/
├── PRD.md                  产品需求文档
├── Cargo.toml              Rust workspace
├── crates/
│   ├── engine/             检测引擎（tsuba-engine）：识别、取证、离线规则、威胁情报、AI 判断
│   │   ├── rules/          Tsuba 规则包（tsuba.yar 检测模式、tsuba.toml 名单）
│   │   └── tests/          引擎测试和惰性攻击样本（tests/fixtures）
│   └── cli/                终端检查程序（tsuba），由 zsh 钩子调用
│       └── shell/          zsh 钩子
└── app/                    Tauri 2 菜单栏应用
    ├── src/                界面（React + TypeScript）
    └── src-tauri/          应用后端：托盘、窗口、后台监控、终端接入
```

## 开发

需要 Rust（`rustup`）、Node.js 和 pnpm。

```bash
cd app && pnpm install && pnpm tauri dev   # 启动应用
cargo test                                 # 跑引擎测试
cargo run -p tsuba-cli -- scan <路径>       # 不开应用，直接检查一个文件或目录
```

开发时 App 会在自己旁边（`target/debug/tsuba`）找终端检查程序，在“概览 → 接入终端”里一键装好，新开的终端窗口生效。

测试样本都是惰性的：只模仿攻击代码的形状，里面的 IP 属于文档保留网段，解码后的内容也无害。

## 终端里的小技巧

```bash
tskip npm install          # 这一次不检查
export TSUBA_DISABLE=1     # 当前终端窗口暂时关闭
```

被取消的命令会保留在 shell 历史里，核实后按上箭头就能找回来。
