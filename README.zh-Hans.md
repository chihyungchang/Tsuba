<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>陌生代码第一次运行之前，先替你看一眼。</b><br/>
  一款 macOS 菜单栏 App，在假面试项目、假会议软件、投毒的包和恶意 MCP 服务器运行之前把它们拦下来。
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">官网</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">下载</a> ·
  <a href="#install">安装</a> ·
  <a href="#development">从源码构建</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <b>简体中文</b> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/chihyungchang/Tsuba?style=flat&color=b4873a" /></a>
  <a href="https://github.com/chihyungchang/Tsuba/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/chihyungchang/Tsuba/total?style=flat&color=1f8a50" /></a>
  <img alt="macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-1f1c17?style=flat&logo=apple" />
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat" /></a>
  <a href="https://m8ven.ai/mcp/chihyungchang-tsuba-hmqqrw?s=readme"><img alt="M8ven Verified" src="https://m8ven.ai/badge/mcp/chihyungchang-tsuba-hmqqrw?variant=verified&v=786841f2c90c79c8b3d1e9bf30ae8ba8" /></a>
</p>

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png" />
  <img src="docs/screenshots/overview-light.png" alt="Tsuba 仪表盘：守护状态、需要注意的事项和最近的检查" width="100%" />
</picture>
</p>

---

## Tsuba 是什么

Tsuba（鍔，日本刀的护手）守在陌生代码第一次运行的那一刻。假面试项目、假会议软件、投毒的 npm 包和恶意编辑器扩展每次都换新包装，用的又是 node、curl、bash 这些普通工具，传统杀毒软件很少会报。

Tsuba 守在它们第一次运行的入口：判断**这段代码接下来要做什么、从哪里来、像不像已知的攻击**，再决定**放行、提醒还是拦截**，并列出每个结论背后的文件、行号和规则。

## 为什么选 Tsuba

- 🛡️ **在运行之前，而不是之后。** `curl | bash`、`npm install`、`git clone`、下载目录里新出现的 DMG、刚装好的扩展或 MCP 服务器：每一个都在它即将第一次运行时检查。
- 🧠 **离线规则先行，AI 看上下文。** 本地规则和威胁情报总是会跑。随后由前沿模型阅读证据，减少误报，抓住规则还没见过的攻击；规则判为高风险的，它永远不能放行。
- 🔑 **不用注册新账号。** 直接用 Mac 上已登录的 Claude Code 或 Codex，或用你自己的密钥接入 20 多家服务商之一，也可以完全不用模型。
- 🔒 **从设计上就是只读的。** 被检查的代码只解析、不运行：磁盘镜像以只读方式挂载，远程脚本只下载不执行，最终运行的就是 Tsuba 检查过的那一份。
- 🤫 **没事不打扰你。** “提醒”静静记进检查记录；只有“拦截”会发通知并响一声短音。确认是误报的可以忽略或标记为安全。
- 🔄 **安全地自动更新。** 新版本从 GitHub Releases 安装，且只有签名与 Tsuba 的密钥匹配才会安装。
- 🌏 **说你的语言。** App、通知、终端检查、规则说明和 AI 回答都支持 English、简体中文、繁體中文、日本語、한국어、Español、Français、Deutsch、Português 和 Русский。默认跟随 macOS，也可以在“设置 → 外观”里选择。

## 产品一览

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="检查记录：每个结论及其背后的文件、行号和规则" />
</picture>
      <br/><sub><b>检查记录</b>：每条“提醒”和“拦截”都附上文件、行号和命中的规则；可以忽略、移入隔离区或标记为安全</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="体检：一个按钮，逐项完成的检查清单" />
</picture>
      <br/><sub><b>体检</b>：点一下就查找已知攻击留下的痕迹，再逐个检查每个编辑器扩展和 AI 工具</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="选择判断方式" />
</picture>
      <br/><sub><b>判断方式</b>：用你已登录的 Claude Code 或 Codex、20 多家服务商的 API Key，或只用离线规则</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="威胁情报来源及其许可证" />
</picture>
      <br/><sub><b>威胁情报</b>：公开的名单和特征，每天下载、在本地对照，每一项都注明来源</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## 安装

从 [Releases](https://github.com/chihyungchang/Tsuba/releases) 下载 DMG（需要 macOS 13 或更高版本）：Apple 芯片的 Mac（M1 及以后）用 `Tsuba_*_aarch64.dmg`，Intel Mac 用 `Tsuba_*_x64.dmg`。不需要账号；AI 判断可以直接使用 Mac 上已登录的 Claude Code 或 Codex。从 0.2.0 起，新版本可以在 App 内安装（“设置 → 关于与更新”，或菜单栏里的“检查更新…”）。

> [!WARNING]
> **目前的版本还没有经过 Apple 签名和公证。** 第一次打开时 macOS 会拦住这个 App：请到 **系统设置 → 隐私与安全性**，点击 **仍要打开**。
>
> Tsuba 是开源的，你可以核实自己运行的是什么：用每个版本附带的 `SHA256SUMS.txt` 校验 DMG（`shasum -a 256 Tsuba_*.dmg`），阅读构建它的 [workflow](.github/workflows/release.yml)，或者自己构建（见[开发](#development)中的“发布”）。
>
> 请不要用 `xattr` 删除隔离标记：Tsuba 会对要求你这么做的安装包发出提醒，它自己也不该例外。

## 检查哪些地方

| 入口 | 例子 | 检查内容 |
| --- | --- | --- |
| 终端命令 | `curl … \| bash`、`npm install`、`npx`、`npm start`、`code .`、`git clone` | 下载远程脚本（不执行）并跟进后续阶段；npm 包的创建时间、发布冷却期和安装脚本；项目源码里的隐藏代码、硬编码的 C2，以及读取钱包和密码库的行为；打开文件夹就会自动运行的 VS Code 任务 |
| 粘贴到终端 | 网页让你“把这条命令复制到终端” | 粘贴的瞬间就提醒一次，不需要联网；用 base64 混淆后交给 shell 的命令会立刻判为高风险 |
| 下载目录 | 新出现的 `.dmg`、`.pkg`、`.vsix` 文件 | 以只读方式挂载，检查签名、公证、下载来源、主程序是否被换成隐藏文件，以及安装脚本 |
| 编辑器扩展 | VS Code、Cursor、Windsurf、VSCodium 中新装或更新的扩展 | 官方恶意扩展名单、是否一启动就激活、藏在不可见 Unicode 字符里的代码、可疑的网络和文件访问；高风险扩展会自动移入隔离区 |
| AI 编程工具 | Claude Code、Cursor、Codex 等工具的 MCP 服务器、skill 和插件钩子；项目里的 `.mcp.json`、hooks 和 `CLAUDE.md` | 启动的包是否在恶意名单里、是否从临时或隐藏目录启动、拿到了哪些密钥；skill 和工具描述里是否藏着写给 AI 的指令（工具投毒）、要求它对用户隐瞒、读取私钥或外传数据 |
| 体检 | 菜单栏 → 体检 | 已知攻击留下的痕迹、可疑的登录项、快速扫描已安装的扩展 |
| 扫描文件夹 | “扫描”页面，或 `tsuba scan <folder>` | 下载目录、外接硬盘和代码目录里的安装包、脚本、扩展，以及带自动运行入口的项目；已扫描过且没有变化的文件会跳过，默认每 7 天用最新规则重扫一遍下载目录 |

想在 Claude Code 里问“这个为什么被拦了”：`claude mcp add tsuba -- tsuba mcp`。这是只读的 MCP 工具：只能查检查记录和隔离区，不能改动任何东西。它返回的命令和摘要会标明是不可信数据，密钥一律隐去。

确认是误报的东西可以“标记为安全”，Tsuba 会把它的内容指纹记进白名单；内容一旦变化，就会重新检查。可疑的文件、目录和扩展可以移入隔离区，随时恢复或删除。

从扩展商店安装的扩展不经过终端，所以只能在安装后立即检查。在 Finder 里双击打开的程序目前还拦不住，这需要 Apple 的 Endpoint Security 权限（见 PRD 第 12 节）。

## AI 判断

离线规则总是先跑，AI 再在此基础上结合上下文判断。你可以在设置里选择：

- **编程工具账号**（推荐）：Mac 上已登录的 Claude Code 或 Codex。前沿模型，不用管理 API Key。
- **API Key**：Claude、OpenAI 或 Gemini，DeepSeek、通义千问、Kimi、GLM 等模型厂商，OpenRouter、硅基流动等平台，通过 Ollama、LM Studio 或 vLLM 运行的本地模型，或任何兼容 OpenAI Chat Completions API 的接口。
- **只用离线规则**：不联网，不调用模型。

模型分为两个信任等级。公开研究表明，前沿模型在识别恶意代码上明显领先，而非前沿模型误报更多，也更容易被代码里的提示注入骗过：

| | 前沿模型（Claude、OpenAI / Codex、Gemini，或在自定义接口、平台上手动标记的模型） | 本地和其他模型 |
| --- | --- | --- |
| 能否单独建议拦截 | 能 | 不能，最多提醒 |
| 能否降低离线规则发现的风险 | 可从“拦截”降为“提醒”，但不能直接放行 | 不能 |

发给模型之前会先去掉代码注释（防范藏在注释里的提示注入）；证据太长时，每段文本保留开头和结尾，离线规则的命中内容始终完整保留。模型只会收到这次判断需要的证据，不会上传其他文件、环境变量或密钥。配置和检查记录都在 `~/.tsuba`。

<a id="threat-intel"></a>
## 威胁情报

在离线规则之外，Tsuba 每天从公开来源更新一次威胁情报，存放在 `~/.tsuba/intel`（也可以在终端运行 `tsuba intel update`）：

| 来源 | 内容 | 许可证 |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | 约 23 万个已确认的恶意 npm / PyPI 包；lockfile 里的间接依赖也会检查 | Apache-2.0 |
| [OSV.dev](https://osv.dev)（在线，可关闭） | 同上，检查时实时查询；只发送包名和版本 | - |
| VS Code 官方恶意扩展名单 | 被微软下架的恶意扩展 | - |
| [Elastic](https://github.com/elastic/protections-artifacts)、[ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) YARA 规则 | 已知恶意软件家族的特征 | Elastic License 2.0 / MIT |
| [GuardDog](https://github.com/DataDog/guarddog) YARA 规则 | 恶意包里常见的可疑写法（只作为证据，不会单独触发“提醒”） | Apache-2.0 |
| 本机 XProtect 规则 | 苹果自己的恶意软件特征，只在这台 Mac 上使用 | Apple |
| [VirusTotal](https://www.virustotal.com)（可选，用你自己的密钥） | 70 多家杀毒引擎对安装包、程序和远程脚本的结论；只发送哈希，从不上传文件 | 免费 API 不允许商用 |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus（可选） | 恶意域名、IP 和网址；需要免费的 Auth-Key，免费版仅限非营利使用 | - |

规则由 [YARA-X](https://github.com/VirusTotal/yara-x) 编译和执行。从规则包地址下载的规则包，只有带着有效签名（`tsuba.sig`，ed25519）且版本不比正在用的旧，才会被采用；发布时用 `tsuba rules sign --key <private key file> <rules directory>` 签名。Tsuba 自己的检测规则也不写在代码里：它们放在 [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) 和 [tsuba.toml](crates/engine/rules/tsuba.toml)，可以单独更新。

开发规范见 [CLAUDE.md](CLAUDE.md)。

## 在终端里

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

被取消的命令会留在 shell 历史里；确认没问题后，按上方向键就能找回来。

每个 `tsuba` 命令都支持 `--lang <code>`（`en`、`zh-Hans`、`zh-Hant`、`ja`、`ko`、`es`、`fr`、`de`、`pt-BR`、`ru`）；不指定时，终端使用 App 里选择的语言。

### 沙箱试运行（原型）

对拿不准的脚本，可以在沙箱里短暂运行一下，看看它实际做了什么，而不必逐行读代码：

```bash
tsuba sandbox install.sh
```

沙箱直接使用 macOS 内置的沙箱：真实的个人目录被锁住，程序只能看到一个放了诱饵的假个人目录；所有网络请求都由本地代理记录，不会真的发出去；最多运行 60 秒。读取诱饵密钥并往外发、写入登录项、直连 IP 等行为都会被记录下来。注意：短时间运行没看到坏行为，不代表它一定安全。

也可以在沙箱里试运行一个项目目录（`tsuba sandbox ~/code/interview-project`），它会执行项目的启动命令并观察行为；面试项目里那种“一打开就运行”的恶意代码会在这里现形。加上 `--install` 可以在沙箱里试装依赖（`npm install`），看看它们的安装脚本做了什么；这个模式下只放行 npm 官方源的下载，其他连接仍然只记录。针对 DMG / App 的虚拟机沙箱还没做。

<a id="development"></a>
## 开发

<details>
<summary><b>目录结构</b></summary>

```
Tsuba/
├── Cargo.toml              Rust workspace
├── crates/
│   ├── engine/             Detection engine (tsuba-engine): recognition, evidence collection, offline rules, threat intel, AI judgment
│   │   ├── rules/          Tsuba rule pack (tsuba.yar detection patterns, tsuba.toml lists)
│   │   └── tests/          Engine tests and inert attack samples (tests/fixtures)
│   └── cli/                Terminal checker (tsuba), called by the zsh hook
│       └── shell/          zsh hook
└── app/                    Tauri 2 menu bar app
    ├── src/                UI (React + TypeScript)
    └── src-tauri/          App back end: tray, windows, background monitoring, terminal integration
```

</details>

需要 Rust（`rustup`）、Node.js 和 pnpm。

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

样本目录下放 `malicious/` 和 `benign/` 两个子目录，每个文件或子目录算一个样本（项目、扩展、安装包和脚本都行，符号链接也可以）。只用离线规则，所以结果可复现；没达到目标时退出码为 1，可以直接放进 CI。如果要按时间切分，把较旧和较新的样本分别放进两个目录各跑一次。

开发时，App 会在自己旁边查找终端检查程序（`target/debug/tsuba`）；在“设置 → 防护 → 接入 zsh”里一键配置，新开的终端窗口即生效。

测试样本全部是无害的：只模仿攻击代码的形态，IP 属于文档专用网段，解码后的内容也无害。

代码里只放英文文本；翻译存放在每种语言一份的目录文件里（`app/src`、`app/src-tauri`、`crates/engine` 和 `crates/cli` 下的 `locales/<code>.json`），规则包里的每条规则则带着自己的 `message_<lang>`。任何语言缺少字符串，或者译文漏掉了 `{placeholder}`，目录测试和 `pnpm check:i18n` 都会失败。

App 图标、仪表盘上的笔记本电脑和鍔都是 Blender 渲染的：`app/src-tauri/icons/source/` 里有重新生成它们的脚本和步骤。

<details>
<summary><b>发布</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

发布版的 bundle 会以 `Tsuba.app/Contents/MacOS/tsuba` 的形式带上终端检查程序。这由 `tauri.release.conf.json` 加入，并运行 `app/scripts/build-cli-sidecar.sh`；它没有放进 `tauri.conf.json`，因为缺少这个文件时 Tauri 会拒绝构建，那样会让 `cargo test` 跑不起来。

要发布时，在干净的 `main` 上运行 `scripts/release.sh X.Y.Z`：它会设置根目录 `Cargo.toml` 里的版本号（App、CLI 和 DMG 唯一的版本来源），运行提交前检查、提交、打上 `vX.Y.Z` 标签，并在推送前先询问。标签会触发 `.github/workflows/release.yml`，在三台 runner 上同时运行测试并构建 Apple 芯片和 Intel 的 DMG，把它们和 `SHA256SUMS.txt` 附加到一个 GitHub Release 草稿上，并根据提交记录生成说明，所有 job 通过后自动发布（同时重建网站）。任何一个 job 失败，草稿都会被删除，标签则保留。手动运行 workflow（Actions → Release → Run workflow，或 `gh workflow run release.yml`）是一次试运行，DMG 会保留为 workflow artifact。

App 内更新来自同样的 Releases：“设置 → 关于与更新”会检查最新已发布版本的 `latest.json`（Tsuba 启动时也会悄悄检查一次），下载适合这台 Mac 的包，只有签名与 `tauri.conf.json` 里的公钥匹配才会安装。当仓库 secret `TAURI_SIGNING_PRIVATE_KEY` 存有更新用的私钥（用 `pnpm tauri signer generate` 生成，不设密码）时，CI 会生成已签名的包和 `latest.json`。请备份好这把密钥：没有它，已安装的版本就再也无法更新。

设置以下仓库 secret 后就会签名并公证：`APPLE_CERTIFICATE`（base64 .p12）、`APPLE_CERTIFICATE_PASSWORD`、`APPLE_SIGNING_IDENTITY`、`APPLE_ID`、`APPLE_PASSWORD`（App 专用密码）和 `APPLE_TEAM_ID`。没有这些时，DMG 不签名，下载后会被 Gatekeeper 拦住。

</details>

## 许可证

Tsuba 采用 [Apache License 2.0](LICENSE) 许可。运行时下载的威胁情报保留各自的许可证，列在[威胁情报](#threat-intel)中，并显示在每一条用到它的发现旁边。
