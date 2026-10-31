<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>Takes a look for you before unfamiliar code runs for the first time.</b><br/>
  A macOS menu bar app that catches fake interview projects, fake meeting apps, poisoned packages and malicious MCP servers before they run.
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">Website</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">Download</a> ·
  <a href="#install">Install</a> ·
  <a href="#development">Build from source</a>
</p>

<p align="center">
  <b>English</b> · <a href="README.zh-Hans.md">简体中文</a> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
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
  <img src="docs/screenshots/overview-light.png" alt="Tsuba's dashboard: protection status, what needs attention and recent checks" width="100%" />
</picture>
</p>

---

## What is Tsuba

Tsuba (鍔, the hand guard of a Japanese sword) guards the moment unfamiliar code runs for the first time. Fake interview projects, fake meeting software, poisoned npm packages and malicious editor extensions come in new packaging every time and use ordinary tools like node, curl and bash, so traditional antivirus rarely flags them.

Tsuba steps in at the entry points where they first run: it works out **what the code is about to do, where it came from and whether it looks like a known attack**, then decides to **Allow, Warn or Block**, and shows the file, line and rule behind every verdict.

## Why Tsuba

- 🛡️ **Before it runs, not after.** `curl | bash`, `npm install`, `git clone`, a new DMG in Downloads, a freshly installed extension or MCP server: each is checked at the moment it would first run.
- 🧠 **Offline rules first, AI in context.** Local rules and threat intel always run. A frontier model then reads the evidence to cut false alarms and catch what no rule has seen yet, and it can never allow what the rules found high risk.
- 🔑 **No new account.** It uses the Claude Code or Codex already signed in on your Mac, or any of 20-odd providers with your own key, or no model at all.
- 🔒 **Read-only by design.** Code under check is parsed, never run: disk images are mounted read-only, remote scripts are downloaded but not executed, and the script that runs is the one Tsuba checked.
- 🤫 **Quiet until it matters.** Warnings land in history without a sound; only Block notifies with a short tone. Anything confirmed as a false alarm can be ignored or marked safe.
- 🔄 **Updates itself, safely.** New versions install from GitHub Releases only when their signature matches Tsuba's key.
- 🌏 **Speaks your language.** The app, notifications, terminal checks, rule explanations and AI answers come in English, 简体中文, 繁體中文, 日本語, 한국어, Español, Français, Deutsch, Português and Русский. It follows macOS, or pick one in Settings → Appearance.

## Product tour

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="Check history: every verdict with the file, line and rule behind it" />
</picture>
      <br/><sub><b>Check history</b> — every Warn and Block with the file, the line and the rule that matched; ignore it, quarantine it or mark it safe</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="Health Check: one button, a checklist that fills in" />
</picture>
      <br/><sub><b>Health Check</b> — one click looks for traces of known attacks, then checks every editor extension and AI tool</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="Choosing how verdicts are made" />
</picture>
      <br/><sub><b>Judgment</b> — the Claude Code or Codex you are already signed in to, an API key for 20-odd providers, or offline rules only</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="Threat intel sources and their licences" />
</picture>
      <br/><sub><b>Threat intel</b> — public lists and signatures, downloaded daily and checked locally, each with where it comes from</sub>
    </td>
  </tr>
</table>

## Install

Download the DMG from [Releases](https://github.com/chihyungchang/Tsuba/releases) (macOS 13 or later): `Tsuba_*_aarch64.dmg` for Apple silicon Macs (M1 and later), `Tsuba_*_x64.dmg` for Intel Macs. It needs no account; for AI review it can use the Claude Code or Codex already signed in on your Mac. From 0.2.0 on, new versions install from inside the app (Settings → About & Updates, or Check for Updates… in the menu bar).

> [!WARNING]
> **Builds are not yet signed or notarized by Apple.** macOS blocks the App the first time you open it: go to **System Settings → Privacy & Security** and click **Open Anyway**.
>
> Tsuba is open source, so you can check what you run: compare the DMG with the `SHA256SUMS.txt` attached to each release (`shasum -a 256 Tsuba_*.dmg`), read [the workflow](.github/workflows/release.yml) that built it, or build it yourself (see Releasing under [Development](#development)).
>
> Please don't remove the quarantine flag with `xattr`: Tsuba warns about installers that ask you to, and its own shouldn't be the exception.

## What it checks

| Entry point | Examples | What is checked |
| --- | --- | --- |
| Terminal commands | `curl … \| bash`, `npm install`, `npx`, `npm start`, `code .`, `git clone` | Downloads the remote script (without running it) and follows any second stage; the npm package's creation date, release cooldown and install scripts; hidden code, hard-coded C2 and reads of wallets and password stores in the project source; VS Code tasks that run automatically when the folder is opened |
| Pasting into the terminal | A web page tells you to "copy this command into your terminal" | Warns once the moment you paste, without going online; base64-obfuscated commands piped into a shell are flagged as high risk right away |
| Downloads folder | New `.dmg`, `.pkg`, `.vsix` files | Mounts them read-only and checks the signature, notarization, download source, whether the main executable was replaced with a hidden file, and install scripts |
| Editor extensions | Newly installed or updated extensions in VS Code, Cursor, Windsurf, VSCodium | The official malicious extension list, activation on startup, code hidden in invisible Unicode characters, suspicious network and file access; high-risk extensions are moved to quarantine automatically |
| AI coding tools | MCP servers, skills and plugin hooks for Claude Code, Cursor, Codex and others; `.mcp.json`, hooks and `CLAUDE.md` in projects | Whether the launched package is on a malicious list, whether it starts from a temporary or hidden directory, which secrets it receives; whether skills and tool descriptions hide instructions aimed at the AI (tool poisoning), ask it to hide things from the user, read private keys or exfiltrate data |
| Health Check | Menu bar → Health Check | Traces left behind by known attacks, suspicious login items, a quick scan of installed extensions |
| Scan a folder | The Scan page, or `tsuba scan <folder>` | Installers, scripts, extensions and projects with auto-run entry points in the Downloads folder, external drives and code directories; unchanged files that were already scanned are skipped, and by default the Downloads folder is rescanned with the latest rules every 7 days |

To ask "why was this blocked?" inside Claude Code: `claude mcp add tsuba -- tsuba mcp`. This is a read-only MCP tool: it can only look up check history and quarantine, and cannot change anything. Commands and summaries it returns are marked as untrusted data, and secrets are always redacted.

Anything confirmed to be a false positive can be "marked as safe", which records its content fingerprint in the allowlist; if the content changes, it gets checked again. Suspicious files, directories and extensions can be moved to quarantine and restored or deleted at any time.

Extensions installed from the extension marketplace don't go through the terminal, so they can only be checked right after installation. Programs opened by double-clicking in Finder can't be blocked yet; that requires Apple's Endpoint Security entitlement (see PRD section 12).

## AI judgment

The offline rules always run first, and the AI then judges on top of them, taking context into account. You can choose in Settings:

- **Coding tool account** (recommended): the Claude Code or Codex already signed in on your Mac. Frontier models, no API key to manage.
- **API key**: Claude, OpenAI or Gemini, model vendors such as DeepSeek, Qwen, Kimi and GLM, platforms such as OpenRouter and SiliconFlow, local models through Ollama, LM Studio or vLLM, or any endpoint compatible with the OpenAI Chat Completions API.
- **Offline rules only**: no network access, no model calls.

Models fall into two trust tiers. Public research shows frontier models are clearly ahead at recognizing malicious code, while non-frontier models produce more false positives and are more easily fooled by prompt injection in the code:

| | Frontier models (Claude, OpenAI / Codex, Gemini, or a model marked manually on a custom endpoint or platform) | Local and other models |
| --- | --- | --- |
| Can recommend Block on their own | Yes | No, Warn at most |
| Can lower the risk found by the offline rules | Can lower Block to Warn, but cannot Allow outright | No |

Code comments are stripped before anything reaches the model (to defeat prompt injection hidden in comments); when evidence is too long, the beginning and end of each text are kept, and offline rule hits are always kept in full. The model only receives the evidence this judgment needs; no other files, environment variables or secrets are uploaded. Configuration and check history live in `~/.tsuba`.

## Threat intel

On top of the offline rules, Tsuba updates its threat intel from public sources once a day and stores it in `~/.tsuba/intel` (you can also run `tsuba intel update` in the terminal):

| Source | Contents | License |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | About 230,000 confirmed malicious npm / PyPI packages; transitive dependencies in lockfiles are checked too | Apache-2.0 |
| [OSV.dev](https://osv.dev) (online, can be turned off) | Same as above, queried live during a check; only the package name and version are sent | - |
| VS Code official malicious extension list | Malicious extensions taken down by Microsoft | - |
| [Elastic](https://github.com/elastic/protections-artifacts), [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) YARA rules | Signatures of known malware families | Elastic License 2.0 / MIT |
| [GuardDog](https://github.com/DataDog/guarddog) YARA rules | Suspicious coding patterns common in malicious packages (evidence only; never triggers a Warn on its own) | Apache-2.0 |
| Local XProtect rules | Apple's own malware signatures, used only on this Mac | Apple |
| [VirusTotal](https://www.virustotal.com) (optional, your own key) | Verdicts from 70+ antivirus engines on installers, programs and remote scripts; only hashes are sent, files are never uploaded | The free API does not allow commercial use |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus (optional) | Malicious domains, IPs and URLs; requires a free Auth-Key, and the free tier is for non-profit use only | - |

Rules are compiled and run with [YARA-X](https://github.com/VirusTotal/yara-x). A rule pack downloaded from the rule pack URL is used only if it carries a valid signature (`tsuba.sig`, ed25519) and its version is not older than the one in use; sign it for release with `tsuba rules sign --key <private key file> <rules directory>`. Tsuba's own detection rules aren't written in code either: they live in [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) and [tsuba.toml](crates/engine/rules/tsuba.toml) and can be updated separately.

For development guidelines, see [CLAUDE.md](CLAUDE.md).

## In the terminal

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

Cancelled commands stay in your shell history; once you've verified them, press the up arrow to get them back.

Every `tsuba` command takes `--lang <code>` (`en`, `zh-Hans`, `zh-Hant`, `ja`, `ko`, `es`, `fr`, `de`, `pt-BR`, `ru`); without it, the terminal uses the language chosen in the app.

### Sandbox trial run (prototype)

For a script you're unsure about, you can run it briefly in a sandbox and see what it actually does, instead of reading the code line by line:

```bash
tsuba sandbox install.sh
```

The sandbox runs directly in macOS's built-in sandbox: the real home directory is locked down and the program only sees a fake home directory with decoys; every network request is recorded by a local proxy and never actually sent out; it runs for at most 60 seconds. Reading decoy secrets and sending them out, writing login items and connecting to bare IPs are all recorded. Note: seeing no bad behavior during a short run does not guarantee it's safe.

You can also trial-run a project directory in the sandbox (`tsuba sandbox ~/code/interview-project`), which runs its start command and watches the behavior; malicious code in interview projects that "runs as soon as you open it" is exposed here. Add `--install` to try installing dependencies (`npm install`) in the sandbox and see what their install scripts do; in that mode only downloads from the official npm registry are let through, and every other connection is still only recorded. The virtual machine sandbox for DMGs / Apps isn't built yet.

## Development

<details>
<summary><b>Directory layout</b></summary>

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

Requires Rust (`rustup`), Node.js and pnpm.

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

The samples directory contains two subdirectories, `malicious/` and `benign/`; each file or subdirectory counts as one sample (projects, extensions, installers and scripts all work, and so do symlinks). Only the offline rules are used, so results are reproducible; if the targets aren't met, the exit code is 1, so it can go into CI. For a time-based split, put the older and newer samples into two directories and run them separately.

During development the App looks for the terminal checker next to itself (`target/debug/tsuba`); set it up in one click under Settings → Protection → Connect to zsh, and it takes effect in newly opened terminal windows.

Test samples are all inert: they only mimic the shape of attack code, their IPs belong to documentation ranges, and decoded content is harmless too.

Code holds English text; translations live in one catalog per language (`locales/<code>.json` in `app/src`, `app/src-tauri`, `crates/engine` and `crates/cli`), and each rule in the rule pack carries its own `message_<lang>`. The catalog tests and `pnpm check:i18n` fail when a string is missing from any language or a translation drops a `{placeholder}`.

The app icon, the dashboard's laptop and the guard are Blender renders: `app/src-tauri/icons/source/` holds the scripts and the steps to regenerate them.

<details>
<summary><b>Releasing</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

A release bundle carries the terminal checker as `Tsuba.app/Contents/MacOS/tsuba`. `tauri.release.conf.json` adds it and runs `app/scripts/build-cli-sidecar.sh`; it stays out of `tauri.conf.json` because Tauri refuses to build without the file, which would break `cargo test`.

To publish, run `scripts/release.sh X.Y.Z` on a clean `main`: it sets the version in the root `Cargo.toml` (the single source for the App, CLI and DMG), runs the pre-commit checks, commits, tags `vX.Y.Z` and asks before pushing. The tag starts `.github/workflows/release.yml`, which runs the tests and builds the Apple silicon and Intel DMGs on three runners at once, attaching them and `SHA256SUMS.txt` to a GitHub Release with notes generated from the commits, and publishes it once every job passes (which also rebuilds the website). If any job fails, the draft is deleted and the tag stays. Running the workflow by hand (Actions → Release → Run workflow, or `gh workflow run release.yml`) is a dry run that keeps the DMGs as workflow artifacts instead.

In-app updates come from the same releases: Settings → About & Updates checks the latest published release's `latest.json` (Tsuba also checks quietly at launch), downloads the package for this Mac and installs it only if its signature matches the public key in `tauri.conf.json`. CI makes the signed packages and `latest.json` when the `TAURI_SIGNING_PRIVATE_KEY` repository secret holds the updater private key (generated with `pnpm tauri signer generate`, no password). Keep a backup of that key: without it, installed copies can never be updated again.

It signs and notarizes when these repository secrets are set: `APPLE_CERTIFICATE` (base64 .p12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` (app-specific password) and `APPLE_TEAM_ID`. Without them the DMG is unsigned and Gatekeeper blocks it on download.

</details>

## License

Tsuba is licensed under the [Apache License 2.0](LICENSE). Threat intel it downloads at runtime keeps its own license, listed in [Threat intel](#threat-intel) and shown next to every finding that uses it.
