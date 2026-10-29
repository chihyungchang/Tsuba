# Tsuba

**Takes a look for you before unfamiliar code runs for the first time.**

Tsuba (鍔, the hand guard of a Japanese sword) is a macOS menu bar app. Fake interview projects, fake meeting software, poisoned npm packages, malicious editor extensions: these attacks come in new packaging every time and use ordinary tools like node, curl and bash, so traditional antivirus software rarely flags them. Tsuba steps in at the entry points where they run for the first time: it works out what the code is about to do, where it came from and whether it looks like a known attack pattern, then decides whether to Allow, Warn or Block.

## Install

Download the DMG from [Releases](https://github.com/chihyungchang/Tsuba/releases) (macOS 13 or later): `Tsuba_*_aarch64.dmg` for Apple silicon Macs (M1 and later), `Tsuba_*_x64.dmg` for Intel Macs. It needs no account; for AI review it can use the Claude Code or Codex already signed in on your Mac.

> [!WARNING]
> **Builds are not yet signed or notarized by Apple.** macOS blocks the App the first time you open it: go to **System Settings → Privacy & Security** and click **Open Anyway**.
>
> Tsuba is open source, so you can check what you run: compare the DMG with the `SHA256SUMS.txt` attached to each release (`shasum -a 256 Tsuba_*.dmg`), read [the workflow](.github/workflows/release.yml) that built it, or build it yourself (see [Releasing](#releasing)).
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

## AI judgment

The offline rules always run first, and the AI then judges on top of them, taking context into account. You can choose in Settings:

- **Claude**: the best results; requires an Anthropic API key.
- **Other models**: OpenAI, Google Gemini, DeepSeek, Qwen, Ollama, LM Studio, or any custom endpoint compatible with the OpenAI Chat Completions API.
- **Offline rules only**: no network access, no model calls.

Models fall into two trust tiers. Public research shows frontier models are clearly ahead at recognizing malicious code, while non-frontier models produce more false positives and are more easily fooled by prompt injection in the code:

| | Frontier models (Claude, OpenAI, Gemini, or a custom model marked manually) | Local and other models |
| --- | --- | --- |
| Can recommend Block on their own | Yes | No, Warn at most |
| Can lower the risk found by the offline rules | Can lower Block to Warn, but cannot Allow outright | No |

Code comments are stripped before anything reaches the model (to defeat prompt injection hidden in comments); when evidence is too long, the beginning and end of each text are kept, and offline rule hits are always kept in full. The model only receives the evidence this judgment needs; no other files, environment variables or secrets are uploaded. Configuration and check history live in `~/.tsuba`.

## Directory layout

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

## Development

Requires Rust (`rustup`), Node.js and pnpm.

```bash
cd app && pnpm install && pnpm tauri dev     # start the app
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

The samples directory contains two subdirectories, `malicious/` and `benign/`; each file or subdirectory counts as one sample (projects, extensions, installers and scripts all work, and so do symlinks). Only the offline rules are used, so results are reproducible; if the targets aren't met, the exit code is 1, so it can go into CI. For a time-based split, put the older and newer samples into two directories and run them separately.

During development the App looks for the terminal checker next to itself (`target/debug/tsuba`); set it up in one click under Overview → Connect Terminal, and it takes effect in newly opened terminal windows.

Test samples are all inert: they only mimic the shape of attack code, their IPs belong to documentation ranges, and decoded content is harmless too.

### Releasing

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

A release bundle carries the terminal checker as `Tsuba.app/Contents/MacOS/tsuba`. `tauri.release.conf.json` adds it and runs `app/scripts/build-cli-sidecar.sh`; it stays out of `tauri.conf.json` because Tauri refuses to build without the file, which would break `cargo test`.

To publish, run `scripts/release.sh X.Y.Z` on a clean `main`: it sets the version in the root `Cargo.toml` (the single source for the App, CLI and DMG), runs the pre-commit checks, commits, tags `vX.Y.Z` and asks before pushing. The tag starts `.github/workflows/release.yml`, which runs the tests and builds the Apple silicon and Intel DMGs on three runners at once, attaching them and `SHA256SUMS.txt` to a draft GitHub Release with notes generated from the commits; review it and publish. If any job fails, the draft is deleted and the tag stays. Running the workflow by hand (Actions → Release → Run workflow, or `gh workflow run release.yml`) is a dry run that keeps the DMGs as workflow artifacts instead.

In-app updates come from the same releases: Settings → About & Updates checks the latest published release's `latest.json` (Tsuba also checks quietly at launch), downloads the package for this Mac and installs it only if its signature matches the public key in `tauri.conf.json`. CI makes the signed packages and `latest.json` when the `TAURI_SIGNING_PRIVATE_KEY` repository secret holds the updater private key (generated with `pnpm tauri signer generate`, no password). Keep a backup of that key: without it, installed copies can never be updated again.

It signs and notarizes when these repository secrets are set: `APPLE_CERTIFICATE` (base64 .p12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` (app-specific password) and `APPLE_TEAM_ID`. Without them the DMG is unsigned and Gatekeeper blocks it on download.

## Sandbox trial run (prototype)

For a script you're unsure about, you can run it briefly in a sandbox and see what it actually does, instead of reading the code line by line:

```bash
tsuba sandbox install.sh
```

The sandbox runs directly in macOS's built-in sandbox: the real home directory is locked down and the program only sees a fake home directory with decoys; every network request is recorded by a local proxy and never actually sent out; it runs for at most 60 seconds. Reading decoy secrets and sending them out, writing login items and connecting to bare IPs are all recorded. Note: seeing no bad behavior during a short run does not guarantee it's safe.

You can also trial-run a project directory in the sandbox (`tsuba sandbox ~/code/interview-project`), which runs its start command and watches the behavior; malicious code in interview projects that "runs as soon as you open it" is exposed here. Add `--install` to try installing dependencies (`npm install`) in the sandbox and see what their install scripts do; in that mode only downloads from the official npm registry are let through, and every other connection is still only recorded. The virtual machine sandbox for DMGs / Apps isn't built yet.

## Terminal tips

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

Cancelled commands stay in your shell history; once you've verified them, press the up arrow to get them back.

## License

Tsuba is licensed under the [Apache License 2.0](LICENSE). Threat intel it downloads at runtime keeps its own license, listed in [Threat intel](#threat-intel) and shown next to every finding that uses it.
