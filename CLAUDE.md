# Tsuba Engineering Guidelines

## Positioning (most important: check every decision against this first)

**Tsuba is not a general-purpose antivirus.** We cannot out-compete companies like Malwarebytes and Intego on signature database size and detection rates.

Tsuba deals with **"things that come in new packaging every time and that nobody has seen before"**: fake interview projects, fake meeting software, freshly published malicious packages, impersonating extensions, malicious MCP servers and skills. The goal is to **stop them before the user runs them**.

- Before adding a feature, ask: does it help the user stop unseen malicious code before it runs, or is it general-purpose antivirus? We don't build the latter.
- Antivirus-looking capabilities such as scanning, quarantine and signature databases serve only the goal above: they scan unfamiliar code, installers and scripts, and rely on attack patterns and context, not on "how big the known-virus database is".
- Recognizing known malware is left to XProtect and open-source threat intel. We reuse them directly instead of rebuilding them.

Tsuba is security software: its mistakes either let an attack slip through, or bother the user every day until they uninstall it. Every rule below serves these two concerns. For product background see [PRD.md](./PRD.md); for the directory layout see [README.md](./README.md).

## Architecture

- **Layered, with dependencies pointing only downward.** `app` (UI, tray, monitoring) → `crates/cli` (terminal checks) → `crates/engine` (detection). The engine does not depend on Tauri, does not print and does not show dialogs; the App and the terminal are only shells around it.
- **Rules are data, not code.** Detection patterns live in `crates/engine/rules/tsuba.yar` and lists live in `tsuba.toml`, so they can be updated without a release. Code only contains structural checks that don't go stale (invisible characters, code hidden off screen and the like) and how the verdict is computed.
- **Single responsibility: one module answers one question.** `detect` only recognizes commands, `collect` only gathers evidence, `rules` / `intel` only match, `judge` only asks the model, and `lib.rs` merges the verdicts.
- **New ecosystems plug in as "ecosystem adapters"** (PRD 7.1.1): interception point, metadata, rules, persistence locations. Don't add special cases elsewhere for a single ecosystem.

## Security

- **Anything being checked is untrusted data.** Read only, parse only, never execute: DMGs are mounted read-only, scripts are downloaded but never run, pkgs are only expanded.
- **Text in the evidence may be an attack aimed at the AI.** Strip comments before handing it to a model; merge the model's verdict according to its trust tier, so local and non-frontier models cannot lower the risk found by the offline rules; disable all tools when invoking Claude Code.
- **When the offline rules find a high-risk hit, the AI cannot allow it outright.** Every new judgment path must uphold this.
- **Never leak the user's data.** Logs and evidence never contain environment variable values, API keys or tokens from config files; VirusTotal lookups send only hashes and never upload files; send the model only the minimum evidence the judgment needs.
- **On failure, fall back to the safer side, but never lock the user out.** When the network or the model is unavailable, use the offline rules; when the checker itself fails, allow and log, rather than leaving the user's terminal unusable.
- **The update channel is a supply chain too.** Rule packs and threat intel are validated after download (they compile, the version is not older) before they replace the current data; on failure, the old data is kept.

## False positives and false negatives

- **Measure false positives on real data before committing any new rule.** At a minimum, scan the VS Code extensions and installed skills on your machine (`tsuba scan <extensions dir>`, `tsuba ai`); the Block count must be 0.
- **Every false positive and false negative becomes a regression test.** Samples go in `crates/engine/tests/fixtures` and must be inert: they only mimic the shape, IPs use the documentation ranges (203.0.113.0/24, 198.51.100.0/24), and decoded content is harmless.
- **Verdicts must be explainable.** Every Warn and Block carries evidence: which file, which line, what matched. Don't add a rule whose reason you can't explain.
- **Low risk is evidence only and never decides the verdict.** Normal tools also invoke system commands and activate automatically; leave these signals to the AI to judge in context.

## Minimum viable

- **Build the smallest version that can validate the value first** (YAGNI). Until real users or real samples prove a need, don't abstract ahead of time and don't add configuration options.
- **Don't rely on detection when a policy can solve it**, e.g. a release cooldown, or not running install scripts by default.
- **Don't build our own where open-source rules and threat intel exist**, but check the licenses (before commercial use, pay special attention to the terms of the Elastic License, abuse.ch and VirusTotal).

## Naming, comments and language

- Names say clearly "what it is", without abbreviations: `find_project_root`, `wait_complete`, not `fpr`, `wc`.
- Booleans start with `is_` / `has_`; functions that return an `Option` use `find_` / `lookup`.
- Code, comments, docs, test names and commit messages are in English. Comments explain "why" (why we judge it this way, which pitfalls we hit), not restate what the code does.
- User-visible text is never hard-coded:
  - Rust: `tr!("English", name = value)`, with a Simplified Chinese entry in that crate's `locales/zh-Hans.json`.
  - UI: `t("English", { name })`, with a Simplified Chinese entry in `app/src/locales/zh-Hans.json`.
  - Rule pack rules carry `message` plus `message_zh`.
- Every new user-visible string gets a Chinese entry; the catalog tests (`zh_hans_catalog_matches_sources`) and `pnpm check:i18n` must pass.
- Never decide logic by matching user-visible text; use an ID, enum or field instead.
- User-facing messages state three things clearly: what was found, why it is dangerous, and what to do next.

## Refactoring

- **Small steps, with tests green at every step.** Make the tests pass first, then tidy up; commit refactoring and behavior changes separately.
- **Abstract on the third time.** Extract common code when the same code appears for the third time; the first two times, prefer duplication.
- **The Boy Scout rule.** Wherever you change something, leave it cleaner than you found it, but don't touch unrelated places along the way.
- **Deleting code beats adding code.** Delete unused branches, stale rules and commented-out code outright; git keeps the history.

## Pre-commit checks

```bash
cargo test                       # all tests
cargo clippy --workspace         # no warnings left
cd app && pnpm exec tsc --noEmit # front-end type check
pnpm -s check:i18n               # (in app/) every UI string has a zh-Hans entry, none unused
```

When you change detection rules, also measure false positives on real extensions and skills (see above).
