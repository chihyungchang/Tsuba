<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>見慣れないコードが初めて実行される前に、代わりに確認します。</b><br/>
  偽の面接プロジェクト、偽の会議アプリ、汚染されたパッケージ、悪意のある MCP サーバを、実行される前に食い止める macOS メニューバーアプリです。
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">Web サイト</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">ダウンロード</a> ·
  <a href="#install">インストール</a> ·
  <a href="#development">ソースからビルド</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hans.md">简体中文</a> · <a href="README.zh-Hant.md">繁體中文</a> · <b>日本語</b> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
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
  <img src="docs/screenshots/overview-light.png" alt="Tsuba のダッシュボード：保護の状態、要確認の項目、最近のチェック" width="100%" />
</picture>
</p>

---

## Tsuba とは

Tsuba（鍔、日本刀の手元を守る部品）は、見慣れないコードが初めて実行される瞬間を守ります。偽の面接プロジェクト、偽の会議ソフト、汚染された npm パッケージ、悪意のあるエディタ拡張機能は、毎回新しい姿で現れ、node、curl、bash といった普通のツールを使うため、従来のウイルス対策ソフトではほとんど検出されません。

Tsuba は、こうしたコードが最初に実行される入口に割り込みます。**そのコードが何をしようとしているのか、どこから来たのか、既知の攻撃に似ていないか**を見極めたうえで、**許可・警告・ブロック**のいずれかを判定し、すべての判定について根拠となるファイル、行、ルールを示します。

## Tsuba を選ぶ理由

- 🛡️ **実行後ではなく、実行前に。** `curl | bash`、`npm install`、`git clone`、ダウンロードフォルダに届いた新しい DMG、インストールしたばかりの拡張機能や MCP サーバ。どれも最初に実行される瞬間にチェックします。
- 🧠 **まずオフラインルール、次に文脈を読む AI。** ローカルのルールと脅威インテリジェンスは常に実行されます。そのうえでフロンティアモデルが証拠を読み、誤検知を減らし、まだどのルールも知らない攻撃を捉えます。ルールが高リスクと判定したものを AI が許可することはありません。
- 🔑 **新しいアカウントは不要。** Mac でサインイン済みの Claude Code や Codex をそのまま使えます。自分のキーで 20 余りのプロバイダから選ぶことも、モデルをまったく使わないこともできます。
- 🔒 **設計から読み取り専用。** チェック対象のコードは解析するだけで、実行しません。ディスクイメージは読み取り専用でマウントし、リモートスクリプトはダウンロードしても実行しません。実際に実行されるのは Tsuba がチェックしたスクリプトです。
- 🤫 **必要なときだけ知らせる。** 警告は音を鳴らさず履歴に残り、ブロックのときだけ短い音で通知します。誤検知と確認できたものは、無視するか安全とマークできます。
- 🔄 **安全に自動アップデート。** 新しいバージョンは GitHub Releases から配信され、署名が Tsuba の鍵と一致する場合にのみインストールされます。
- 🌏 **あなたの言語で。** アプリ、通知、ターミナルチェック、ルールの説明、AI の回答は、English、简体中文、繁體中文、日本語、한국어、Español、Français、Deutsch、Português、Русский に対応しています。macOS の設定に合わせるか、設定 → 外観で選べます。

## 機能紹介

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="チェック履歴：すべての判定と、その根拠となるファイル、行、ルール" />
</picture>
      <br/><sub><b>チェック履歴</b> — すべての警告とブロックについて、ファイル、行、一致したルールを表示。無視、隔離、安全とマークができます</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="ヘルスチェック：ボタンひとつで、チェックリストが埋まっていく" />
</picture>
      <br/><sub><b>ヘルスチェック</b> — ワンクリックで既知の攻撃の痕跡を探し、すべてのエディタ拡張機能と AI ツールをチェックします</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="判定方法の選択" />
</picture>
      <br/><sub><b>判定</b> — サインイン済みの Claude Code や Codex、20 余りのプロバイダの API キー、またはオフラインルールのみから選べます</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="脅威インテリジェンスの提供元とそのライセンス" />
</picture>
      <br/><sub><b>脅威インテリジェンス</b> — 公開リストとシグネチャを毎日ダウンロードしてローカルで照合。それぞれの提供元も表示します</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## インストール

[Releases](https://github.com/chihyungchang/Tsuba/releases) から DMG をダウンロードしてください（macOS 13 以降）。Apple シリコン搭載の Mac（M1 以降）は `Tsuba_*_aarch64.dmg`、Intel Mac は `Tsuba_*_x64.dmg` です。アカウントは不要で、AI による判定には Mac でサインイン済みの Claude Code や Codex を使えます。0.2.0 以降は、新しいバージョンをアプリ内からインストールできます（設定 → 情報とアップデート、またはメニューバーの「アップデートを確認…」）。

> [!WARNING]
> **現在のビルドは、まだ Apple による署名と公証を受けていません。** 初めて開くときに macOS がアプリをブロックするので、**システム設定 → プライバシーとセキュリティ**を開き、**このまま開く**をクリックしてください。
>
> Tsuba はオープンソースなので、実行するものを自分で確かめられます。各リリースに添付された `SHA256SUMS.txt` と DMG を照合する（`shasum -a 256 Tsuba_*.dmg`）、ビルドした[ワークフロー](.github/workflows/release.yml)を読む、あるいは自分でビルドする（[開発](#development)の「リリース」を参照）ことができます。
>
> `xattr` で検疫フラグを削除しないでください。Tsuba はそれを求めるインストーラに警告を出します。Tsuba 自身も例外ではありません。

## チェックする対象

| 入口 | 例 | チェック内容 |
| --- | --- | --- |
| ターミナルコマンド | `curl … \| bash`、`npm install`、`npx`、`npm start`、`code .`、`git clone` | リモートスクリプトを（実行せずに）ダウンロードし、その先の第 2 段階も追跡します。npm パッケージの作成日、リリースのクールダウン、インストールスクリプト。プロジェクトのソースに含まれる隠しコード、ハードコードされた C2、ウォレットやパスワードストアの読み取り。フォルダを開くと自動で実行される VS Code のタスク |
| ターミナルへの貼り付け | Web ページが「このコマンドをターミナルにコピーして」と促す | 貼り付けた瞬間に、オンラインに接続せず一度だけ警告します。base64 で難読化されてシェルにパイプされるコマンドは、即座に高リスクと判定します |
| ダウンロードフォルダ | 新しい `.dmg`、`.pkg`、`.vsix` ファイル | 読み取り専用でマウントし、署名、公証、ダウンロード元、メインの実行ファイルが隠しファイルに置き換えられていないか、インストールスクリプトをチェックします |
| エディタ拡張機能 | VS Code、Cursor、Windsurf、VSCodium で新規インストールまたは更新された拡張機能 | 公式の悪意ある拡張機能リスト、起動時の自動有効化、不可視の Unicode 文字に隠されたコード、不審なネットワークアクセスやファイルアクセス。高リスクの拡張機能は自動で隔離します |
| AI コーディングツール | Claude Code、Cursor、Codex などの MCP サーバ、スキル、プラグインフック。プロジェクト内の `.mcp.json`、フック、`CLAUDE.md` | 起動されるパッケージが悪意あるリストに載っていないか、一時ディレクトリや隠しディレクトリから起動していないか、どのシークレットを受け取るか。スキルやツールの説明に AI 向けの指示が隠されていないか（ツールポイズニング）、ユーザーに隠し事をするよう求めていないか、秘密鍵を読み取ったりデータを持ち出したりしないか |
| ヘルスチェック | メニューバー → ヘルスチェック | 既知の攻撃が残した痕跡、不審なログイン項目、インストール済み拡張機能のクイックスキャン |
| フォルダをスキャン | スキャンページ、または `tsuba scan <folder>` | ダウンロードフォルダ、外部ドライブ、コードディレクトリにあるインストーラ、スクリプト、拡張機能、自動実行の入口を持つプロジェクト。スキャン済みで変更のないファイルはスキップし、デフォルトでは 7 日ごとにダウンロードフォルダを最新のルールで再スキャンします |

Claude Code の中で「なぜこれはブロックされた？」と尋ねるには、`claude mcp add tsuba -- tsuba mcp` を実行します。これは読み取り専用の MCP ツールで、チェック履歴と隔離を参照できるだけで、何も変更できません。返すコマンドや要約は信頼できないデータとして明示され、シークレットは常に伏せられます。

誤検知と確認できたものは「安全とマーク」でき、内容のフィンガープリントが許可リストに記録されます。内容が変われば、再びチェックされます。不審なファイル、ディレクトリ、拡張機能は隔離でき、いつでも復元または削除できます。

拡張機能マーケットプレイスからインストールされた拡張機能はターミナルを経由しないため、インストール直後にしかチェックできません。Finder でダブルクリックして開いたプログラムは、まだブロックできません。それには Apple の Endpoint Security の権限が必要です（PRD 第 12 章を参照）。

## AI による判定

常にオフラインルールが先に実行され、その結果に基づいて AI が文脈を踏まえて判定します。設定で次のいずれかを選べます。

- **コーディングツールのアカウント**（推奨）：Mac でサインイン済みの Claude Code または Codex。フロンティアモデルを使え、API キーの管理も不要です。
- **API キー**：Claude、OpenAI、Gemini、DeepSeek、Qwen、Kimi、GLM などのモデルベンダー、OpenRouter や SiliconFlow などのプラットフォーム、Ollama、LM Studio、vLLM 経由のローカルモデル、または OpenAI Chat Completions API 互換の任意のエンドポイント。
- **オフラインルールのみ**：ネットワークに接続せず、モデルも呼び出しません。

モデルは 2 段階の信頼度に分かれます。公開されている研究では、悪意あるコードの識別でフロンティアモデルが明らかに優れており、非フロンティアモデルは誤検知が多く、コード内のプロンプトインジェクションにも騙されやすいことが示されています。

| | フロンティアモデル（Claude、OpenAI / Codex、Gemini、またはカスタムエンドポイントやプラットフォームで手動で指定したモデル） | ローカルモデルとその他のモデル |
| --- | --- | --- |
| 単独でブロックを推奨できるか | はい | いいえ、最大で警告 |
| オフラインルールが検出したリスクを下げられるか | ブロックを警告に下げられるが、直接許可はできない | いいえ |

モデルに渡す前にコードのコメントを取り除きます（コメントに仕込まれたプロンプトインジェクションを防ぐため）。証拠が長すぎる場合は各テキストの先頭と末尾を残し、オフラインルールに一致した箇所は常にすべて残します。モデルが受け取るのは今回の判定に必要な証拠だけで、その他のファイル、環境変数、シークレットはアップロードされません。設定とチェック履歴は `~/.tsuba` に保存されます。

<a id="threat-intel"></a>
## 脅威インテリジェンス

オフラインルールに加えて、Tsuba は 1 日 1 回、公開されている提供元から脅威インテリジェンスを更新し、`~/.tsuba/intel` に保存します（ターミナルで `tsuba intel update` を実行することもできます）。

| 提供元 | 内容 | ライセンス |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | 悪意が確認された約 23 万件の npm / PyPI パッケージ。ロックファイル内の推移的な依存関係もチェックします | Apache-2.0 |
| [OSV.dev](https://osv.dev)（オンライン、オフにできます） | 上と同じ内容を、チェック時にリアルタイムで照会します。送るのはパッケージ名とバージョンだけです | - |
| VS Code 公式の悪意ある拡張機能リスト | Microsoft が削除した悪意ある拡張機能 | - |
| [Elastic](https://github.com/elastic/protections-artifacts)、[ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) の YARA ルール | 既知のマルウェアファミリーのシグネチャ | Elastic License 2.0 / MIT |
| [GuardDog](https://github.com/DataDog/guarddog) の YARA ルール | 悪意あるパッケージによく見られる不審なコードパターン（証拠としてのみ使い、単独で警告を出すことはありません） | Apache-2.0 |
| ローカルの XProtect ルール | Apple 独自のマルウェアシグネチャ。この Mac でのみ使用します | Apple |
| [VirusTotal](https://www.virustotal.com)（任意、自分のキー） | インストーラ、プログラム、リモートスクリプトに対する 70 以上のウイルス対策エンジンの判定。送るのはハッシュだけで、ファイルはアップロードしません | 無料 API は商用利用不可 |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus（任意） | 悪意あるドメイン、IP、URL。無料の Auth-Key が必要で、無料プランは非営利目的に限ります | - |

ルールは [YARA-X](https://github.com/VirusTotal/yara-x) でコンパイルして実行します。ルールパックの URL からダウンロードしたルールパックは、有効な署名（`tsuba.sig`、ed25519）があり、バージョンが使用中のものより古くない場合にのみ使われます。リリース用の署名は `tsuba rules sign --key <private key file> <rules directory>` で行います。Tsuba 独自の検出ルールもコードには書かれておらず、[crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) と [tsuba.toml](crates/engine/rules/tsuba.toml) にあり、個別に更新できます。

開発のガイドラインは [CLAUDE.md](CLAUDE.md) を参照してください。

## ターミナルで

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

キャンセルしたコマンドはシェルの履歴に残ります。確認が済んだら、上矢印キーで呼び出せます。

すべての `tsuba` コマンドは `--lang <code>`（`en`、`zh-Hans`、`zh-Hant`、`ja`、`ko`、`es`、`fr`、`de`、`pt-BR`、`ru`）を受け付けます。指定しない場合、ターミナルはアプリで選んだ言語を使います。

### サンドボックスでの試験実行（プロトタイプ）

不安なスクリプトは、コードを 1 行ずつ読む代わりに、サンドボックスで短時間実行して実際の動作を確認できます。

```bash
tsuba sandbox install.sh
```

サンドボックスは macOS 標準のサンドボックスで直接動きます。本物のホームディレクトリは閉ざされ、プログラムにはおとりを置いた偽のホームディレクトリだけが見えます。ネットワークリクエストはすべてローカルのプロキシが記録し、実際には送信されません。実行時間は最大 60 秒です。おとりのシークレットを読み取って送信する、ログイン項目を書き込む、IP アドレスに直接接続する、といった動作はすべて記録されます。ただし、短時間の実行で悪い動作が見えなかったとしても、安全とは限りません。

プロジェクトディレクトリをサンドボックスで試験実行することもできます（`tsuba sandbox ~/code/interview-project`）。起動コマンドを実行して動作を観察するので、面接プロジェクトに仕込まれた「開いた瞬間に動く」悪意あるコードはここで明らかになります。`--install` を付けると、サンドボックス内で依存関係のインストール（`npm install`）を試し、インストールスクリプトが何をするかを確認できます。このモードでは npm 公式レジストリからのダウンロードだけを通し、それ以外の接続は記録するだけです。DMG / アプリ向けの仮想マシンによるサンドボックスはまだ実装されていません。

<a id="development"></a>
## 開発

<details>
<summary><b>ディレクトリ構成</b></summary>

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

Rust（`rustup`）、Node.js、pnpm が必要です。

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

サンプルディレクトリには `malicious/` と `benign/` の 2 つのサブディレクトリを置きます。各ファイルまたはサブディレクトリが 1 サンプルです（プロジェクト、拡張機能、インストーラ、スクリプトのいずれでもよく、シンボリックリンクも使えます）。オフラインルールだけを使うので結果は再現可能で、目標に届かなければ終了コードが 1 になるため、CI に組み込めます。時期で分けて評価したい場合は、古いサンプルと新しいサンプルを別々のディレクトリに置いて個別に実行してください。

開発中、アプリは自身と同じ場所でターミナルチェッカー（`target/debug/tsuba`）を探します。設定 → 保護 → 「zsh に接続」でワンクリックで設定でき、新しく開いたターミナルウインドウから有効になります。

テストサンプルはすべて無害です。攻撃コードの形を真似ているだけで、IP はドキュメント用の範囲のものを使い、デコードした内容も無害です。

コードには英語のテキストだけを置き、翻訳は言語ごとのカタログ（`app/src`、`app/src-tauri`、`crates/engine`、`crates/cli` の `locales/<code>.json`）にまとめています。ルールパックの各ルールは、それぞれ `message_<lang>` を持ちます。いずれかの言語で文字列が欠けている場合や、翻訳で `{placeholder}` が抜けている場合は、カタログのテストと `pnpm check:i18n` が失敗します。

アプリのアイコン、ダッシュボードのノートパソコン、鍔は Blender でレンダリングしたものです。`app/src-tauri/icons/source/` に、再生成するためのスクリプトと手順があります。

<details>
<summary><b>リリース</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

リリースバンドルには、ターミナルチェッカーが `Tsuba.app/Contents/MacOS/tsuba` として含まれます。これを追加して `app/scripts/build-cli-sidecar.sh` を実行するのは `tauri.release.conf.json` です。`tauri.conf.json` に含めないのは、ファイルがないと Tauri がビルドを拒否し、`cargo test` が壊れるためです。

公開するには、クリーンな `main` で `scripts/release.sh X.Y.Z` を実行します。ルートの `Cargo.toml` にバージョンを設定し（アプリ、CLI、DMG のバージョンの唯一の情報源です）、コミット前チェックを実行してコミットし、`vX.Y.Z` のタグを付け、プッシュする前に確認を求めます。タグによって `.github/workflows/release.yml` が起動し、テストを実行したうえで 3 つのランナーで同時に Apple シリコン版と Intel 版の DMG をビルドし、それらと `SHA256SUMS.txt` を、コミットから生成したノート付きの GitHub Release の下書きに添付します。内容を確認してから公開してください。いずれかのジョブが失敗すると下書きは削除され、タグは残ります。ワークフローを手動で実行した場合（Actions → Release → Run workflow、または `gh workflow run release.yml`）はドライランとなり、DMG はワークフローの成果物として保存されます。

アプリ内アップデートも同じリリースから配信されます。設定 → 情報とアップデートで、最新の公開リリースの `latest.json` を確認し（Tsuba は起動時にも静かに確認します）、この Mac 用のパッケージをダウンロードして、署名が `tauri.conf.json` の公開鍵と一致する場合にのみインストールします。リポジトリのシークレット `TAURI_SIGNING_PRIVATE_KEY` にアップデーター用の秘密鍵（`pnpm tauri signer generate` で生成、パスワードなし）が設定されていれば、CI が署名済みパッケージと `latest.json` を作成します。この鍵は必ずバックアップしてください。失うと、インストール済みのコピーを二度とアップデートできなくなります。

次のリポジトリシークレットが設定されていれば、署名と公証を行います：`APPLE_CERTIFICATE`（base64 の .p12）、`APPLE_CERTIFICATE_PASSWORD`、`APPLE_SIGNING_IDENTITY`、`APPLE_ID`、`APPLE_PASSWORD`（App 用パスワード）、`APPLE_TEAM_ID`。これらがない場合、DMG は署名されず、ダウンロード時に Gatekeeper がブロックします。

</details>

## ライセンス

Tsuba は [Apache License 2.0](LICENSE) でライセンスされています。実行時にダウンロードする脅威インテリジェンスはそれぞれのライセンスに従います。ライセンスは[脅威インテリジェンス](#threat-intel)に記載しており、それを使った検出結果の横にも表示されます。
