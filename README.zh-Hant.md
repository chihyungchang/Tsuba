<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>陌生程式碼第一次執行之前，先幫你看一眼。</b><br/>
  一款 macOS 選單列 App，在假面試專案、假會議軟體、遭投毒的套件和惡意 MCP 伺服器執行之前把它們攔下來。
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">官方網站</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">下載</a> ·
  <a href="#install">安裝</a> ·
  <a href="#development">從原始碼建置</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hans.md">简体中文</a> · <b>繁體中文</b> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
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
  <img src="docs/screenshots/overview-light.png" alt="Tsuba 儀表板：守護狀態、需要注意的項目和最近的檢查" width="100%" />
</picture>
</p>

---

## Tsuba 是什麼

Tsuba（鍔，日本刀的護手）守在陌生程式碼第一次執行的那一刻。假面試專案、假會議軟體、遭投毒的 npm 套件和惡意編輯器擴充功能每次都換新包裝，用的又是 node、curl、bash 這些普通工具，傳統防毒軟體很少會報。

Tsuba 守在它們第一次執行的入口：判斷**這段程式碼接下來要做什麼、從哪裡來、像不像已知的攻擊**，再決定**放行、提醒或攔截**，並列出每個判定背後的檔案、行號和規則。

## 為什麼選 Tsuba

- 🛡️ **在執行之前，而不是之後。** `curl | bash`、`npm install`、`git clone`、「下載項目」裡新出現的 DMG、剛安裝的擴充功能或 MCP 伺服器：每一個都在它即將第一次執行時檢查。
- 🧠 **離線規則優先，AI 看上下文。** 本機規則和威脅情資一定會執行。接著由前沿模型閱讀證據，減少誤報、抓出規則還沒見過的攻擊；規則判定為高風險的，它永遠不能放行。
- 🔑 **不用註冊新帳號。** 直接使用 Mac 上已登入的 Claude Code 或 Codex，或用你自己的金鑰接 20 多家服務商之一，也可以完全不用模型。
- 🔒 **設計上就是唯讀。** 受檢查的程式碼只解析、不執行：磁碟映像檔以唯讀方式掛載，遠端腳本只下載不執行，最後執行的就是 Tsuba 檢查過的那一份。
- 🤫 **沒事不吵你。** 「提醒」安靜地記進檢查紀錄；只有「攔截」會發通知並響一聲短音。確認是誤報的可以忽略或標記為安全。
- 🔄 **安全地自動更新。** 新版本從 GitHub Releases 安裝，而且只有簽章符合 Tsuba 的金鑰才會安裝。
- 🌏 **說你的語言。** App、通知、終端機檢查、規則說明和 AI 回答都支援 English、简体中文、繁體中文、日本語、한국어、Español、Français、Deutsch、Português 和 Русский。預設跟隨 macOS，也可以在「設定 → 外觀」中選擇。

## 產品導覽

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="檢查紀錄：每個判定及其背後的檔案、行號和規則" />
</picture>
      <br/><sub><b>檢查紀錄</b>：每一筆「提醒」和「攔截」都附上檔案、行號和符合的規則；可以忽略、移入隔離區或標記為安全</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="健檢：一個按鈕，逐項填滿的檢查清單" />
</picture>
      <br/><sub><b>健檢</b>：按一下就檢查已知攻擊留下的痕跡，再逐一檢查每個編輯器擴充功能和 AI 工具</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="選擇判斷方式" />
</picture>
      <br/><sub><b>判斷方式</b>：使用你已登入的 Claude Code 或 Codex、20 多家服務商的 API Key，或只用離線規則</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="威脅情資來源及其授權" />
</picture>
      <br/><sub><b>威脅情資</b>：公開的清單和特徵，每天下載、在本機比對，每一項都標明來源</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## 安裝

從 [Releases](https://github.com/chihyungchang/Tsuba/releases) 下載 DMG（需要 macOS 13 或更新版本）：Apple 晶片的 Mac（M1 及之後）用 `Tsuba_*_aarch64.dmg`，Intel Mac 用 `Tsuba_*_x64.dmg`。不需要帳號；AI 判斷可以直接使用 Mac 上已登入的 Claude Code 或 Codex。從 0.2.0 開始，新版本可在 App 內安裝（「設定 → 關於與更新」，或選單列中的「檢查更新…」）。

> [!WARNING]
> **目前的版本尚未經過 Apple 簽署和公證。** 第一次開啟時 macOS 會阻擋這個 App：請到 **系統設定 → 隱私權與安全性**，按一下 **強制打開**。
>
> Tsuba 是開源軟體，你可以查證自己執行的是什麼：用每個版本附帶的 `SHA256SUMS.txt` 比對 DMG（`shasum -a 256 Tsuba_*.dmg`），閱讀建置它的 [workflow](.github/workflows/release.yml)，或自己建置（見[開發](#development)中的「發布」）。
>
> 請不要用 `xattr` 移除隔離標記：Tsuba 會對要求你這麼做的安裝程式發出提醒，它自己也不該例外。

## 檢查哪些地方

| 入口 | 例子 | 檢查內容 |
| --- | --- | --- |
| 終端機指令 | `curl … \| bash`、`npm install`、`npx`、`npm start`、`code .`、`git clone` | 下載遠端腳本（不執行）並追蹤後續階段；npm 套件的建立日期、發布冷卻期和安裝腳本；專案原始碼中的隱藏程式碼、寫死的 C2，以及讀取錢包和密碼庫的行為；開啟資料夾就會自動執行的 VS Code 工作 |
| 貼上到終端機 | 網頁要你「把這條指令複製到終端機」 | 貼上的瞬間就提醒一次，不需要連網；用 base64 混淆後交給 shell 的指令會立即判為高風險 |
| 「下載項目」資料夾 | 新出現的 `.dmg`、`.pkg`、`.vsix` 檔案 | 以唯讀方式掛載，檢查簽章、公證、下載來源、主程式是否被換成隱藏檔案，以及安裝腳本 |
| 編輯器擴充功能 | VS Code、Cursor、Windsurf、VSCodium 中新安裝或更新的擴充功能 | 官方惡意擴充功能清單、是否一啟動就啟用、藏在不可見 Unicode 字元裡的程式碼、可疑的網路和檔案存取；高風險的擴充功能會自動移入隔離區 |
| AI 程式設計工具 | Claude Code、Cursor、Codex 等工具的 MCP 伺服器、skill 和外掛 hook；專案中的 `.mcp.json`、hooks 和 `CLAUDE.md` | 啟動的套件是否在惡意清單上、是否從暫存或隱藏目錄啟動、拿到了哪些密鑰；skill 和工具描述是否藏著寫給 AI 的指令（工具投毒）、要求它對使用者隱瞞、讀取私密金鑰或外洩資料 |
| 健檢 | 選單列 → 健檢 | 已知攻擊留下的痕跡、可疑的登入項目、快速掃描已安裝的擴充功能 |
| 掃描資料夾 | 「掃描」頁面，或 `tsuba scan <folder>` | 「下載項目」資料夾、外接硬碟和程式碼目錄中的安裝程式、腳本、擴充功能，以及帶有自動執行入口的專案；已經掃描過且沒有變動的檔案會略過，預設每 7 天用最新規則重新掃描一次「下載項目」資料夾 |

想在 Claude Code 裡問「這個為什麼被攔截」：`claude mcp add tsuba -- tsuba mcp`。這是唯讀的 MCP 工具：只能查詢檢查紀錄和隔離區，無法變更任何東西。它回傳的指令和摘要會標示為不可信資料，密鑰一律隱藏。

確認是誤報的項目可以「標記為安全」，Tsuba 會把它的內容指紋記進白名單；內容一旦變動，就會重新檢查。可疑的檔案、目錄和擴充功能可以移入隔離區，隨時還原或刪除。

從擴充功能市集安裝的擴充功能不經過終端機，所以只能在安裝後立即檢查。在 Finder 中按兩下開啟的程式目前還無法攔截，這需要 Apple 的 Endpoint Security 權限（見 PRD 第 12 節）。

## AI 判斷

離線規則一定先執行，AI 再在此基礎上結合上下文判斷。你可以在設定中選擇：

- **程式設計工具帳號**（推薦）：Mac 上已登入的 Claude Code 或 Codex。前沿模型，不必管理 API Key。
- **API Key**：Claude、OpenAI 或 Gemini，DeepSeek、通義千問、Kimi、GLM 等模型廠商，OpenRouter、硅基流動等平台，透過 Ollama、LM Studio 或 vLLM 執行的本機模型，或任何相容 OpenAI Chat Completions API 的端點。
- **只用離線規則**：不連網，不呼叫模型。

模型分為兩個信任層級。公開研究顯示，前沿模型在辨識惡意程式碼上明顯領先，而非前沿模型誤報較多，也較容易被程式碼中的提示注入騙過：

| | 前沿模型（Claude、OpenAI / Codex、Gemini，或在自訂端點、平台上手動標記的模型） | 本機和其他模型 |
| --- | --- | --- |
| 能否單獨建議攔截 | 能 | 不能，最多提醒 |
| 能否降低離線規則發現的風險 | 可從「攔截」降為「提醒」，但不能直接放行 | 不能 |

送給模型之前會先移除程式碼註解（防範藏在註解裡的提示注入）；證據太長時，每段文字保留開頭和結尾，離線規則的命中內容一律完整保留。模型只會收到這次判斷所需的證據，不會上傳其他檔案、環境變數或密鑰。設定和檢查紀錄存放在 `~/.tsuba`。

<a id="threat-intel"></a>
## 威脅情資

除了離線規則，Tsuba 每天從公開來源更新一次威脅情資，存放在 `~/.tsuba/intel`（也可以在終端機執行 `tsuba intel update`）：

| 來源 | 內容 | 授權 |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | 約 23 萬個已確認的惡意 npm / PyPI 套件；lockfile 中的間接相依套件也會檢查 | Apache-2.0 |
| [OSV.dev](https://osv.dev)（線上，可關閉） | 同上，在檢查時即時查詢；只送出套件名稱和版本 | - |
| VS Code 官方惡意擴充功能清單 | 被 Microsoft 下架的惡意擴充功能 | - |
| [Elastic](https://github.com/elastic/protections-artifacts)、[ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) YARA 規則 | 已知惡意軟體家族的特徵 | Elastic License 2.0 / MIT |
| [GuardDog](https://github.com/DataDog/guarddog) YARA 規則 | 惡意套件中常見的可疑寫法（只作為證據，不會單獨觸發「提醒」） | Apache-2.0 |
| 本機 XProtect 規則 | Apple 自己的惡意軟體特徵，只在這台 Mac 上使用 | Apple |
| [VirusTotal](https://www.virustotal.com)（選用，使用你自己的金鑰） | 70 多家防毒引擎對安裝程式、程式和遠端腳本的結論；只送出雜湊值，絕不上傳檔案 | 免費 API 不允許商業用途 |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus（選用） | 惡意網域、IP 和網址；需要免費的 Auth-Key，免費方案僅限非營利用途 | - |

規則由 [YARA-X](https://github.com/VirusTotal/yara-x) 編譯和執行。從規則包網址下載的規則包，必須帶有有效簽章（`tsuba.sig`，ed25519）且版本不比目前使用的舊，才會被採用；發布時用 `tsuba rules sign --key <private key file> <rules directory>` 簽署。Tsuba 自己的偵測規則也不寫在程式碼裡：它們放在 [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) 和 [tsuba.toml](crates/engine/rules/tsuba.toml)，可以單獨更新。

開發規範請見 [CLAUDE.md](CLAUDE.md)。

## 在終端機中

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

被取消的指令會留在 shell 歷史中；確認沒問題後，按向上鍵就能叫回來。

每個 `tsuba` 指令都接受 `--lang <code>`（`en`、`zh-Hans`、`zh-Hant`、`ja`、`ko`、`es`、`fr`、`de`、`pt-BR`、`ru`）；不指定時，終端機使用 App 中選擇的語言。

### 沙箱試執行（原型）

對於拿不準的腳本，可以在沙箱裡短暫執行一下，看看它實際做了什麼，而不必逐行讀程式碼：

```bash
tsuba sandbox install.sh
```

沙箱直接使用 macOS 內建的沙箱：真正的個人目錄被鎖住，程式只看得到一個放了誘餌的假個人目錄；所有網路請求都由本機代理伺服器記錄，不會真的送出去；最多執行 60 秒。讀取誘餌密鑰並往外送、寫入登入項目、直接連線到 IP 等行為都會被記錄下來。注意：短時間執行沒看到惡意行為，不代表它一定安全。

也可以在沙箱裡試執行一個專案目錄（`tsuba sandbox ~/code/interview-project`），它會執行專案的啟動指令並觀察行為；面試專案裡那種「一打開就執行」的惡意程式碼會在這裡現形。加上 `--install` 可以在沙箱裡試裝相依套件（`npm install`），看看它們的安裝腳本做了什麼；這個模式下只放行 npm 官方套件庫的下載，其他連線仍然只記錄。用於 DMG / App 的虛擬機器沙箱還沒做。

<a id="development"></a>
## 開發

<details>
<summary><b>目錄結構</b></summary>

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

樣本目錄下包含 `malicious/` 和 `benign/` 兩個子目錄，每個檔案或子目錄算一個樣本（專案、擴充功能、安裝程式和腳本都可以，符號連結也行）。只使用離線規則，所以結果可以重現；未達目標時結束代碼為 1，可以直接放進 CI。如果要按時間切分，把較舊和較新的樣本放進兩個目錄分別執行。

開發期間，App 會在自己旁邊尋找終端機檢查程式（`target/debug/tsuba`）；在「設定 → 防護 → 接入 zsh」一鍵設定，新開的終端機視窗即生效。

測試樣本全都是無害的：只模仿攻擊程式碼的樣子，IP 屬於文件專用網段，解碼後的內容也無害。

程式碼裡只放英文文字；翻譯存放在每種語言一份的目錄檔中（`app/src`、`app/src-tauri`、`crates/engine` 和 `crates/cli` 中的 `locales/<code>.json`），規則包中的每條規則則帶有自己的 `message_<lang>`。任何語言缺少字串，或翻譯漏掉了 `{placeholder}`，目錄檔測試和 `pnpm check:i18n` 都會失敗。

App 圖示、儀表板上的筆電和鍔都是 Blender 算圖：`app/src-tauri/icons/source/` 中有重新產生它們的腳本和步驟。

<details>
<summary><b>發布</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

發布版的套件包會以 `Tsuba.app/Contents/MacOS/tsuba` 的形式附帶終端機檢查程式。這由 `tauri.release.conf.json` 加入，並執行 `app/scripts/build-cli-sidecar.sh`；它沒有放在 `tauri.conf.json`，因為缺少這個檔案時 Tauri 會拒絕建置，那樣會讓 `cargo test` 壞掉。

要發布時，在乾淨的 `main` 上執行 `scripts/release.sh X.Y.Z`：它會設定根目錄 `Cargo.toml` 中的版本（App、CLI 和 DMG 的唯一版本來源），執行提交前檢查、提交、打上 `vX.Y.Z` 標籤，並在推送前先詢問。標籤會觸發 `.github/workflows/release.yml`，在三台 runner 上同時執行測試並建置 Apple 晶片和 Intel 的 DMG，把它們和 `SHA256SUMS.txt` 附加到一個 GitHub Release 草稿上，並根據提交紀錄產生說明；檢查無誤後再發布。任何一個 job 失敗，草稿就會被刪除，標籤則保留。手動執行 workflow（Actions → Release → Run workflow，或 `gh workflow run release.yml`）是試跑，DMG 會保留為 workflow artifact。

App 內更新來自同樣的 Releases：「設定 → 關於與更新」會檢查最新已發布版本的 `latest.json`（Tsuba 啟動時也會安靜地檢查一次），下載適合這台 Mac 的套件包，只有簽章符合 `tauri.conf.json` 中的公開金鑰才會安裝。當儲存庫 secret `TAURI_SIGNING_PRIVATE_KEY` 存有更新用的私密金鑰（用 `pnpm tauri signer generate` 產生，不設密碼）時，CI 會產生已簽署的套件包和 `latest.json`。請備份這把金鑰：沒有它，已安裝的版本就再也無法更新。

設定以下儲存庫 secret 後就會簽署並公證：`APPLE_CERTIFICATE`（base64 .p12）、`APPLE_CERTIFICATE_PASSWORD`、`APPLE_SIGNING_IDENTITY`、`APPLE_ID`、`APPLE_PASSWORD`（App 專用密碼）和 `APPLE_TEAM_ID`。沒有這些時，DMG 不會簽署，下載後會被 Gatekeeper 阻擋。

</details>

## 授權

Tsuba 採用 [Apache License 2.0](LICENSE) 授權。執行時下載的威脅情資保有各自的授權，列在[威脅情資](#threat-intel)中，並顯示在每一則用到它的發現旁邊。
