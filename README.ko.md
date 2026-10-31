<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>낯선 코드가 처음 실행되기 전에 먼저 살펴봅니다.</b><br/>
  가짜 면접 프로젝트, 가짜 회의 앱, 악성 코드가 심긴 패키지, 악성 MCP 서버를 실행 전에 잡아내는 macOS 메뉴 막대 앱입니다.
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">웹사이트</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">다운로드</a> ·
  <a href="#install">설치</a> ·
  <a href="#development">소스에서 빌드</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hans.md">简体中文</a> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <b>한국어</b> · <a href="README.es.md">Español</a> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
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
  <img src="docs/screenshots/overview-light.png" alt="Tsuba 대시보드: 보호 상태, 확인이 필요한 항목, 최근 검사" width="100%" />
</picture>
</p>

---

## Tsuba란

Tsuba(鍔, 일본도의 코등이)는 낯선 코드가 처음 실행되는 순간을 지킵니다. 가짜 면접 프로젝트, 가짜 회의 소프트웨어, 악성 코드가 심긴 npm 패키지, 악성 편집기 확장 프로그램은 매번 새로운 모습으로 나타나고 node, curl, bash 같은 평범한 도구를 쓰기 때문에 기존 백신은 이를 거의 잡아내지 못합니다.

Tsuba는 이런 코드가 처음 실행되는 진입점에서 개입합니다. **코드가 무엇을 하려는지, 어디서 왔는지, 알려진 공격과 비슷한지** 파악한 뒤 **허용, 경고, 차단** 중 하나로 판정하고, 모든 판정의 근거가 된 파일, 줄, 규칙을 보여 줍니다.

## 왜 Tsuba인가

- 🛡️ **실행된 뒤가 아니라 실행되기 전에.** `curl | bash`, `npm install`, `git clone`, 다운로드 폴더의 새 DMG, 방금 설치한 확장 프로그램이나 MCP 서버를 각각 처음 실행되려는 순간에 검사합니다.
- 🧠 **오프라인 규칙이 먼저, AI는 맥락으로.** 로컬 규칙과 위협 인텔리전스는 항상 실행됩니다. 이어서 프런티어 모델이 증거를 읽고 오탐을 줄이며 어떤 규칙도 본 적 없는 공격을 잡아냅니다. 규칙이 고위험으로 판단한 것은 모델도 허용할 수 없습니다.
- 🔑 **새 계정이 필요 없습니다.** Mac에 이미 로그인된 Claude Code나 Codex를 쓰거나, 본인 키로 20여 곳의 제공업체 중 하나를 쓰거나, 모델 없이도 쓸 수 있습니다.
- 🔒 **설계부터 읽기 전용.** 검사 대상 코드는 해석만 하고 실행하지 않습니다. 디스크 이미지는 읽기 전용으로 마운트하고, 원격 스크립트는 다운로드만 하고 실행하지 않으며, 실제로 실행되는 스크립트는 Tsuba가 검사한 바로 그 스크립트입니다.
- 🤫 **중요할 때만 알립니다.** 경고는 소리 없이 기록에 남고, 차단만 짧은 소리로 알립니다. 오탐으로 확인된 것은 무시하거나 안전으로 표시할 수 있습니다.
- 🔄 **안전하게 스스로 업데이트합니다.** 새 버전은 서명이 Tsuba의 키와 일치할 때만 GitHub Releases에서 설치됩니다.
- 🌏 **사용자의 언어로.** 앱, 알림, 터미널 검사, 규칙 설명, AI 답변을 English, 简体中文, 繁體中文, 日本語, 한국어, Español, Français, Deutsch, Português, Русский로 제공합니다. macOS 설정을 따르거나 설정 → 모양에서 직접 고를 수 있습니다.

## 둘러보기

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="검사 기록: 모든 판정과 그 근거가 된 파일, 줄, 규칙" />
</picture>
      <br/><sub><b>검사 기록</b> — 모든 경고와 차단을 일치한 파일, 줄, 규칙과 함께 보여 줍니다. 무시하거나, 격리하거나, 안전으로 표시할 수 있습니다</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="상태 점검: 버튼 하나로 채워지는 체크리스트" />
</picture>
      <br/><sub><b>상태 점검</b> — 한 번의 클릭으로 알려진 공격의 흔적을 찾고, 모든 편집기 확장 프로그램과 AI 도구를 검사합니다</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="판정 방식 선택" />
</picture>
      <br/><sub><b>판단 방식</b> — 이미 로그인된 Claude Code나 Codex, 20여 곳 제공업체의 API 키, 또는 오프라인 규칙만</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="위협 인텔리전스 출처와 라이선스" />
</picture>
      <br/><sub><b>위협 인텔리전스</b> — 매일 다운로드해 로컬에서 대조하는 공개 목록과 시그니처, 각각의 출처 표시</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## 설치

[Releases](https://github.com/chihyungchang/Tsuba/releases)에서 DMG를 다운로드하세요(macOS 13 이상). Apple silicon Mac(M1 이후)은 `Tsuba_*_aarch64.dmg`, Intel Mac은 `Tsuba_*_x64.dmg`입니다. 계정은 필요 없으며, AI 검토에는 Mac에 이미 로그인된 Claude Code나 Codex를 쓸 수 있습니다. 0.2.0부터는 앱 안에서 새 버전을 설치합니다(설정 → 정보 및 업데이트, 또는 메뉴 막대의 업데이트 확인…).

> [!WARNING]
> **빌드는 아직 Apple의 서명과 공증을 받지 않았습니다.** 처음 열 때 macOS가 앱을 막습니다. **시스템 설정 → 개인정보 보호 및 보안**으로 가서 **그래도 열기**를 클릭하세요.
>
> Tsuba는 오픈 소스이므로 실행하는 것을 직접 확인할 수 있습니다. 각 릴리스에 첨부된 `SHA256SUMS.txt`와 DMG를 비교하거나(`shasum -a 256 Tsuba_*.dmg`), 이를 빌드한 [워크플로](.github/workflows/release.yml)를 읽거나, 직접 빌드하세요([개발](#development)의 릴리스 항목 참고).
>
> `xattr`로 격리 플래그를 제거하지 마세요. Tsuba는 그렇게 하라고 요구하는 설치 프로그램을 경고하며, 자기 자신도 예외가 되어서는 안 됩니다.

## 검사 대상

| 진입점 | 예시 | 검사 내용 |
| --- | --- | --- |
| 터미널 명령 | `curl … \| bash`, `npm install`, `npx`, `npm start`, `code .`, `git clone` | 원격 스크립트를 (실행하지 않고) 다운로드해 2단계 스크립트까지 따라갑니다. npm 패키지의 생성일, 릴리스 대기 기간, 설치 스크립트를 확인합니다. 프로젝트 소스에서 숨겨진 코드, 하드코딩된 C2, 지갑과 암호 저장소 읽기를 찾습니다. 폴더를 열면 자동으로 실행되는 VS Code 작업도 확인합니다 |
| 터미널에 붙여 넣기 | 웹 페이지가 "이 명령을 터미널에 복사하세요"라고 안내하는 경우 | 붙여 넣는 순간 네트워크 없이 한 번 경고합니다. base64로 난독화해 셸로 넘기는 명령은 즉시 고위험으로 표시합니다 |
| 다운로드 폴더 | 새 `.dmg`, `.pkg`, `.vsix` 파일 | 읽기 전용으로 마운트한 뒤 서명, 공증, 다운로드 출처, 주 실행 파일이 숨김 파일로 바뀌었는지, 설치 스크립트를 검사합니다 |
| 편집기 확장 프로그램 | VS Code, Cursor, Windsurf, VSCodium에 새로 설치되거나 업데이트된 확장 프로그램 | 공식 악성 확장 프로그램 목록, 시작 시 활성화, 보이지 않는 Unicode 문자에 숨긴 코드, 의심스러운 네트워크 및 파일 접근을 확인합니다. 고위험 확장 프로그램은 자동으로 격리함으로 옮깁니다 |
| AI 코딩 도구 | Claude Code, Cursor, Codex 등의 MCP 서버, 스킬, 플러그인 훅, 프로젝트의 `.mcp.json`, 훅, `CLAUDE.md` | 실행되는 패키지가 악성 목록에 있는지, 임시 디렉터리나 숨겨진 디렉터리에서 시작되는지, 어떤 비밀 정보를 받는지 확인합니다. 스킬과 도구 설명에 AI를 향한 지시를 숨겼는지(도구 포이즈닝), 사용자에게 숨기라고 하는지, 개인 키를 읽거나 데이터를 유출하는지도 봅니다 |
| 상태 점검 | 메뉴 막대 → 상태 점검 | 알려진 공격이 남긴 흔적, 의심스러운 로그인 항목, 설치된 확장 프로그램 빠른 스캔 |
| 폴더 스캔 | 스캔 페이지 또는 `tsuba scan <folder>` | 다운로드 폴더, 외장 드라이브, 코드 디렉터리의 설치 프로그램, 스크립트, 확장 프로그램, 자동 실행 진입점이 있는 프로젝트. 이미 스캔했고 바뀌지 않은 파일은 건너뛰며, 기본적으로 7일마다 최신 규칙으로 다운로드 폴더를 다시 스캔합니다 |

Claude Code 안에서 "이건 왜 차단됐어?"라고 물으려면 `claude mcp add tsuba -- tsuba mcp`를 실행하세요. 읽기 전용 MCP 도구로, 검사 기록과 격리함을 조회만 할 수 있고 아무것도 바꿀 수 없습니다. 반환하는 명령과 요약은 신뢰할 수 없는 데이터로 표시되며, 비밀 정보는 항상 가려집니다.

오탐으로 확인된 것은 "안전으로 표시"할 수 있습니다. 내용 지문이 허용 목록에 기록되고, 내용이 바뀌면 다시 검사합니다. 의심스러운 파일, 디렉터리, 확장 프로그램은 격리함으로 옮길 수 있으며 언제든 복원하거나 삭제할 수 있습니다.

확장 프로그램 마켓플레이스에서 설치한 확장 프로그램은 터미널을 거치지 않으므로 설치 직후에만 검사할 수 있습니다. Finder에서 더블 클릭으로 연 프로그램은 아직 막을 수 없습니다. Apple의 Endpoint Security 권한이 필요합니다(PRD 12절 참고).

## AI 판단

오프라인 규칙이 항상 먼저 실행되고, 그 위에서 AI가 맥락을 고려해 판단합니다. 설정에서 고를 수 있습니다.

- **코딩 도구 계정**(권장): Mac에 이미 로그인된 Claude Code나 Codex. 프런티어 모델이며 관리할 API 키가 없습니다.
- **API 키**: Claude, OpenAI, Gemini, DeepSeek, Qwen, Kimi, GLM 같은 모델 개발사, OpenRouter와 SiliconFlow 같은 플랫폼, Ollama, LM Studio, vLLM으로 돌리는 로컬 모델, 또는 OpenAI Chat Completions API와 호환되는 모든 엔드포인트.
- **오프라인 규칙만**: 네트워크 접속도, 모델 호출도 없습니다.

모델은 두 가지 신뢰 등급으로 나뉩니다. 공개된 연구에 따르면 프런티어 모델은 악성 코드를 알아보는 능력이 분명히 앞서는 반면, 프런티어가 아닌 모델은 오탐이 더 많고 코드 속 프롬프트 인젝션에 더 쉽게 속습니다.

| | 프런티어 모델(Claude, OpenAI / Codex, Gemini, 또는 사용자 지정 엔드포인트나 플랫폼에서 직접 지정한 모델) | 로컬 모델 및 기타 모델 |
| --- | --- | --- |
| 단독으로 차단 권장 가능 | 예 | 아니요, 최대 경고 |
| 오프라인 규칙이 찾은 위험을 낮출 수 있음 | 차단을 경고로 낮출 수 있지만 바로 허용할 수는 없음 | 아니요 |

모델에 보내기 전에 코드 주석을 제거합니다(주석에 숨긴 프롬프트 인젝션을 막기 위해). 증거가 너무 길면 각 텍스트의 앞과 끝을 남기며, 오프라인 규칙에 일치한 부분은 항상 전부 남깁니다. 모델은 이번 판단에 필요한 증거만 받으며, 다른 파일, 환경 변수, 비밀 정보는 업로드하지 않습니다. 설정과 검사 기록은 `~/.tsuba`에 있습니다.

<a id="threat-intel"></a>
## 위협 인텔리전스

Tsuba는 오프라인 규칙에 더해 하루에 한 번 공개 출처에서 위협 인텔리전스를 업데이트하고 `~/.tsuba/intel`에 저장합니다(터미널에서 `tsuba intel update`를 실행해도 됩니다).

| 출처 | 내용 | 라이선스 |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | 확인된 악성 npm / PyPI 패키지 약 23만 개. lockfile의 전이 의존성도 검사합니다 | Apache-2.0 |
| [OSV.dev](https://osv.dev)(온라인, 끌 수 있음) | 위와 같으며 검사 중 실시간으로 조회합니다. 패키지 이름과 버전만 보냅니다 | - |
| VS Code 공식 악성 확장 프로그램 목록 | Microsoft가 내린 악성 확장 프로그램 | - |
| [Elastic](https://github.com/elastic/protections-artifacts), [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) YARA 규칙 | 알려진 악성 코드 계열의 시그니처 | Elastic License 2.0 / MIT |
| [GuardDog](https://github.com/DataDog/guarddog) YARA 규칙 | 악성 패키지에 흔한 의심스러운 코드 패턴(증거로만 쓰이며 단독으로 경고를 일으키지 않음) | Apache-2.0 |
| 로컬 XProtect 규칙 | Apple 자체 악성 코드 시그니처, 이 Mac에서만 사용 | Apple |
| [VirusTotal](https://www.virustotal.com)(선택, 본인 키) | 설치 프로그램, 프로그램, 원격 스크립트에 대한 70개 이상 백신 엔진의 판정. 해시만 보내며 파일은 업로드하지 않습니다 | 무료 API는 상업적 이용 불가 |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus(선택) | 악성 도메인, IP, URL. 무료 Auth-Key가 필요하며 무료 등급은 비영리 용도로만 쓸 수 있습니다 | - |

규칙은 [YARA-X](https://github.com/VirusTotal/yara-x)로 컴파일하고 실행합니다. 규칙 팩 URL에서 다운로드한 규칙 팩은 유효한 서명(`tsuba.sig`, ed25519)이 있고 버전이 사용 중인 것보다 오래되지 않았을 때만 사용합니다. 릴리스용 서명은 `tsuba rules sign --key <private key file> <rules directory>`로 합니다. Tsuba 자체 탐지 규칙도 코드에 들어 있지 않고 [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar)와 [tsuba.toml](crates/engine/rules/tsuba.toml)에 있어 따로 업데이트할 수 있습니다.

개발 지침은 [CLAUDE.md](CLAUDE.md)를 참고하세요.

## 터미널에서

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

취소한 명령은 셸 기록에 남습니다. 확인을 마쳤다면 위쪽 화살표 키로 다시 불러오세요.

모든 `tsuba` 명령은 `--lang <code>`(`en`, `zh-Hans`, `zh-Hant`, `ja`, `ko`, `es`, `fr`, `de`, `pt-BR`, `ru`)를 받습니다. 지정하지 않으면 터미널은 앱에서 고른 언어를 씁니다.

### 샌드박스 시험 실행(프로토타입)

확신이 서지 않는 스크립트는 코드를 한 줄씩 읽는 대신 샌드박스에서 잠깐 실행해 실제로 무엇을 하는지 볼 수 있습니다.

```bash
tsuba sandbox install.sh
```

샌드박스는 macOS 내장 샌드박스에서 바로 실행됩니다. 실제 홈 디렉터리는 잠기고 프로그램은 미끼가 든 가짜 홈 디렉터리만 봅니다. 모든 네트워크 요청은 로컬 프록시가 기록할 뿐 실제로 내보내지 않으며, 최대 60초 동안 실행됩니다. 미끼 비밀 정보를 읽어 내보내기, 로그인 항목 쓰기, IP 직접 연결은 모두 기록됩니다. 주의: 짧은 실행에서 나쁜 동작이 보이지 않았다고 안전이 보장되지는 않습니다.

프로젝트 디렉터리도 샌드박스에서 시험 실행할 수 있습니다(`tsuba sandbox ~/code/interview-project`). 시작 명령을 실행하고 동작을 지켜보므로, 면접 프로젝트에 숨은 "열자마자 실행되는" 악성 코드가 여기서 드러납니다. `--install`을 붙이면 샌드박스에서 의존성 설치(`npm install`)를 시도해 설치 스크립트가 무엇을 하는지 봅니다. 이 모드에서는 npm 공식 레지스트리의 다운로드만 허용하고, 다른 연결은 여전히 기록만 합니다. DMG / 앱용 가상 머신 샌드박스는 아직 만들지 않았습니다.

<a id="development"></a>
## 개발

<details>
<summary><b>디렉터리 구조</b></summary>

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

Rust(`rustup`), Node.js, pnpm이 필요합니다.

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

샘플 디렉터리에는 `malicious/`와 `benign/` 두 하위 디렉터리가 있으며, 파일이나 하위 디렉터리 하나가 샘플 하나입니다(프로젝트, 확장 프로그램, 설치 프로그램, 스크립트 모두 되고 심볼릭 링크도 됩니다). 오프라인 규칙만 쓰므로 결과를 재현할 수 있고, 목표에 못 미치면 종료 코드가 1이라 CI에 넣을 수 있습니다. 시점 기준으로 나누려면 오래된 샘플과 새 샘플을 두 디렉터리에 넣고 따로 실행하세요.

개발 중에는 앱이 자기 옆에서 터미널 검사 프로그램(`target/debug/tsuba`)을 찾습니다. 설정 → 보호 → zsh에 연결에서 한 번에 설정할 수 있으며, 새로 연 터미널 창부터 적용됩니다.

테스트 샘플은 모두 무해합니다. 공격 코드의 형태만 흉내 내며, IP는 문서용 대역이고 디코딩한 내용도 무해합니다.

코드에는 영어 텍스트가 들어 있고, 번역은 언어별 카탈로그 하나에 있습니다(`app/src`, `app/src-tauri`, `crates/engine`, `crates/cli`의 `locales/<code>.json`). 규칙 팩의 각 규칙은 자체 `message_<lang>`을 가집니다. 어느 언어에서든 문자열이 빠지거나 번역에서 `{placeholder}`가 사라지면 카탈로그 테스트와 `pnpm check:i18n`이 실패합니다.

앱 아이콘, 대시보드의 노트북, 코등이는 Blender 렌더링입니다. `app/src-tauri/icons/source/`에 스크립트와 다시 생성하는 방법이 있습니다.

<details>
<summary><b>릴리스</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

릴리스 번들에는 터미널 검사 프로그램이 `Tsuba.app/Contents/MacOS/tsuba`로 들어 있습니다. `tauri.release.conf.json`이 이를 추가하고 `app/scripts/build-cli-sidecar.sh`를 실행합니다. `tauri.conf.json`에 넣지 않은 이유는 파일이 없으면 Tauri가 빌드를 거부해 `cargo test`가 깨지기 때문입니다.

배포하려면 깨끗한 `main`에서 `scripts/release.sh X.Y.Z`를 실행하세요. 루트 `Cargo.toml`의 버전(앱, CLI, DMG의 단일 출처)을 설정하고, 커밋 전 검사를 실행하고, 커밋하고, `vX.Y.Z` 태그를 붙인 뒤 푸시 전에 확인을 묻습니다. 태그가 `.github/workflows/release.yml`을 시작하며, 이 워크플로는 테스트를 실행하고 세 러너에서 동시에 Apple silicon과 Intel DMG를 빌드해 커밋으로부터 생성한 노트와 함께 `SHA256SUMS.txt`를 초안 GitHub Release에 첨부하고, 모든 작업이 통과하면 게시합니다(웹사이트도 함께 다시 빌드됩니다). 작업이 하나라도 실패하면 초안은 삭제되고 태그는 남습니다. 워크플로를 직접 실행하면(Actions → Release → Run workflow 또는 `gh workflow run release.yml`) 시험 실행이 되어 DMG를 워크플로 아티팩트로만 보관합니다.

앱 내 업데이트도 같은 릴리스에서 받습니다. 설정 → 정보 및 업데이트에서 최신 게시 릴리스의 `latest.json`을 확인하고(Tsuba는 시작할 때도 조용히 확인합니다), 이 Mac용 패키지를 다운로드해 서명이 `tauri.conf.json`의 공개 키와 일치할 때만 설치합니다. `TAURI_SIGNING_PRIVATE_KEY` 저장소 시크릿에 업데이터 개인 키(`pnpm tauri signer generate`로 생성, 암호 없음)가 있으면 CI가 서명된 패키지와 `latest.json`을 만듭니다. 이 키는 꼭 백업하세요. 키가 없으면 설치된 사본을 다시는 업데이트할 수 없습니다.

다음 저장소 시크릿이 설정되면 서명과 공증을 합니다: `APPLE_CERTIFICATE`(base64 .p12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`(앱 전용 암호), `APPLE_TEAM_ID`. 이 시크릿이 없으면 DMG는 서명되지 않으며, 다운로드하면 Gatekeeper가 막습니다.

</details>

## 라이선스

Tsuba는 [Apache License 2.0](LICENSE)으로 배포됩니다. 실행 중에 다운로드하는 위협 인텔리전스는 각자의 라이선스를 따르며, [위협 인텔리전스](#threat-intel)에 나열되어 있고 이를 사용하는 모든 발견 항목 옆에 표시됩니다.
