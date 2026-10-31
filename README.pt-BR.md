<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>Dá uma olhada por você antes que um código desconhecido rode pela primeira vez.</b><br/>
  Um app de barra de menus do macOS que pega projetos falsos de entrevista, apps falsos de reunião, pacotes envenenados e servidores MCP maliciosos antes que eles rodem.
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">Site</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">Baixar</a> ·
  <a href="#install">Instalar</a> ·
  <a href="#development">Compilar a partir do código</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hans.md">简体中文</a> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <b>Português</b> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/chihyungchang/Tsuba?style=flat&color=b4873a" /></a>
  <a href="https://github.com/chihyungchang/Tsuba/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/chihyungchang/Tsuba/total?style=flat&color=1f8a50" /></a>
  <img alt="macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-1f1c17?style=flat&logo=apple" />
  <a href="LICENSE"><img alt="Licença: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat" /></a>
  <a href="https://m8ven.ai/mcp/chihyungchang-tsuba-hmqqrw?s=readme"><img alt="M8ven Verified" src="https://m8ven.ai/badge/mcp/chihyungchang-tsuba-hmqqrw?variant=verified&v=786841f2c90c79c8b3d1e9bf30ae8ba8" /></a>
</p>

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png" />
  <img src="docs/screenshots/overview-light.png" alt="Painel do Tsuba: status da proteção, o que requer atenção e verificações recentes" width="100%" />
</picture>
</p>

---

## O que é o Tsuba

Tsuba (鍔, a guarda da espada japonesa) protege o momento em que um código desconhecido roda pela primeira vez. Projetos falsos de entrevista, softwares falsos de reunião, pacotes npm envenenados e extensões de editor maliciosas chegam com embalagem nova a cada vez e usam ferramentas comuns como node, curl e bash, por isso o antivírus tradicional raramente os detecta.

O Tsuba entra em ação nos pontos onde eles rodam pela primeira vez: descobre **o que o código está prestes a fazer, de onde veio e se parece um ataque conhecido**, decide entre **Permitir, Alertar ou Bloquear** e mostra o arquivo, a linha e a regra por trás de cada veredito.

## Por que o Tsuba

- 🛡️ **Antes de rodar, não depois.** `curl | bash`, `npm install`, `git clone`, um novo DMG em Downloads, uma extensão ou um servidor MCP recém-instalado: cada um é verificado no momento em que rodaria pela primeira vez.
- 🧠 **Regras offline primeiro, IA com contexto.** Regras locais e inteligência de ameaças sempre rodam. Depois, um modelo de ponta lê as evidências para reduzir falsos alarmes e pegar o que nenhuma regra viu ainda, e ele nunca pode permitir o que as regras consideraram de alto risco.
- 🔑 **Nenhuma conta nova.** Usa o Claude Code ou o Codex já conectados no seu Mac, ou qualquer um de uns 20 provedores com a sua própria chave, ou nenhum modelo.
- 🔒 **Somente leitura por design.** O código verificado é analisado, nunca executado: imagens de disco são montadas como somente leitura, scripts remotos são baixados mas não executados, e o script que roda é o mesmo que o Tsuba verificou.
- 🤫 **Silencioso até importar.** Alertas vão para o histórico sem som; só Bloquear notifica, com um toque curto. Qualquer coisa confirmada como falso alarme pode ser ignorada ou marcada como segura.
- 🔄 **Atualiza a si mesmo, com segurança.** Novas versões são instaladas a partir dos GitHub Releases só quando a assinatura corresponde à chave do Tsuba.
- 🌏 **Fala o seu idioma.** O app, as notificações, as verificações do terminal, as explicações das regras e as respostas da IA estão disponíveis em English, 简体中文, 繁體中文, 日本語, 한국어, Español, Français, Deutsch, Português e Русский. Segue o macOS, ou escolha um em Configurações → Aparência.

## Tour pelo produto

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="Histórico de verificações: cada veredito com o arquivo, a linha e a regra por trás dele" />
</picture>
      <br/><sub><b>Histórico de verificações</b> — cada Alertar e Bloquear com o arquivo, a linha e a regra que correspondeu; ignore, mova para a quarentena ou marque como seguro</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="Check-up: um botão e uma lista que vai sendo preenchida" />
</picture>
      <br/><sub><b>Check-up</b> — um clique procura rastros de ataques conhecidos e depois verifica cada extensão de editor e ferramenta de IA</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="Escolhendo como os vereditos são feitos" />
</picture>
      <br/><sub><b>Avaliação</b> — o Claude Code ou o Codex em que você já está conectado, uma chave de API para uns 20 provedores, ou só regras offline</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="Fontes de inteligência de ameaças e suas licenças" />
</picture>
      <br/><sub><b>Inteligência de ameaças</b> — listas e assinaturas públicas, baixadas diariamente e verificadas localmente, cada uma com a sua origem</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## Instalação

Baixe o DMG em [Releases](https://github.com/chihyungchang/Tsuba/releases) (macOS 13 ou posterior): `Tsuba_*_aarch64.dmg` para Macs com Apple silicon (M1 e posteriores), `Tsuba_*_x64.dmg` para Macs Intel. Não precisa de conta; para a avaliação por IA, ele pode usar o Claude Code ou o Codex já conectados no seu Mac. A partir da 0.2.0, novas versões são instaladas de dentro do app (Configurações → Sobre e atualizações, ou Buscar atualizações… na barra de menus).

> [!WARNING]
> **As builds ainda não são assinadas nem notarizadas pela Apple.** O macOS bloqueia o app na primeira vez que você o abre: vá em **Ajustes do Sistema → Privacidade e Segurança** e clique em **Abrir Mesmo Assim**.
>
> O Tsuba é open source, então você pode conferir o que está rodando: compare o DMG com o `SHA256SUMS.txt` anexado a cada release (`shasum -a 256 Tsuba_*.dmg`), leia [o workflow](.github/workflows/release.yml) que o gerou, ou compile você mesmo (veja Publicação em [Desenvolvimento](#development)).
>
> Por favor, não remova o atributo de quarentena com `xattr`: o Tsuba alerta sobre instaladores que pedem isso, e o dele não deveria ser exceção.

## O que ele verifica

| Ponto de entrada | Exemplos | O que é verificado |
| --- | --- | --- |
| Comandos de terminal | `curl … \| bash`, `npm install`, `npx`, `npm start`, `code .`, `git clone` | Baixa o script remoto (sem executá-lo) e segue qualquer segunda etapa; a data de criação do pacote npm, o período de espera após o lançamento e os scripts de instalação; código oculto, C2 fixo no código e leituras de carteiras e cofres de senhas no código do projeto; tarefas do VS Code que rodam automaticamente quando a pasta é aberta |
| Colar no terminal | Uma página web pede para você "copiar este comando no terminal" | Alerta no momento em que você cola, sem acessar a internet; comandos ofuscados em base64 enviados a um shell são marcados como alto risco na hora |
| Pasta Downloads | Novos arquivos `.dmg`, `.pkg`, `.vsix` | Monta como somente leitura e verifica a assinatura, a notarização, a origem do download, se o executável principal foi trocado por um arquivo oculto e os scripts de instalação |
| Extensões de editor | Extensões novas ou atualizadas no VS Code, Cursor, Windsurf, VSCodium | A lista oficial de extensões maliciosas, ativação na inicialização, código escondido em caracteres Unicode invisíveis, acessos suspeitos à rede e a arquivos; extensões de alto risco vão para a quarentena automaticamente |
| Ferramentas de código com IA | Servidores MCP, skills e hooks de plugins para Claude Code, Cursor, Codex e outros; `.mcp.json`, hooks e `CLAUDE.md` em projetos | Se o pacote iniciado está em uma lista de maliciosos, se ele inicia de um diretório temporário ou oculto, quais segredos ele recebe; se skills e descrições de ferramentas escondem instruções para a IA (tool poisoning), pedem que ela esconda coisas do usuário, leem chaves privadas ou exfiltram dados |
| Check-up | Barra de menus → Check-up | Rastros deixados por ataques conhecidos, itens de login suspeitos, uma varredura rápida das extensões instaladas |
| Varredura de pasta | A página Varredura, ou `tsuba scan <folder>` | Instaladores, scripts, extensões e projetos com pontos de execução automática na pasta Downloads, em discos externos e em diretórios de código; arquivos inalterados que já passaram pela varredura são pulados e, por padrão, a pasta Downloads passa por nova varredura com as regras mais recentes a cada 7 dias |

Para perguntar "por que isto foi bloqueado?" dentro do Claude Code: `claude mcp add tsuba -- tsuba mcp`. É uma ferramenta MCP somente leitura: só consulta o histórico de verificações e a quarentena, e não pode mudar nada. Comandos e resumos que ela retorna são marcados como dados não confiáveis, e segredos são sempre ocultados.

Qualquer coisa confirmada como falso positivo pode ser "marcada como segura", o que registra a impressão digital do conteúdo na lista de permissões; se o conteúdo mudar, ele é verificado de novo. Arquivos, diretórios e extensões suspeitos podem ser movidos para a quarentena e restaurados ou excluídos a qualquer momento.

Extensões instaladas pelo marketplace não passam pelo terminal, então só podem ser verificadas logo após a instalação. Programas abertos com duplo clique no Finder ainda não podem ser bloqueados; isso exige o entitlement Endpoint Security da Apple (veja a seção 12 do PRD).

## Avaliação por IA

As regras offline sempre rodam primeiro, e a IA avalia em cima delas, levando o contexto em conta. Você pode escolher em Configurações:

- **Conta da ferramenta de código** (recomendado): o Claude Code ou o Codex já conectados no seu Mac. Modelos de ponta, sem chave de API para gerenciar.
- **Chave de API**: Claude, OpenAI ou Gemini, fornecedores de modelos como DeepSeek, Qwen, Kimi e GLM, plataformas como OpenRouter e SiliconFlow, modelos locais via Ollama, LM Studio ou vLLM, ou qualquer endpoint compatível com a API Chat Completions da OpenAI.
- **Só regras offline**: sem acesso à rede, sem chamadas a modelos.

Os modelos se dividem em dois níveis de confiança. Pesquisas públicas mostram que modelos de ponta estão claramente à frente em reconhecer código malicioso, enquanto modelos que não são de ponta geram mais falsos positivos e são enganados com mais facilidade por prompt injection no código:

| | Modelos de ponta (Claude, OpenAI / Codex, Gemini, ou um modelo marcado manualmente em um endpoint ou plataforma personalizados) | Modelos locais e outros |
| --- | --- | --- |
| Podem recomendar Bloquear sozinhos | Sim | Não, no máximo Alertar |
| Podem reduzir o risco encontrado pelas regras offline | Podem reduzir Bloquear para Alertar, mas não podem Permitir direto | Não |

Os comentários do código são removidos antes de qualquer coisa chegar ao modelo (para neutralizar prompt injection escondido em comentários); quando as evidências são longas demais, o início e o fim de cada texto são mantidos, e as correspondências das regras offline são sempre mantidas por inteiro. O modelo recebe só as evidências de que esta avaliação precisa; nenhum outro arquivo, variável de ambiente ou segredo é enviado. A configuração e o histórico de verificações ficam em `~/.tsuba`.

<a id="threat-intel"></a>
## Inteligência de ameaças

Além das regras offline, o Tsuba atualiza sua inteligência de ameaças a partir de fontes públicas uma vez por dia e a guarda em `~/.tsuba/intel` (você também pode rodar `tsuba intel update` no terminal):

| Fonte | Conteúdo | Licença |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | Cerca de 230.000 pacotes npm / PyPI confirmados como maliciosos; dependências transitivas nos lockfiles também são verificadas | Apache-2.0 |
| [OSV.dev](https://osv.dev) (online, pode ser desativado) | O mesmo que acima, consultado em tempo real durante a verificação; só o nome e a versão do pacote são enviados | - |
| Lista oficial de extensões maliciosas do VS Code | Extensões maliciosas removidas pela Microsoft | - |
| Regras YARA da [Elastic](https://github.com/elastic/protections-artifacts) e da [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | Assinaturas de famílias de malware conhecidas | Elastic License 2.0 / MIT |
| Regras YARA do [GuardDog](https://github.com/DataDog/guarddog) | Padrões de código suspeitos comuns em pacotes maliciosos (apenas evidência; nunca gera um Alertar sozinho) | Apache-2.0 |
| Regras locais do XProtect | Assinaturas de malware da própria Apple, usadas só neste Mac | Apple |
| [VirusTotal](https://www.virustotal.com) (opcional, com a sua chave) | Vereditos de mais de 70 motores antivírus sobre instaladores, programas e scripts remotos; só hashes são enviados, arquivos nunca são enviados | A API gratuita não permite uso comercial |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus (opcional) | Domínios, IPs e URLs maliciosos; requer uma Auth-Key gratuita, e o plano gratuito é só para uso sem fins lucrativos | - |

As regras são compiladas e executadas com o [YARA-X](https://github.com/VirusTotal/yara-x). Um pacote de regras baixado da URL do pacote de regras só é usado se tiver uma assinatura válida (`tsuba.sig`, ed25519) e uma versão que não seja mais antiga que a em uso; assine-o para publicação com `tsuba rules sign --key <private key file> <rules directory>`. As próprias regras de detecção do Tsuba também não ficam no código: estão em [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) e [tsuba.toml](crates/engine/rules/tsuba.toml) e podem ser atualizadas separadamente.

Para as diretrizes de desenvolvimento, veja [CLAUDE.md](CLAUDE.md).

## No terminal

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

Comandos cancelados continuam no histórico do shell; depois de conferi-los, pressione a seta para cima para recuperá-los.

Todo comando `tsuba` aceita `--lang <code>` (`en`, `zh-Hans`, `zh-Hant`, `ja`, `ko`, `es`, `fr`, `de`, `pt-BR`, `ru`); sem ele, o terminal usa o idioma escolhido no app.

### Execução de teste no sandbox (protótipo)

Para um script de que você não tem certeza, dá para rodá-lo rapidamente em um sandbox e ver o que ele realmente faz, em vez de ler o código linha por linha:

```bash
tsuba sandbox install.sh
```

O sandbox roda direto no sandbox embutido do macOS: a pasta pessoal real fica bloqueada e o programa só vê uma pasta pessoal falsa com iscas; toda requisição de rede é registrada por um proxy local e nunca é enviada de fato; ele roda por no máximo 60 segundos. Ler segredos de isca e enviá-los para fora, gravar itens de login e conectar a IPs diretos ficam todos registrados. Atenção: não ver nenhum comportamento ruim em uma execução curta não garante que seja seguro.

Você também pode testar um diretório de projeto no sandbox (`tsuba sandbox ~/code/interview-project`), que roda o comando de início e observa o comportamento; código malicioso em projetos de entrevista que "roda assim que você abre" fica exposto aqui. Adicione `--install` para testar a instalação das dependências (`npm install`) no sandbox e ver o que os scripts de instalação fazem; nesse modo só downloads do registro oficial do npm são liberados, e qualquer outra conexão continua apenas registrada. O sandbox em máquina virtual para DMGs / apps ainda não foi construído.

<a id="development"></a>
## Desenvolvimento

<details>
<summary><b>Estrutura de diretórios</b></summary>

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

Requer Rust (`rustup`), Node.js e pnpm.

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

O diretório de amostras contém dois subdiretórios, `malicious/` e `benign/`; cada arquivo ou subdiretório conta como uma amostra (projetos, extensões, instaladores e scripts funcionam, assim como links simbólicos). Só as regras offline são usadas, então os resultados são reproduzíveis; se as metas não forem atingidas, o código de saída é 1, então dá para colocar no CI. Para uma divisão por tempo, coloque as amostras mais antigas e as mais novas em dois diretórios e rode-os separadamente.

Durante o desenvolvimento, o app procura o verificador do terminal ao lado de si mesmo (`target/debug/tsuba`); configure-o com um clique em Configurações → Proteção → Conectar ao zsh, e ele vale para as novas janelas do terminal.

As amostras de teste são todas inertes: só imitam a forma do código de ataque, seus IPs pertencem a faixas de documentação e o conteúdo decodificado também é inofensivo.

O código contém o texto em inglês; as traduções ficam em um catálogo por idioma (`locales/<code>.json` em `app/src`, `app/src-tauri`, `crates/engine` e `crates/cli`), e cada regra do pacote de regras traz o seu próprio `message_<lang>`. Os testes dos catálogos e `pnpm check:i18n` falham quando falta uma string em algum idioma ou quando uma tradução perde um `{placeholder}`.

O ícone do app, o laptop do painel e a guarda são renderizações do Blender: `app/src-tauri/icons/source/` contém os scripts e os passos para gerá-los de novo.

<details>
<summary><b>Publicação</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

Um bundle de release leva o verificador do terminal como `Tsuba.app/Contents/MacOS/tsuba`. O `tauri.release.conf.json` o adiciona e roda `app/scripts/build-cli-sidecar.sh`; ele fica fora do `tauri.conf.json` porque o Tauri se recusa a compilar sem o arquivo, o que quebraria o `cargo test`.

Para publicar, rode `scripts/release.sh X.Y.Z` em um `main` limpo: ele define a versão no `Cargo.toml` da raiz (a fonte única para o app, a CLI e o DMG), roda as verificações de pré-commit, faz o commit, cria a tag `vX.Y.Z` e pergunta antes de fazer push. A tag dispara o `.github/workflows/release.yml`, que roda os testes e gera os DMGs para Apple silicon e Intel em três runners ao mesmo tempo, anexando-os junto com o `SHA256SUMS.txt` a um GitHub Release em rascunho, com notas geradas a partir dos commits, e o publica quando todos os jobs passam (o que também reconstrói o site). Se algum job falhar, o rascunho é excluído e a tag permanece. Rodar o workflow manualmente (Actions → Release → Run workflow, ou `gh workflow run release.yml`) é um teste a seco que, em vez disso, guarda os DMGs como artefatos do workflow.

As atualizações dentro do app vêm dos mesmos releases: Configurações → Sobre e atualizações consulta o `latest.json` do release publicado mais recente (o Tsuba também verifica discretamente ao abrir), baixa o pacote para este Mac e só o instala se a assinatura corresponder à chave pública em `tauri.conf.json`. O CI gera os pacotes assinados e o `latest.json` quando o secret de repositório `TAURI_SIGNING_PRIVATE_KEY` contém a chave privada do atualizador (gerada com `pnpm tauri signer generate`, sem senha). Guarde um backup dessa chave: sem ela, as cópias instaladas nunca mais poderão ser atualizadas.

Ele assina e notariza quando estes secrets de repositório estão definidos: `APPLE_CERTIFICATE` (.p12 em base64), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` (senha específica de app) e `APPLE_TEAM_ID`. Sem eles, o DMG não é assinado e o Gatekeeper o bloqueia ao ser baixado.

</details>

## Licença

O Tsuba é licenciado sob a [Apache License 2.0](LICENSE). A inteligência de ameaças que ele baixa durante a execução mantém a sua própria licença, listada em [Inteligência de ameaças](#threat-intel) e mostrada ao lado de cada achado que a utiliza.
