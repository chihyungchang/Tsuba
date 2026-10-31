<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>Jette un œil pour vous avant que du code inconnu s'exécute pour la première fois.</b><br/>
  Une app pour la barre des menus de macOS qui repère les faux projets d'entretien, les fausses apps de réunion, les paquets piégés et les serveurs MCP malveillants avant qu'ils s'exécutent.
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">Site web</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">Télécharger</a> ·
  <a href="#install">Installation</a> ·
  <a href="#development">Compiler depuis les sources</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hans.md">简体中文</a> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.es.md">Español</a> · <b>Français</b> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest"><img alt="Version" src="https://img.shields.io/github/v/release/chihyungchang/Tsuba?style=flat&color=b4873a" /></a>
  <a href="https://github.com/chihyungchang/Tsuba/releases"><img alt="Téléchargements" src="https://img.shields.io/github/downloads/chihyungchang/Tsuba/total?style=flat&color=1f8a50" /></a>
  <img alt="macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-1f1c17?style=flat&logo=apple" />
  <a href="LICENSE"><img alt="Licence : Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat" /></a>
  <a href="https://m8ven.ai/mcp/chihyungchang-tsuba-hmqqrw?s=readme"><img alt="M8ven Verified" src="https://m8ven.ai/badge/mcp/chihyungchang-tsuba-hmqqrw?variant=verified&v=786841f2c90c79c8b3d1e9bf30ae8ba8" /></a>
</p>

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png" />
  <img src="docs/screenshots/overview-light.png" alt="Le tableau de bord de Tsuba : état de la protection, ce qui est à examiner et les vérifications récentes" width="100%" />
</picture>
</p>

---

## Qu'est-ce que Tsuba

Tsuba (鍔, la garde d'un sabre japonais) veille sur le moment où du code inconnu s'exécute pour la première fois. Faux projets d'entretien, faux logiciels de réunion, paquets npm piégés et extensions d'éditeur malveillantes changent d'emballage à chaque fois et s'appuient sur des outils ordinaires comme node, curl et bash : les antivirus traditionnels les signalent donc rarement.

Tsuba intervient aux points d'entrée où ils s'exécutent pour la première fois : il détermine **ce que le code s'apprête à faire, d'où il vient et s'il ressemble à une attaque connue**, puis décide d'**Autoriser, Avertir ou Bloquer**, en montrant le fichier, la ligne et la règle derrière chaque verdict.

## Pourquoi Tsuba

- 🛡️ **Avant l'exécution, pas après.** `curl | bash`, `npm install`, `git clone`, un nouveau DMG dans Téléchargements, une extension ou un serveur MCP tout juste installé : chacun est vérifié au moment où il s'exécuterait pour la première fois.
- 🧠 **Règles hors ligne d'abord, IA en contexte.** Les règles locales et le renseignement sur les menaces passent toujours. Un modèle de pointe lit ensuite les preuves pour réduire les fausses alertes et repérer ce qu'aucune règle n'a encore vu, sans jamais pouvoir autoriser ce que les règles ont jugé à haut risque.
- 🔑 **Aucun nouveau compte.** Tsuba utilise le Claude Code ou le Codex déjà connecté sur votre Mac, l'un des quelque 20 fournisseurs avec votre propre clé, ou aucun modèle du tout.
- 🔒 **Lecture seule par conception.** Le code vérifié est analysé, jamais exécuté : les images disque sont montées en lecture seule, les scripts distants sont téléchargés mais pas exécutés, et le script qui s'exécute est bien celui que Tsuba a vérifié.
- 🤫 **Discret tant que ce n'est pas important.** Les avertissements arrivent dans l'historique sans bruit ; seul Bloquer déclenche une notification avec un son bref. Tout ce qui est confirmé comme fausse alerte peut être ignoré ou marqué comme sûr.
- 🔄 **Se met à jour seul, en sécurité.** Les nouvelles versions s'installent depuis les GitHub Releases uniquement si leur signature correspond à la clé de Tsuba.
- 🌏 **Parle votre langue.** L'app, les notifications, les vérifications du terminal, les explications des règles et les réponses de l'IA existent en English, 简体中文, 繁體中文, 日本語, 한국어, Español, Français, Deutsch, Português et Русский. Tsuba suit la langue de macOS, ou choisissez-en une dans Réglages → Apparence.

## Visite guidée

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="Historique des vérifications : chaque verdict avec le fichier, la ligne et la règle qui le justifient" />
</picture>
      <br/><sub><b>Historique des vérifications</b> — chaque Avertir et Bloquer avec le fichier, la ligne et la règle déclenchée ; ignorez-le, mettez-le en quarantaine ou marquez-le comme sûr</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="Bilan de santé : un bouton, une liste de contrôle qui se remplit" />
</picture>
      <br/><sub><b>Bilan de santé</b> — un clic recherche les traces d'attaques connues, puis vérifie chaque extension d'éditeur et chaque outil IA</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="Choisir comment les verdicts sont rendus" />
</picture>
      <br/><sub><b>Jugement</b> — le Claude Code ou le Codex auquel vous êtes déjà connecté, une clé API pour l'un des quelque 20 fournisseurs, ou les règles hors ligne uniquement</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="Sources du renseignement sur les menaces et leurs licences" />
</picture>
      <br/><sub><b>Renseignement sur les menaces</b> — listes publiques et signatures, téléchargées chaque jour et comparées en local, chacune avec sa provenance</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## Installation

Téléchargez le DMG depuis les [Releases](https://github.com/chihyungchang/Tsuba/releases) (macOS 13 ou ultérieur) : `Tsuba_*_aarch64.dmg` pour les Mac Apple silicon (M1 et ultérieurs), `Tsuba_*_x64.dmg` pour les Mac Intel. Aucun compte n'est nécessaire ; pour l'examen par IA, Tsuba peut utiliser le Claude Code ou le Codex déjà connecté sur votre Mac. Depuis la 0.2.0, les nouvelles versions s'installent depuis l'app (Réglages → À propos et mises à jour, ou Rechercher des mises à jour… dans la barre des menus).

> [!WARNING]
> **Les builds ne sont pas encore signés ni notariés par Apple.** macOS bloque l'app à sa première ouverture : allez dans **Réglages Système → Confidentialité et sécurité** et cliquez sur **Ouvrir quand même**.
>
> Tsuba est open source, vous pouvez donc vérifier ce que vous exécutez : comparez le DMG avec le `SHA256SUMS.txt` joint à chaque release (`shasum -a 256 Tsuba_*.dmg`), lisez [le workflow](.github/workflows/release.yml) qui l'a construit, ou compilez-le vous-même (voir Publier une version sous [Développement](#development)).
>
> Ne supprimez pas l'attribut de quarantaine avec `xattr` : Tsuba avertit contre les installeurs qui vous le demandent, et le sien ne doit pas faire exception.

## Ce qui est vérifié

| Point d'entrée | Exemples | Ce qui est vérifié |
| --- | --- | --- |
| Commandes du terminal | `curl … \| bash`, `npm install`, `npx`, `npm start`, `code .`, `git clone` | Télécharge le script distant (sans l'exécuter) et suit une éventuelle deuxième étape ; date de création du paquet npm, délai de carence et scripts d'installation ; code caché, C2 codé en dur et lecture de portefeuilles et de mots de passe enregistrés dans les sources du projet ; tâches VS Code qui s'exécutent automatiquement à l'ouverture du dossier |
| Collage dans le terminal | Une page web vous dit de « copier cette commande dans votre terminal » | Avertit dès que vous collez, sans connexion réseau ; les commandes obscurcies en base64 envoyées à un shell sont signalées tout de suite comme à haut risque |
| Dossier Téléchargements | Nouveaux fichiers `.dmg`, `.pkg`, `.vsix` | Les monte en lecture seule et vérifie la signature, la notarisation, la provenance du téléchargement, si l'exécutable principal a été remplacé par un fichier masqué, et les scripts d'installation |
| Extensions d'éditeur | Extensions nouvelles ou mises à jour dans VS Code, Cursor, Windsurf, VSCodium | Liste officielle des extensions malveillantes, activation au démarrage, code caché dans des caractères Unicode invisibles, accès réseau et fichiers suspects ; les extensions à haut risque sont mises en quarantaine automatiquement |
| Outils de code IA | Serveurs MCP, skills et hooks de plugin pour Claude Code, Cursor, Codex et d'autres ; `.mcp.json`, hooks et `CLAUDE.md` dans les projets | Si le paquet lancé figure sur une liste malveillante, s'il démarre depuis un répertoire temporaire ou masqué, quels secrets il reçoit ; si les skills et descriptions d'outils cachent des instructions destinées à l'IA (empoisonnement d'outil), lui demandent de cacher des choses à l'utilisateur, lisent des clés privées ou exfiltrent des données |
| Bilan de santé | Barre des menus → Bilan de santé | Traces laissées par des attaques connues, éléments d'ouverture suspects, analyse rapide des extensions installées |
| Analyser un dossier | La page Analyse, ou `tsuba scan <folder>` | Installeurs, scripts, extensions et projets avec points d'entrée à exécution automatique dans Téléchargements, les disques externes et les dossiers de code ; les fichiers inchangés déjà analysés sont ignorés, et par défaut Téléchargements est réanalysé avec les dernières règles tous les 7 jours |

Pour demander « pourquoi ceci a été bloqué ? » directement dans Claude Code : `claude mcp add tsuba -- tsuba mcp`. C'est un outil MCP en lecture seule : il peut seulement consulter l'historique des vérifications et la quarantaine, sans rien modifier. Les commandes et résumés qu'il renvoie sont marqués comme données non fiables, et les secrets sont toujours masqués.

Tout ce qui est confirmé comme faux positif peut être « marqué comme sûr » : son empreinte de contenu est alors enregistrée dans la liste d'autorisation, et s'il change, il est vérifié à nouveau. Fichiers, dossiers et extensions suspects peuvent être mis en quarantaine, puis restaurés ou supprimés à tout moment.

Les extensions installées depuis le Marketplace ne passent pas par le terminal : elles ne peuvent être vérifiées que juste après leur installation. Les programmes ouverts par double-clic dans le Finder ne peuvent pas encore être bloqués ; il faudrait pour cela l'entitlement Endpoint Security d'Apple (voir la section 12 du PRD).

## Jugement par IA

Les règles hors ligne passent toujours en premier, puis l'IA juge par-dessus en tenant compte du contexte. Vous pouvez choisir dans les Réglages :

- **Compte d'outil de code** (recommandé) : le Claude Code ou le Codex déjà connecté sur votre Mac. Des modèles de pointe, sans clé API à gérer.
- **Clé API** : Claude, OpenAI ou Gemini, des éditeurs de modèles comme DeepSeek, Qwen, Kimi et GLM, des plateformes comme OpenRouter et SiliconFlow, des modèles locaux via Ollama, LM Studio ou vLLM, ou tout endpoint compatible avec l'API OpenAI Chat Completions.
- **Règles hors ligne uniquement** : aucun accès réseau, aucun appel de modèle.

Les modèles se répartissent en deux niveaux de confiance. Les recherches publiques montrent que les modèles de pointe ont une nette avance pour reconnaître le code malveillant, tandis que les autres produisent plus de faux positifs et se laissent plus facilement duper par une injection de prompt dans le code :

| | Modèles de pointe (Claude, OpenAI / Codex, Gemini, ou un modèle marqué manuellement sur un endpoint personnalisé ou une plateforme) | Modèles locaux et autres |
| --- | --- | --- |
| Peut recommander seul le blocage | Oui | Non, Avertir au plus |
| Peut abaisser le risque trouvé par les règles hors ligne | Peut ramener Bloquer à Avertir, mais jamais Autoriser directement | Non |

Les commentaires du code sont retirés avant tout envoi au modèle (pour neutraliser les injections de prompt cachées dans les commentaires) ; quand les preuves sont trop longues, le début et la fin de chaque texte sont conservés, et les correspondances des règles hors ligne sont toujours gardées en entier. Le modèle ne reçoit que les preuves nécessaires à ce jugement ; aucun autre fichier, aucune variable d'environnement ni aucun secret n'est envoyé. La configuration et l'historique des vérifications se trouvent dans `~/.tsuba`.

<a id="threat-intel"></a>
## Renseignement sur les menaces

En plus des règles hors ligne, Tsuba met à jour son renseignement sur les menaces depuis des sources publiques une fois par jour et le stocke dans `~/.tsuba/intel` (vous pouvez aussi lancer `tsuba intel update` dans le terminal) :

| Source | Contenu | Licence |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | Environ 230 000 paquets npm / PyPI malveillants confirmés ; les dépendances transitives des lockfiles sont vérifiées aussi | Apache-2.0 |
| [OSV.dev](https://osv.dev) (en ligne, désactivable) | Comme ci-dessus, interrogé en direct pendant une vérification ; seuls le nom et la version du paquet sont envoyés | - |
| Liste officielle des extensions VS Code malveillantes | Extensions malveillantes retirées par Microsoft | - |
| Règles YARA [Elastic](https://github.com/elastic/protections-artifacts), [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | Signatures de familles de malwares connues | Elastic License 2.0 / MIT |
| Règles YARA [GuardDog](https://github.com/DataDog/guarddog) | Motifs de code suspects courants dans les paquets malveillants (simple preuve ; ne déclenche jamais Avertir à lui seul) | Apache-2.0 |
| Règles XProtect locales | Les signatures de malwares d'Apple, utilisées uniquement sur ce Mac | Apple |
| [VirusTotal](https://www.virustotal.com) (facultatif, votre propre clé) | Verdicts de plus de 70 moteurs antivirus sur les installeurs, programmes et scripts distants ; seuls des hachages sont envoyés, jamais les fichiers | L'API gratuite n'autorise pas l'usage commercial |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus (facultatif) | Domaines, IP et URL malveillants ; nécessite une Auth-Key gratuite, et l'offre gratuite est réservée à un usage non lucratif | - |

Les règles sont compilées et exécutées avec [YARA-X](https://github.com/VirusTotal/yara-x). Un pack de règles téléchargé depuis l'URL des packs de règles n'est utilisé que s'il porte une signature valide (`tsuba.sig`, ed25519) et que sa version n'est pas plus ancienne que celle en service ; signez-le pour publication avec `tsuba rules sign --key <private key file> <rules directory>`. Les règles de détection propres à Tsuba ne sont pas non plus écrites dans le code : elles se trouvent dans [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) et [tsuba.toml](crates/engine/rules/tsuba.toml) et peuvent être mises à jour séparément.

Pour les règles de développement, voir [CLAUDE.md](CLAUDE.md).

## Dans le terminal

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

Les commandes annulées restent dans l'historique de votre shell ; une fois vérifiées, appuyez sur la flèche du haut pour les retrouver.

Chaque commande `tsuba` accepte `--lang <code>` (`en`, `zh-Hans`, `zh-Hant`, `ja`, `ko`, `es`, `fr`, `de`, `pt-BR`, `ru`) ; sans cette option, le terminal utilise la langue choisie dans l'app.

### Essai en bac à sable (prototype)

Pour un script dont vous n'êtes pas sûr, vous pouvez le faire tourner brièvement dans un bac à sable et voir ce qu'il fait réellement, au lieu de lire le code ligne par ligne :

```bash
tsuba sandbox install.sh
```

Le bac à sable s'appuie directement sur celui intégré à macOS : le vrai dossier personnel est verrouillé et le programme ne voit qu'un faux dossier personnel garni de leurres ; chaque requête réseau est enregistrée par un proxy local et jamais réellement envoyée ; l'exécution dure 60 secondes au plus. La lecture de secrets leurres suivie de leur envoi, l'écriture d'éléments d'ouverture et les connexions à des IP nues sont toutes enregistrées. Attention : ne rien voir de malveillant pendant une courte exécution ne garantit pas que c'est sûr.

Vous pouvez aussi essayer un dossier de projet dans le bac à sable (`tsuba sandbox ~/code/interview-project`) : Tsuba lance sa commande de démarrage et observe son comportement ; le code malveillant des projets d'entretien qui « s'exécute dès l'ouverture » se révèle ici. Ajoutez `--install` pour essayer l'installation des dépendances (`npm install`) dans le bac à sable et voir ce que font leurs scripts d'installation ; dans ce mode, seuls les téléchargements depuis le registre npm officiel passent, et toute autre connexion est seulement enregistrée. Le bac à sable en machine virtuelle pour les DMG / apps n'existe pas encore.

<a id="development"></a>
## Développement

<details>
<summary><b>Structure des dossiers</b></summary>

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

Nécessite Rust (`rustup`), Node.js et pnpm.

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

Le dossier d'échantillons contient deux sous-dossiers, `malicious/` et `benign/` ; chaque fichier ou sous-dossier compte comme un échantillon (projets, extensions, installeurs et scripts fonctionnent tous, les liens symboliques aussi). Seules les règles hors ligne sont utilisées, les résultats sont donc reproductibles ; si les objectifs ne sont pas atteints, le code de sortie est 1, ce qui permet de l'intégrer à la CI. Pour un découpage dans le temps, placez les échantillons anciens et récents dans deux dossiers et lancez-les séparément.

En développement, l'app cherche le vérificateur du terminal à côté d'elle (`target/debug/tsuba`) ; configurez-le en un clic dans Réglages → Protection → Connecter à zsh, et il prend effet dans les nouvelles fenêtres de terminal.

Les échantillons de test sont tous inertes : ils imitent seulement la forme du code d'attaque, leurs IP appartiennent aux plages de documentation, et le contenu décodé est lui aussi inoffensif.

Le code contient le texte anglais ; les traductions se trouvent dans un catalogue par langue (`locales/<code>.json` dans `app/src`, `app/src-tauri`, `crates/engine` et `crates/cli`), et chaque règle du pack de règles porte son propre `message_<lang>`. Les tests des catalogues et `pnpm check:i18n` échouent si une chaîne manque dans une langue ou si une traduction perd un `{placeholder}`.

L'icône de l'app, l'ordinateur portable du tableau de bord et la garde sont des rendus Blender : `app/src-tauri/icons/source/` contient les scripts et les étapes pour les régénérer.

<details>
<summary><b>Publier une version</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

Un bundle de release embarque le vérificateur du terminal sous `Tsuba.app/Contents/MacOS/tsuba`. `tauri.release.conf.json` l'ajoute et lance `app/scripts/build-cli-sidecar.sh` ; il reste hors de `tauri.conf.json` parce que Tauri refuse de compiler sans ce fichier, ce qui casserait `cargo test`.

Pour publier, lancez `scripts/release.sh X.Y.Z` sur une branche `main` propre : il fixe la version dans le `Cargo.toml` racine (la source unique pour l'app, la CLI et le DMG), lance les vérifications d'avant commit, commite, crée le tag `vX.Y.Z` et demande confirmation avant de pousser. Le tag déclenche `.github/workflows/release.yml`, qui lance les tests et construit en parallèle les DMG Apple silicon et Intel sur trois runners, puis les joint avec `SHA256SUMS.txt` à un brouillon de GitHub Release dont les notes sont générées à partir des commits, et le publie une fois tous les jobs réussis (ce qui reconstruit aussi le site). Si un job échoue, le brouillon est supprimé et le tag reste. Lancer le workflow à la main (Actions → Release → Run workflow, ou `gh workflow run release.yml`) fait un essai à blanc qui conserve les DMG comme artefacts du workflow.

Les mises à jour dans l'app proviennent des mêmes releases : Réglages → À propos et mises à jour consulte le `latest.json` de la dernière release publiée (Tsuba vérifie aussi discrètement au lancement), télécharge le paquet adapté à ce Mac et ne l'installe que si sa signature correspond à la clé publique de `tauri.conf.json`. La CI produit les paquets signés et `latest.json` lorsque le secret de dépôt `TAURI_SIGNING_PRIVATE_KEY` contient la clé privée du système de mise à jour (générée avec `pnpm tauri signer generate`, sans mot de passe). Gardez une sauvegarde de cette clé : sans elle, les copies installées ne pourront plus jamais être mises à jour.

La signature et la notarisation se font quand ces secrets de dépôt sont définis : `APPLE_CERTIFICATE` (.p12 en base64), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` (mot de passe pour app) et `APPLE_TEAM_ID`. Sans eux, le DMG n'est pas signé et Gatekeeper le bloque après téléchargement.

</details>

## Licence

Tsuba est distribué sous la [licence Apache 2.0](LICENSE). Le renseignement sur les menaces téléchargé à l'exécution conserve sa propre licence, indiquée dans [Renseignement sur les menaces](#threat-intel) et affichée à côté de chaque résultat qui l'utilise.
