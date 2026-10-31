<p align="center">
  <img src="app/src-tauri/icons/128x128@2x.png" width="104" alt="Tsuba" />
</p>

<h1 align="center">Tsuba</h1>

<p align="center">
  <b>Revisa por ti el código desconocido antes de que se ejecute por primera vez.</b><br/>
  Una app de la barra de menús de macOS que detecta proyectos de entrevista falsos, apps de reuniones falsas, paquetes envenenados y servidores MCP maliciosos antes de que se ejecuten.
</p>

<p align="center">
  <a href="https://oliverz.dev/products/tsuba">Sitio web</a> ·
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest">Descargar</a> ·
  <a href="#install">Instalar</a> ·
  <a href="#development">Compilar desde el código</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hans.md">简体中文</a> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <b>Español</b> · <a href="README.fr.md">Français</a> · <a href="README.de.md">Deutsch</a> · <a href="README.pt-BR.md">Português</a> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/chihyungchang/Tsuba/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/chihyungchang/Tsuba?style=flat&color=b4873a" /></a>
  <a href="https://github.com/chihyungchang/Tsuba/releases"><img alt="Descargas" src="https://img.shields.io/github/downloads/chihyungchang/Tsuba/total?style=flat&color=1f8a50" /></a>
  <img alt="macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-1f1c17?style=flat&logo=apple" />
  <a href="LICENSE"><img alt="Licencia: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat" /></a>
  <a href="https://m8ven.ai/mcp/chihyungchang-tsuba-hmqqrw?s=readme"><img alt="M8ven Verified" src="https://m8ven.ai/badge/mcp/chihyungchang-tsuba-hmqqrw?variant=verified&v=786841f2c90c79c8b3d1e9bf30ae8ba8" /></a>
</p>

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png" />
  <img src="docs/screenshots/overview-light.png" alt="Panel de Tsuba: estado de la protección, lo que requiere atención y las comprobaciones recientes" width="100%" />
</picture>
</p>

---

## Qué es Tsuba

Tsuba (鍔, la guarda de una espada japonesa) vigila el momento en que un código desconocido se ejecuta por primera vez. Los proyectos de entrevista falsos, el software de reuniones falso, los paquetes npm envenenados y las extensiones de editor maliciosas llegan cada vez con un envoltorio nuevo y usan herramientas corrientes como node, curl y bash, así que los antivirus tradicionales rara vez los detectan.

Tsuba interviene en los puntos de entrada donde se ejecutan por primera vez: averigua **qué está a punto de hacer el código, de dónde viene y si se parece a un ataque conocido**, decide entre **Permitir, Advertir o Bloquear**, y muestra el archivo, la línea y la regla que hay detrás de cada veredicto.

## Por qué Tsuba

- 🛡️ **Antes de que se ejecute, no después.** `curl | bash`, `npm install`, `git clone`, un DMG nuevo en Descargas, una extensión o un servidor MCP recién instalados: cada uno se comprueba justo cuando se ejecutaría por primera vez.
- 🧠 **Primero reglas sin conexión, después AI con contexto.** Las reglas locales y la inteligencia de amenazas siempre se ejecutan. Después, un modelo de frontera lee la evidencia para reducir las falsas alarmas y detectar lo que ninguna regla ha visto aún, y nunca puede permitir lo que las reglas consideraron de alto riesgo.
- 🔑 **Sin cuentas nuevas.** Usa el Claude Code o Codex con el que ya has iniciado sesión en tu Mac, cualquiera de una veintena de proveedores con tu propia clave, o ningún modelo.
- 🔒 **Solo lectura por diseño.** El código que se comprueba se analiza, nunca se ejecuta: las imágenes de disco se montan en solo lectura, los scripts remotos se descargan pero no se ejecutan, y el script que se ejecuta es el mismo que Tsuba comprobó.
- 🤫 **Silencioso hasta que importa.** Las advertencias van al historial sin hacer ruido; solo Bloquear notifica con un tono breve. Todo lo que confirmes como falsa alarma se puede ignorar o marcar como seguro.
- 🔄 **Se actualiza solo, de forma segura.** Las versiones nuevas se instalan desde GitHub Releases solo si su firma coincide con la clave de Tsuba.
- 🌏 **Habla tu idioma.** La app, las notificaciones, las comprobaciones de terminal, las explicaciones de las reglas y las respuestas de la AI están en English, 简体中文, 繁體中文, 日本語, 한국어, Español, Français, Deutsch, Português y Русский. Sigue el idioma de macOS, o elige uno en Ajustes → Apariencia.

## Recorrido por el producto

<table>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/history-dark.png" />
  <img src="docs/screenshots/history-light.png" alt="Historial de comprobaciones: cada veredicto con el archivo, la línea y la regla que lo respaldan" />
</picture>
      <br/><sub><b>Historial de comprobaciones</b>: cada Advertir y Bloquear con el archivo, la línea y la regla que coincidió; ignóralo, ponlo en cuarentena o márcalo como seguro</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/health-check-dark.png" />
  <img src="docs/screenshots/health-check-light.png" alt="Chequeo de salud: un botón y una lista que se va completando" />
</picture>
      <br/><sub><b>Chequeo de salud</b>: con un clic busca rastros de ataques conocidos y luego comprueba cada extensión de editor y herramienta de AI</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/judgment-dark.png" />
  <img src="docs/screenshots/judgment-light.png" alt="Elegir cómo se emiten los veredictos" />
</picture>
      <br/><sub><b>Juicio</b>: el Claude Code o Codex con el que ya has iniciado sesión, una clave de API de una veintena de proveedores, o solo reglas sin conexión</sub>
    </td>
    <td width="50%" valign="top">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/threat-intel-dark.png" />
  <img src="docs/screenshots/threat-intel-light.png" alt="Fuentes de inteligencia de amenazas y sus licencias" />
</picture>
      <br/><sub><b>Inteligencia de amenazas</b>: listas y firmas públicas, descargadas a diario y comprobadas localmente, cada una con su procedencia</sub>
    </td>
  </tr>
</table>

<a id="install"></a>
## Instalación

Descarga el DMG desde [Releases](https://github.com/chihyungchang/Tsuba/releases) (macOS 13 o posterior): `Tsuba_*_aarch64.dmg` para Mac con Apple silicon (M1 y posteriores), `Tsuba_*_x64.dmg` para Mac con Intel. No necesita cuenta; para la revisión con AI puede usar el Claude Code o Codex con el que ya has iniciado sesión en tu Mac. A partir de la 0.2.0, las versiones nuevas se instalan desde la propia app (Ajustes → Acerca de y actualizaciones, o Buscar actualizaciones… en la barra de menús).

> [!WARNING]
> **Las compilaciones aún no están firmadas ni notarizadas por Apple.** macOS bloquea la App la primera vez que la abres: ve a **Ajustes del Sistema → Privacidad y seguridad** y haz clic en **Abrir igualmente**.
>
> Tsuba es de código abierto, así que puedes comprobar lo que ejecutas: compara el DMG con el `SHA256SUMS.txt` adjunto a cada release (`shasum -a 256 Tsuba_*.dmg`), lee [el workflow](.github/workflows/release.yml) que lo compiló, o compílalo tú mismo (consulta Publicar una versión en [Desarrollo](#development)).
>
> Por favor, no quites la marca de cuarentena con `xattr`: Tsuba advierte de los instaladores que te piden hacerlo, y el suyo no debería ser la excepción.

## Qué comprueba

| Punto de entrada | Ejemplos | Qué se comprueba |
| --- | --- | --- |
| Comandos de terminal | `curl … \| bash`, `npm install`, `npx`, `npm start`, `code .`, `git clone` | Descarga el script remoto (sin ejecutarlo) y sigue cualquier segunda fase; la fecha de creación del paquete npm, el periodo de espera tras su publicación y los scripts de instalación; código oculto, C2 fijados en el código y lecturas de monederos y almacenes de contraseñas en el código fuente del proyecto; tareas de VS Code que se ejecutan automáticamente al abrir la carpeta |
| Pegar en el terminal | Una página web te dice que "copies este comando en tu terminal" | Advierte una vez en el momento de pegar, sin conectarse a internet; los comandos ofuscados con base64 que se pasan a un shell se marcan como de alto riesgo al instante |
| Carpeta Descargas | Archivos `.dmg`, `.pkg`, `.vsix` nuevos | Los monta en solo lectura y comprueba la firma, la notarización, el origen de la descarga, si el ejecutable principal se ha sustituido por un archivo oculto, y los scripts de instalación |
| Extensiones de editor | Extensiones recién instaladas o actualizadas en VS Code, Cursor, Windsurf, VSCodium | La lista oficial de extensiones maliciosas, la activación al arrancar, código oculto en caracteres Unicode invisibles, accesos sospechosos a la red y a archivos; las extensiones de alto riesgo se mueven a cuarentena automáticamente |
| Herramientas de programación con AI | Servidores MCP, skills y hooks de plugin de Claude Code, Cursor, Codex y otros; `.mcp.json`, hooks y `CLAUDE.md` en los proyectos | Si el paquete que se lanza está en una lista de maliciosos, si arranca desde un directorio temporal u oculto, qué secretos recibe; si las skills y las descripciones de herramientas esconden instrucciones dirigidas a la AI (envenenamiento de herramientas), le piden ocultar cosas al usuario, leen claves privadas o exfiltran datos |
| Chequeo de salud | Barra de menús → Chequeo de salud | Rastros que dejan ataques conocidos, ítems de inicio sospechosos, un escaneo rápido de las extensiones instaladas |
| Escanear una carpeta | La página Escanear, o `tsuba scan <folder>` | Instaladores, scripts, extensiones y proyectos con puntos de entrada que se ejecutan solos en la carpeta Descargas, discos externos y directorios de código; se omiten los archivos ya escaneados que no han cambiado y, por defecto, la carpeta Descargas se vuelve a escanear con las últimas reglas cada 7 días |

Para preguntar "¿por qué se bloqueó esto?" dentro de Claude Code: `claude mcp add tsuba -- tsuba mcp`. Es una herramienta MCP de solo lectura: solo puede consultar el historial de comprobaciones y la cuarentena, y no puede cambiar nada. Los comandos y resúmenes que devuelve se marcan como datos no fiables, y los secretos siempre se ocultan.

Todo lo que confirmes como falso positivo se puede "marcar como seguro", lo que guarda la huella de su contenido en la lista de permitidos; si el contenido cambia, se vuelve a comprobar. Los archivos, directorios y extensiones sospechosos se pueden mover a cuarentena y restaurar o eliminar cuando quieras.

Las extensiones instaladas desde el marketplace de extensiones no pasan por el terminal, así que solo se pueden comprobar justo después de instalarse. Los programas que se abren con doble clic en Finder aún no se pueden bloquear; para eso hace falta el entitlement Endpoint Security de Apple (consulta la sección 12 del PRD).

## Juicio con AI

Las reglas sin conexión siempre se ejecutan primero, y después la AI emite su juicio sobre ellas teniendo en cuenta el contexto. Puedes elegir en Ajustes:

- **Cuenta de herramienta de programación** (recomendado): el Claude Code o Codex con el que ya has iniciado sesión en tu Mac. Modelos de frontera, sin claves de API que gestionar.
- **Clave de API**: Claude, OpenAI o Gemini; proveedores de modelos como DeepSeek, Qwen, Kimi y GLM; plataformas como OpenRouter y SiliconFlow; modelos locales con Ollama, LM Studio o vLLM; o cualquier endpoint compatible con la API OpenAI Chat Completions.
- **Solo reglas sin conexión**: sin acceso a la red ni llamadas a modelos.

Los modelos se dividen en dos niveles de confianza. La investigación pública muestra que los modelos de frontera van claramente por delante al reconocer código malicioso, mientras que los que no son de frontera dan más falsos positivos y se dejan engañar con más facilidad por la inyección de prompts en el código:

| | Modelos de frontera (Claude, OpenAI / Codex, Gemini, o un modelo marcado a mano en un endpoint o plataforma personalizados) | Modelos locales y otros |
| --- | --- | --- |
| Pueden recomendar Bloquear por su cuenta | Sí | No, como mucho Advertir |
| Pueden rebajar el riesgo que hallaron las reglas sin conexión | Pueden rebajar Bloquear a Advertir, pero no Permitir directamente | No |

Los comentarios del código se eliminan antes de que nada llegue al modelo (para neutralizar la inyección de prompts escondida en comentarios); si la evidencia es demasiado larga, se conservan el principio y el final de cada texto, y las coincidencias de las reglas sin conexión siempre se mantienen completas. El modelo solo recibe la evidencia que necesita para este juicio; no se sube ningún otro archivo, variable de entorno ni secreto. La configuración y el historial de comprobaciones se guardan en `~/.tsuba`.

<a id="threat-intel"></a>
## Inteligencia de amenazas

Además de las reglas sin conexión, Tsuba actualiza su inteligencia de amenazas desde fuentes públicas una vez al día y la guarda en `~/.tsuba/intel` (también puedes ejecutar `tsuba intel update` en el terminal):

| Fuente | Contenido | Licencia |
| --- | --- | --- |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | Unos 230.000 paquetes npm / PyPI maliciosos confirmados; también se comprueban las dependencias transitivas de los lockfiles | Apache-2.0 |
| [OSV.dev](https://osv.dev) (en línea, se puede desactivar) | Lo mismo que arriba, consultado en directo durante la comprobación; solo se envían el nombre y la versión del paquete | - |
| Lista oficial de extensiones maliciosas de VS Code | Extensiones maliciosas retiradas por Microsoft | - |
| Reglas YARA de [Elastic](https://github.com/elastic/protections-artifacts) y [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | Firmas de familias de malware conocidas | Elastic License 2.0 / MIT |
| Reglas YARA de [GuardDog](https://github.com/DataDog/guarddog) | Patrones de código sospechosos habituales en paquetes maliciosos (solo como evidencia; nunca provocan un Advertir por sí solos) | Apache-2.0 |
| Reglas locales de XProtect | Las firmas de malware propias de Apple, usadas solo en este Mac | Apple |
| [VirusTotal](https://www.virustotal.com) (opcional, con tu propia clave) | Veredictos de más de 70 motores antivirus sobre instaladores, programas y scripts remotos; solo se envían hashes, los archivos nunca se suben | La API gratuita no permite uso comercial |
| [abuse.ch](https://abuse.ch) ThreatFox / URLhaus (opcional) | Dominios, IP y URL maliciosos; requiere una Auth-Key gratuita, y el plan gratuito es solo para uso sin ánimo de lucro | - |

Las reglas se compilan y ejecutan con [YARA-X](https://github.com/VirusTotal/yara-x). Un paquete de reglas descargado desde la URL del paquete de reglas solo se usa si lleva una firma válida (`tsuba.sig`, ed25519) y su versión no es anterior a la que está en uso; para publicarlo, fírmalo con `tsuba rules sign --key <private key file> <rules directory>`. Las reglas de detección propias de Tsuba tampoco están escritas en código: viven en [crates/engine/rules/tsuba.yar](crates/engine/rules/tsuba.yar) y [tsuba.toml](crates/engine/rules/tsuba.toml) y se pueden actualizar por separado.

Para las pautas de desarrollo, consulta [CLAUDE.md](CLAUDE.md).

## En el terminal

```bash
tskip npm install          # skip the check this one time
export TSUBA_DISABLE=1     # turn it off for the current terminal window
```

Los comandos cancelados se quedan en el historial de tu shell; cuando los hayas verificado, pulsa la flecha arriba para recuperarlos.

Todos los comandos `tsuba` aceptan `--lang <code>` (`en`, `zh-Hans`, `zh-Hant`, `ja`, `ko`, `es`, `fr`, `de`, `pt-BR`, `ru`); sin él, el terminal usa el idioma elegido en la app.

### Ejecución de prueba en sandbox (prototipo)

Si no te fías de un script, puedes ejecutarlo un momento en un sandbox y ver qué hace en realidad, en lugar de leer el código línea a línea:

```bash
tsuba sandbox install.sh
```

El sandbox funciona directamente sobre el sandbox integrado de macOS: la carpeta de inicio real queda bloqueada y el programa solo ve una carpeta de inicio falsa con señuelos; cada solicitud de red la registra un proxy local y nunca llega a enviarse; se ejecuta durante 60 segundos como máximo. Leer secretos señuelo y enviarlos, escribir ítems de inicio y conectarse a IP sin dominio quedan registrados. Ojo: no ver ningún comportamiento malo durante una ejecución corta no garantiza que sea seguro.

También puedes probar un directorio de proyecto en el sandbox (`tsuba sandbox ~/code/interview-project`), que ejecuta su comando de inicio y observa su comportamiento; aquí queda al descubierto el código malicioso de los proyectos de entrevista que "se ejecuta nada más abrirlo". Añade `--install` para probar a instalar las dependencias (`npm install`) en el sandbox y ver qué hacen sus scripts de instalación; en ese modo solo se dejan pasar las descargas del registro oficial de npm, y cualquier otra conexión solo se registra. El sandbox de máquina virtual para DMG / Apps aún no está hecho.

<a id="development"></a>
## Desarrollo

<details>
<summary><b>Estructura de directorios</b></summary>

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

Necesitas Rust (`rustup`), Node.js y pnpm.

```bash
pnpm app                                     # start the app (installs front-end dependencies first)
cargo test                                   # run the engine tests
cargo run -p tsuba-cli -- scan <path>        # check a file or directory directly, without the app
cargo run -p tsuba-cli -- eval <samples dir> # sample set acceptance: detection and false positive rates against the targets in PRD section 4
```

El directorio de muestras contiene dos subdirectorios, `malicious/` y `benign/`; cada archivo o subdirectorio cuenta como una muestra (sirven proyectos, extensiones, instaladores y scripts, y también enlaces simbólicos). Solo se usan las reglas sin conexión, así que los resultados son reproducibles; si no se alcanzan los objetivos, el código de salida es 1, de modo que puede ir en CI. Para una división temporal, pon las muestras antiguas y las nuevas en dos directorios y ejecútalos por separado.

Durante el desarrollo, la App busca el comprobador de terminal junto a sí misma (`target/debug/tsuba`); configúralo con un clic en Ajustes → Protección → Conectar a zsh, y se aplica en las ventanas de terminal que abras a partir de entonces.

Todas las muestras de prueba son inertes: solo imitan la forma del código de ataque, sus IP pertenecen a rangos de documentación y el contenido decodificado también es inofensivo.

El código contiene el texto en inglés; las traducciones viven en un catálogo por idioma (`locales/<code>.json` en `app/src`, `app/src-tauri`, `crates/engine` y `crates/cli`), y cada regla del paquete de reglas lleva su propio `message_<lang>`. Los tests de catálogo y `pnpm check:i18n` fallan si falta un texto en algún idioma o si una traducción pierde un `{placeholder}`.

El icono de la app, el portátil del panel y la guarda son renders de Blender: `app/src-tauri/icons/source/` contiene los scripts y los pasos para regenerarlos.

<details>
<summary><b>Publicar una versión</b></summary>

```bash
cd app && pnpm release --bundles app   # local release build for this Mac, terminal checker included
```

Un paquete de release lleva el comprobador de terminal como `Tsuba.app/Contents/MacOS/tsuba`. `tauri.release.conf.json` lo añade y ejecuta `app/scripts/build-cli-sidecar.sh`; no está en `tauri.conf.json` porque Tauri se niega a compilar sin el archivo, y eso rompería `cargo test`.

Para publicar, ejecuta `scripts/release.sh X.Y.Z` sobre un `main` limpio: fija la versión en el `Cargo.toml` raíz (la única fuente para la App, la CLI y el DMG), ejecuta las comprobaciones previas al commit, hace el commit, crea la etiqueta `vX.Y.Z` y pregunta antes de hacer push. La etiqueta lanza `.github/workflows/release.yml`, que ejecuta los tests y compila los DMG para Apple silicon e Intel en tres runners a la vez, y los adjunta junto con `SHA256SUMS.txt` a un borrador de GitHub Release con notas generadas a partir de los commits, y lo publica cuando todos los jobs pasan (lo que también reconstruye la web). Si algún job falla, el borrador se elimina y la etiqueta se mantiene. Ejecutar el workflow a mano (Actions → Release → Run workflow, o `gh workflow run release.yml`) es una prueba en seco que guarda los DMG como artefactos del workflow.

Las actualizaciones dentro de la app vienen de esas mismas releases: Ajustes → Acerca de y actualizaciones consulta el `latest.json` de la última release publicada (Tsuba también lo comprueba discretamente al arrancar), descarga el paquete para este Mac y solo lo instala si su firma coincide con la clave pública de `tauri.conf.json`. La CI genera los paquetes firmados y `latest.json` cuando el secreto del repositorio `TAURI_SIGNING_PRIVATE_KEY` contiene la clave privada del actualizador (generada con `pnpm tauri signer generate`, sin contraseña). Guarda una copia de seguridad de esa clave: sin ella, las copias instaladas no podrán volver a actualizarse nunca.

Firma y notariza cuando están configurados estos secretos del repositorio: `APPLE_CERTIFICATE` (.p12 en base64), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` (contraseña específica de app) y `APPLE_TEAM_ID`. Sin ellos, el DMG no va firmado y Gatekeeper lo bloquea al descargarlo.

</details>

## Licencia

Tsuba se distribuye bajo la [Apache License 2.0](LICENSE). La inteligencia de amenazas que descarga en tiempo de ejecución conserva su propia licencia, indicada en [Inteligencia de amenazas](#threat-intel) y mostrada junto a cada hallazgo que la usa.
