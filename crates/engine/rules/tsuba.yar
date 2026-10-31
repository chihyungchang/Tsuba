/*
  Tsuba's own detection rules.

  Drawn from what real attack samples have in common: Contagious Interview / BeaverTail / OtterCookie / InvisibleFerret,
  the fake meeting app Zeff, ClickFix, malicious npm packages, malicious editor extensions and AI tool skills.
  A match does not mean malicious: it is evidence for the model, or is scored when offline.

  meta fields:
    severity     high / medium / low. low is evidence only and does not affect the verdict
    message      explanation shown to the user, in English
    message_zh, message_zh_hant, message_ja, message_ko, message_es, message_fr, message_de, message_pt_br, message_ru
                 the same explanation in each supported language. The pack carries its own translations because it
                 updates without a release, so the app's catalogs can't know about new rules
    skip_quoted  matches wrapped in quotes don't count (documentation quoting attack wording, not giving a command)
    doc_keep     don't downgrade in documentation (install steps are normal in docs, but these kinds are just as suspicious there)
    skip_well_known  don't count when every URL in the matched span is an official install source (well_known_hosts in tsuba.toml)

  After changing rules, run the fixture and false-positive tests in crates/engine/tests, then scan real extensions and skills with `tsuba scan`.
*/

rule tsuba_eval_decoded
{
  meta:
    severity = "high"
    message = "Decodes and then dynamically runs code (eval/Function + base64), common in obfuscated poisoned code"
    message_zh = "解码后动态执行代码（eval/Function + base64），常见于混淆的投毒代码"
    message_zh_hant = "解碼後動態執行程式碼（eval/Function + base64），常見於混淆過的投毒程式碼"
    message_ja = "コードをデコードしてから動的に実行します（eval/Function + base64）。難読化された汚染コードによく見られます"
    message_ko = "코드를 디코딩한 뒤 동적으로 실행합니다(eval/Function + base64). 난독화된 악성 코드에서 흔한 패턴입니다"
    message_es = "Decodifica y luego ejecuta código dinámicamente (eval/Function + base64), algo habitual en código envenenado ofuscado"
    message_fr = "Décode puis exécute dynamiquement du code (eval/Function + base64), courant dans le code piégé obscurci"
    message_de = "Dekodiert Code und führt ihn dynamisch aus (eval/Function + base64), typisch für verschleierten, manipulierten Code"
    message_pt_br = "Decodifica e depois executa código dinamicamente (eval/Function + base64), comum em código envenenado ofuscado"
    message_ru = "Декодирует и затем динамически выполняет код (eval/Function + base64), что типично для обфусцированного вредоносного кода"
  strings:
    $a = /(eval|Function)\s*\([^)]{0,200}(atob|base64|fromCharCode|Buffer\.from)/
  condition:
    $a
}

rule tsuba_browser_wallet_data
{
  meta:
    severity = "high"
    message = "Reads browser password stores or crypto wallet data"
    message_zh = "读取浏览器密码库或加密钱包数据"
    message_zh_hant = "讀取瀏覽器密碼庫或加密貨幣錢包資料"
    message_ja = "ブラウザのパスワードストアや暗号資産ウォレットのデータを読み取ります"
    message_ko = "브라우저 암호 저장소나 암호화폐 지갑 데이터를 읽습니다"
    message_es = "Lee almacenes de contraseñas del navegador o datos de monederos de criptomonedas"
    message_fr = "Lit les mots de passe enregistrés du navigateur ou les données de portefeuilles crypto"
    message_de = "Liest Passwortspeicher von Browsern oder Daten von Krypto-Wallets"
    message_pt_br = "Lê cofres de senhas do navegador ou dados de carteiras de criptomoedas"
    message_ru = "Читает хранилища паролей браузера или данные криптокошельков"
  strings:
    // Only these file names under a browser folder; "local state" in ordinary English doesn't count
    $browser = /(Chrome|Chromium|Brave-Browser|Microsoft Edge|Opera|Vivaldi|Arc\/User Data)[^"'`\n]{0,60}\/(Login Data|Local State|Web Data|Cookies)\b/
    // Extension IDs of MetaMask, Phantom and Coinbase Wallet
    $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"
    $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    $w3 = "hnfanknocfeofbddgcijnmhnfnkdnaad"
    $w4 = "ejbalbakoplchlghecdalmeeeajnimhm"
    $solana = ".config/solana"
    $exodus = "Exodus/exodus.wallet"
    $keychain = "Library/Keychains/"
  condition:
    any of them
}

rule tsuba_quarantine_removal
{
  meta:
    severity = "high"
    message = "Removes the macOS quarantine flag (bypassing Gatekeeper's security check)"
    message_zh = "删除 macOS 隔离标记（绕过 Gatekeeper 安全检查）"
    message_zh_hant = "移除 macOS 隔離標記（繞過 Gatekeeper 安全檢查）"
    message_ja = "macOS の検疫フラグを削除します（Gatekeeper のセキュリティチェックを回避）"
    message_ko = "macOS 격리 플래그를 제거합니다(Gatekeeper 보안 검사 우회)"
    message_es = "Elimina la marca de cuarentena de macOS (saltándose la comprobación de seguridad de Gatekeeper)"
    message_fr = "Supprime l'attribut de quarantaine de macOS (contourne le contrôle de sécurité de Gatekeeper)"
    message_de = "Entfernt das macOS-Quarantäne-Flag (umgeht die Sicherheitsprüfung von Gatekeeper)"
    message_pt_br = "Remove o atributo de quarentena do macOS (contornando a verificação de segurança do Gatekeeper)"
    message_ru = "Снимает карантинный флаг macOS (в обход проверки безопасности Gatekeeper)"
  strings:
    $a = /xattr\s+(-\w*[dc]\w*\s+)+/
    $b = /removexattr.{0,40}quarantine/
  condition:
    any of them
}

rule tsuba_hidden_home_dir
{
  meta:
    severity = "high"
    message = "Installs Node dependencies or runs scripts in a hidden folder in your home directory (attackers often hide in ~/.node_modules, ~/.task and the like)"
    message_zh = "在用户目录的隐藏文件夹里安装 Node 依赖或运行脚本（攻击者常用 ~/.node_modules、~/.task 等藏身）"
    message_zh_hant = "在使用者目錄的隱藏資料夾裡安裝 Node 相依套件或執行腳本（攻擊者常藏身在 ~/.node_modules、~/.task 等位置）"
    message_ja = "ホームディレクトリの隠しフォルダで Node の依存関係をインストールしたりスクリプトを実行したりします（攻撃者は ~/.node_modules や ~/.task などによく隠れます）"
    message_ko = "홈 디렉터리의 숨겨진 폴더에서 Node 의존성을 설치하거나 스크립트를 실행합니다(공격자는 ~/.node_modules, ~/.task 같은 곳에 자주 숨습니다)"
    message_es = "Instala dependencias de Node o ejecuta scripts en una carpeta oculta de tu carpeta de inicio (los atacantes suelen esconderse en ~/.node_modules, ~/.task y similares)"
    message_fr = "Installe des dépendances Node ou exécute des scripts dans un dossier masqué de votre dossier personnel (les attaquants se cachent souvent dans ~/.node_modules, ~/.task et similaires)"
    message_de = "Installiert Node-Abhängigkeiten oder führt Skripte in einem versteckten Ordner in deinem Benutzerordner aus (Angreifer verstecken sich oft in ~/.node_modules, ~/.task und Ähnlichem)"
    message_pt_br = "Instala dependências Node ou executa scripts em uma pasta oculta da sua pasta pessoal (atacantes costumam se esconder em ~/.node_modules, ~/.task e similares)"
    message_ru = "Устанавливает зависимости Node или запускает скрипты в скрытой папке вашего домашнего каталога (злоумышленники часто прячутся в ~/.node_modules, ~/.task и подобных)"
  strings:
    $a = /(homedir\(\)|~|\$HOME)["'`,\s+]*\/?\.(node_modules|task|n2|npl|vscode-server|sysinfo)\b/
  condition:
    $a
}

rule tsuba_multistage_download
{
  meta:
    severity = "medium"
    message = "The script downloads and runs another script (multi-stage delivery)"
    message_zh = "脚本里又下载并执行了别的脚本（多阶段投递）"
    message_zh_hant = "腳本裡又下載並執行了其他腳本（多階段投遞）"
    message_ja = "スクリプトが別のスクリプトをダウンロードして実行します（多段階の配布）"
    message_ko = "스크립트가 또 다른 스크립트를 다운로드해 실행합니다(다단계 전달)"
    message_es = "El script descarga y ejecuta otro script (entrega en varias fases)"
    message_fr = "Le script télécharge et exécute un autre script (livraison en plusieurs étapes)"
    message_de = "Das Skript lädt ein weiteres Skript herunter und führt es aus (mehrstufige Auslieferung)"
    message_pt_br = "O script baixa e executa outro script (entrega em várias etapas)"
    message_ru = "Скрипт загружает и запускает другой скрипт (многоступенчатая доставка)"
    skip_well_known = true
  strings:
    $pipe = /(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/
    $save = /(curl|wget)\b[^\n]*-o\s*\S+\s*(&&|;)\s*(chmod|bash|sh|\.\/)/
  condition:
    any of them
}

rule tsuba_standalone_node
{
  meta:
    severity = "medium"
    message = "Downloads a standalone Node.js runtime (to run malicious JS independently of the system)"
    message_zh = "下载独立的 Node.js 运行时（为了脱离系统环境运行恶意 JS）"
    message_zh_hant = "下載獨立的 Node.js 執行環境（為了脫離系統環境執行惡意 JS）"
    message_ja = "独立した Node.js ランタイムをダウンロードします（システムに依存せず悪意ある JS を実行するため）"
    message_ko = "독립 실행형 Node.js 런타임을 다운로드합니다(시스템과 별개로 악성 JS를 실행하기 위해)"
    message_es = "Descarga un entorno de ejecución de Node.js independiente (para ejecutar JS malicioso sin depender del sistema)"
    message_fr = "Télécharge un environnement Node.js autonome (pour exécuter du JS malveillant indépendamment du système)"
    message_de = "Lädt eine eigenständige Node.js-Laufzeit herunter (um bösartiges JS unabhängig vom System auszuführen)"
    message_pt_br = "Baixa um runtime Node.js independente (para executar JS malicioso sem depender do sistema)"
    message_ru = "Загружает отдельную среду выполнения Node.js (чтобы запускать вредоносный JS независимо от системы)"
  strings:
    // Fake meeting app installers fetch Node.js with curl / wget; editor extensions downloading their own Node from JS is common and doesn't count
    $a = /(curl|wget)\b[^\n]{0,200}nodejs\.org\/dist\//
  condition:
    $a
}

rule tsuba_child_process
{
  meta:
    severity = "medium"
    message = "Runs system commands (child_process)"
    message_zh = "调用系统命令执行（child_process）"
    message_zh_hant = "呼叫系統指令執行（child_process）"
    message_ja = "システムコマンドを実行します（child_process）"
    message_ko = "시스템 명령을 실행합니다(child_process)"
    message_es = "Ejecuta comandos del sistema (child_process)"
    message_fr = "Exécute des commandes système (child_process)"
    message_de = "Führt Systembefehle aus (child_process)"
    message_pt_br = "Executa comandos do sistema (child_process)"
    message_ru = "Выполняет системные команды (child_process)"
  strings:
    $req = /require\(\s*['"](node:)?child_process['"]\s*\)/
    $imp = /from\s+['"](node:)?child_process['"]/
  condition:
    any of them
}

rule tsuba_obfuscated_names
{
  meta:
    severity = "medium"
    message = "Many obfuscated variable names of the form _0x"
    message_zh = "大量 _0x 形式的混淆变量名"
    message_zh_hant = "大量 _0x 形式的混淆變數名稱"
    message_ja = "_0x 形式の難読化された変数名が大量にあります"
    message_ko = "_0x 형태의 난독화된 변수 이름이 많습니다"
    message_es = "Muchos nombres de variable ofuscados del tipo _0x"
    message_fr = "Nombreux noms de variables obscurcis de la forme _0x"
    message_de = "Viele verschleierte Variablennamen der Form _0x"
    message_pt_br = "Muitos nomes de variáveis ofuscados no formato _0x"
    message_ru = "Много обфусцированных имён переменных вида _0x"
  strings:
    $a = /_0x[0-9a-f]{4,}/
  condition:
    #a >= 8
}

rule tsuba_persistence
{
  meta:
    severity = "medium"
    message = "Sets itself to start automatically (LaunchAgents / crontab)"
    message_zh = "写入开机自启（LaunchAgents / crontab）"
    message_zh_hant = "將自己設為登入時自動啟動（LaunchAgents / crontab）"
    message_ja = "自身を自動起動するよう設定します（LaunchAgents / crontab）"
    message_ko = "자동으로 시작되도록 설정합니다(LaunchAgents / crontab)"
    message_es = "Se configura para iniciarse automáticamente (LaunchAgents / crontab)"
    message_fr = "Se configure pour démarrer automatiquement (LaunchAgents / crontab)"
    message_de = "Richtet sich für den automatischen Start ein (LaunchAgents / crontab)"
    message_pt_br = "Configura a si mesmo para iniciar automaticamente (LaunchAgents / crontab)"
    message_ru = "Настраивает собственный автозапуск (LaunchAgents / crontab)"
  strings:
    $a = "LaunchAgents"
    $b = "LaunchDaemons"
    $c = /crontab\s+-/
  condition:
    any of them
}

rule tsuba_socket_host_info
{
  meta:
    severity = "medium"
    message = "Collects host information and then sends it out over a socket"
    message_zh = "收集主机信息后用 socket 外连"
    message_zh_hant = "蒐集主機資訊後透過 socket 對外連線傳送"
    message_ja = "ホスト情報を収集してから socket で外部に送信します"
    message_ko = "호스트 정보를 수집한 뒤 소켓으로 외부에 보냅니다"
    message_es = "Recopila información del equipo y luego la envía a través de un socket"
    message_fr = "Collecte des informations sur la machine puis les envoie via un socket"
    message_de = "Sammelt Informationen über den Rechner und sendet sie dann über einen Socket"
    message_pt_br = "Coleta informações da máquina e depois as envia por um socket"
    message_ru = "Собирает сведения о компьютере и отправляет их через сокет"
  strings:
    $sock = "socket.io-client"
    $info = /(hostname|homedir|userInfo|platform)\(/
  condition:
    // The two within 2000 bytes of each other
    for any i in (1..#sock) : (
      for any j in (1..#info) : ( @info[j] < @sock[i] + 2000 and @sock[i] < @info[j] + 2000 )
    )
}

rule tsuba_base64_to_shell
{
  meta:
    severity = "medium"
    message = "Decodes base64 and pipes it straight into a shell"
    message_zh = "解码 base64 后直接交给 shell 执行"
    message_zh_hant = "解碼 base64 後直接交給 shell 執行"
    message_ja = "base64 をデコードしてそのままシェルにパイプします"
    message_ko = "base64를 디코딩해 바로 셸로 넘깁니다"
    message_es = "Decodifica base64 y lo pasa directamente a un shell"
    message_fr = "Décode du base64 et l'envoie directement à un shell"
    message_de = "Dekodiert base64 und leitet es direkt an eine Shell weiter"
    message_pt_br = "Decodifica base64 e o envia direto para um shell"
    message_ru = "Декодирует base64 и передаёт результат прямо в оболочку"
  strings:
    // Only base64 hard-coded in the code and decoded into a shell: echo <payload> | base64 -d | bash, base64 -d <<< <payload> | sh,
    // or decoding a file and running it. Decoding and running data the tool itself wrote to stdin (cat | base64 -d | bash, common in remote container extensions) doesn't count
    $echo = /(echo|printf)\s+(-\w+\s+)?["']?[A-Za-z0-9+\/=]{4,}["']?\s*\|\s*base64\s+(-\w*[dD]\w*|--decode)\b[^;&\n]*\|\s*(sudo\s+)?(ba|z)?sh\b/
    $here = /base64\s+(-\w*[dD]\w*|--decode)\s+<<<\s*["']?[A-Za-z0-9+\/=]{4,}[^;&\n]*\|\s*(sudo\s+)?(ba|z)?sh\b/
    $file = /base64\s+(-\w*[dD]\w*|--decode)\s+[\w.\/~$-]+\s*\|\s*(sudo\s+)?(ba|z)?sh\b/
  condition:
    any of them
}

rule tsuba_tmp_background_run
{
  meta:
    severity = "medium"
    message = "Copies a program to a temporary folder and quietly runs it in the background"
    message_zh = "把程序复制到临时目录后在后台悄悄运行"
    message_zh_hant = "把程式複製到暫存資料夾後在背景悄悄執行"
    message_ja = "プログラムを一時フォルダにコピーし、バックグラウンドでこっそり実行します"
    message_ko = "프로그램을 임시 폴더에 복사한 뒤 백그라운드에서 몰래 실행합니다"
    message_es = "Copia un programa a una carpeta temporal y lo ejecuta en silencio en segundo plano"
    message_fr = "Copie un programme dans un dossier temporaire et l'exécute discrètement en arrière-plan"
    message_de = "Kopiert ein Programm in einen temporären Ordner und führt es unbemerkt im Hintergrund aus"
    message_pt_br = "Copia um programa para uma pasta temporária e o executa discretamente em segundo plano"
    message_ru = "Копирует программу во временную папку и незаметно запускает её в фоне"
  strings:
    $a = /(nohup|exec)\s+["']?(\/private)?\/(tmp|var\/tmp)\//
  condition:
    $a
}

rule tsuba_signing_excuse
{
  meta:
    severity = "medium"
    message = "The script claims it doesn't need Apple's code signing and notarization, a line used to talk you into bypassing system protection"
    message_zh = "脚本自己声称不用苹果的签名和公证，这是骗你绕过系统保护的说辞"
    message_zh_hant = "腳本自稱不需要 Apple 的程式碼簽署和公證，這是騙你繞過系統保護的說詞"
    message_ja = "スクリプトが Apple のコード署名や公証は不要だと主張しています。システムの保護を回避させるための口実です"
    message_ko = "스크립트가 Apple의 코드 서명과 공증이 필요 없다고 주장합니다. 시스템 보호를 우회하도록 설득하려는 말입니다"
    message_es = "El script afirma que no necesita la firma de código ni la notarización de Apple, una frase usada para convencerte de saltarte la protección del sistema"
    message_fr = "Le script prétend ne pas avoir besoin de la signature de code et de la notarisation d'Apple, un argument pour vous pousser à contourner la protection du système"
    message_de = "Das Skript behauptet, Apples Codesignatur und Beglaubigung seien nicht nötig – ein Vorwand, um dich zum Umgehen des Systemschutzes zu bringen"
    message_pt_br = "O script alega não precisar da assinatura de código e da notarização da Apple, um argumento usado para convencer você a contornar a proteção do sistema"
    message_ru = "Скрипт утверждает, что ему не нужны подпись кода и нотаризация Apple, — этим убеждают обойти защиту системы"
  strings:
    $a = /without (using )?Apple.{0,3}s? (official )?(code[- ]signing|notari[sz]ation)/ nocase
  condition:
    $a
}

rule tsuba_prompt_injection
{
  meta:
    severity = "medium"
    message = "The code seems to address an AI reviewer (prompt injection); normal code doesn't do that"
    message_zh = "代码里有疑似写给 AI 审查员的话（提示注入），正常代码不会这样写"
    message_zh_hant = "程式碼裡有疑似寫給 AI 審查者的話（提示注入），正常程式碼不會這樣寫"
    message_ja = "コードが AI レビュアーに語りかけているようです（プロンプトインジェクション）。通常のコードはそうしません"
    message_ko = "코드가 AI 검토자에게 말을 거는 것으로 보입니다(프롬프트 인젝션). 정상적인 코드는 그러지 않습니다"
    message_es = "El código parece dirigirse a un revisor de AI (inyección de prompts); el código normal no hace eso"
    message_fr = "Le code semble s'adresser à un examinateur IA (injection de prompt) ; du code normal ne fait pas ça"
    message_de = "Der Code scheint sich an einen KI-Prüfer zu richten (Prompt-Injection); normaler Code tut das nicht"
    message_pt_br = "O código parece se dirigir a um revisor de IA (prompt injection); código normal não faz isso"
    message_ru = "Код, похоже, обращается к ИИ-проверяющему (prompt injection); обычный код так не делает"
    skip_quoted = true
    doc_keep = true
  strings:
    $ignore = /ignore (all |any )?(previous|prior|above) instructions/ nocase
    $reviewer = /(AI|LLM) (reviewer|auditor|scanner|security (reviewer|scanner))s?\b/ nocase
    $cn1 = "AI 审查"
    $cn2 = "请放行"
    $cn3 = "请直接放行"
    $mark = /(mark|classify|treat|report) (this|it) as (safe|benign|clean)/ nocase
    $safe = /this (code|file|package|script|extension) is (safe|benign|not malicious)/ nocase
  condition:
    any of them
}

rule tsuba_hide_from_user
{
  meta:
    severity = "medium"
    message = "Asks the AI to hide what it does from the user (typical prompt injection)"
    message_zh = "要求 AI 对用户隐瞒操作（提示注入的典型写法）"
    message_zh_hant = "要求 AI 對使用者隱瞞所做的操作（提示注入的典型寫法）"
    message_ja = "AI に対し、行う操作をユーザーに隠すよう求めています（典型的なプロンプトインジェクション）"
    message_ko = "AI에게 하는 일을 사용자에게 숨기라고 요구합니다(전형적인 프롬프트 인젝션)"
    message_es = "Pide a la AI que oculte al usuario lo que hace (inyección de prompts típica)"
    message_fr = "Demande à l'IA de cacher à l'utilisateur ce qu'elle fait (injection de prompt typique)"
    message_de = "Fordert die KI auf, vor dir zu verbergen, was der Code tut (typische Prompt-Injection)"
    message_pt_br = "Pede à IA que esconda do usuário o que ela faz (prompt injection típico)"
    message_ru = "Просит ИИ скрыть от пользователя свои действия (типичная prompt injection)"
    skip_quoted = true
    doc_keep = true
  strings:
    // "do not tell the user to run it" asks the AI to do it itself and doesn't count; we want "don't let the user know about this"
    $a = /\b(do not|don't|never)\s+(tell|inform|mention|reveal|disclose)\s+(this\s+|it\s+)?(to\s+)?the\s+user\s+(about|that|what|you|we)\b/ nocase
    $b = /without\s+(telling|notifying|informing|alerting)\s+the\s+user/ nocase
    $c = /(hide|conceal)\s+(this|it|these|them)\s+from\s+the\s+user/ nocase
    // Tool poisoning wording: "Do not mention this to the user, it is …", "Do not mention that you first need to …"
    $d = /\b(do not|don't|never)\s+(tell|inform|mention|reveal|disclose)\s+(this|it|that)\s+(to\s+)?(the\s+)?user\b/ nocase
    $e = /\b(do not|don't|never)\s+mention\s+that\s+you\s+(first\s+)?(need|have|must)\s+to\b/ nocase
    $cn1 = "不要告诉用户"
    $cn2 = "不要告知用户"
    $cn3 = "不要让用户知道"
    $cn4 = "对用户隐瞒"
  condition:
    any of them
}

rule tsuba_tool_poisoning
{
  meta:
    severity = "high"
    message = "A tool description or skill hides instructions for the AI: read key files first, pass them in a hidden parameter, or change how other tools behave (tool poisoning)"
    message_zh = "工具描述或 skill 里藏着写给 AI 的指令：让它先读取密钥文件、塞进隐藏参数，或改写别的工具的行为（工具投毒）"
    message_zh_hant = "工具描述或 skill 裡藏著寫給 AI 的指令：要它先讀取金鑰檔案、塞進隱藏參數，或改寫其他工具的行為（工具投毒）"
    message_ja = "ツールの説明やスキルに AI 向けの指示が隠されています。先に鍵ファイルを読ませる、隠しパラメータで渡させる、他のツールの動作を変えさせる、といった内容です（ツールポイズニング）"
    message_ko = "도구 설명이나 스킬에 AI를 향한 지시가 숨어 있습니다. 키 파일을 먼저 읽게 하거나, 숨겨진 매개변수로 넘기게 하거나, 다른 도구의 동작을 바꾸게 합니다(도구 포이즈닝)"
    message_es = "La descripción de una herramienta o skill esconde instrucciones para la AI: leer primero archivos de claves, pasarlos en un parámetro oculto o cambiar el comportamiento de otras herramientas (envenenamiento de herramientas)"
    message_fr = "Une description d'outil ou un skill cache des instructions pour l'IA : lire d'abord des fichiers de clés, les passer dans un paramètre caché, ou modifier le comportement d'autres outils (empoisonnement d'outil)"
    message_de = "Eine Tool-Beschreibung oder ein Skill versteckt Anweisungen für die KI: zuerst Schlüsseldateien lesen, sie in einem versteckten Parameter übergeben oder das Verhalten anderer Tools ändern (Tool Poisoning)"
    message_pt_br = "A descrição de uma ferramenta ou skill esconde instruções para a IA: ler arquivos de chaves primeiro, passá-los em um parâmetro oculto ou mudar o comportamento de outras ferramentas (tool poisoning)"
    message_ru = "Описание инструмента или навыка скрывает инструкции для ИИ: сначала прочитать файлы с ключами, передать их в скрытом параметре или изменить поведение других инструментов (tool poisoning)"
    // The poisoned instructions live inside the tool description string, so quoted content can't be skipped
    doc_keep = true
  strings:
    $tag = /<\/?(IMPORTANT|SYSTEM|INSTRUCTIONS?|HIDDEN)>/
    $before = /before (using|calling|running|you use) this tool/ nocase
    $param = /pass (its|their|the) (contents?|values?) (as|in|into|to)\b/ nocase
    $broken = /otherwise the tool (will not|won't|cannot|can't) work/ nocase
    $read_home = /\bread\s+[`'"]?~\/\.[\w.\/-]+/ nocase
    $shadow = /(must|should|always)\s+(send|forward|bcc|cc|route)\s+(all\s+)?(e-?mails?|messages?|requests?|data)\s+to\s+\S+@/ nocase
    $other_tool = /when this tool is (available|present|loaded)/ nocase
  condition:
    // "before using this tool" on its own is common ("read the README before using this tool"); it only counts together with reading keys or smuggling parameters
    ($tag and any of ($param, $broken, $read_home, $shadow, $other_tool))
    or ($before and ($read_home or $param))
    or ($param and $read_home)
    or ($other_tool and $shadow)
}

rule tsuba_exfil_endpoint
{
  meta:
    severity = "medium"
    message = "Sends data to an address commonly used for exfiltration (Discord / Telegram bots, temporary file hosts, tunnels)"
    message_zh = "把数据发往常被用来外传数据的地址（Discord / Telegram 机器人、临时网盘、内网穿透）"
    message_zh_hant = "把資料送往常被用來外洩資料的位址（Discord / Telegram 機器人、臨時檔案空間、內網穿透通道）"
    message_ja = "データ持ち出しによく使われるアドレスにデータを送信します（Discord / Telegram ボット、一時ファイル共有サービス、トンネル）"
    message_ko = "데이터 유출에 흔히 쓰이는 주소로 데이터를 보냅니다(Discord / Telegram 봇, 임시 파일 호스팅, 터널)"
    message_es = "Envía datos a una dirección habitual para exfiltración (bots de Discord / Telegram, servicios temporales de archivos, túneles)"
    message_fr = "Envoie des données vers une adresse souvent utilisée pour l'exfiltration (bots Discord / Telegram, hébergeurs de fichiers temporaires, tunnels)"
    message_de = "Sendet Daten an eine Adresse, die oft zur Exfiltration dient (Discord-/Telegram-Bots, temporäre Datei-Hoster, Tunnel)"
    message_pt_br = "Envia dados para um endereço comum em exfiltração (bots do Discord / Telegram, hospedagens temporárias de arquivos, túneis)"
    message_ru = "Отправляет данные на адрес, часто используемый для утечки (боты Discord / Telegram, временные файлообменники, туннели)"
  strings:
    // Must appear in a URL: a bare ngrok.io in a domain list (the psl library, for example) doesn't count
    $discord = /discord(app)?\.com\/api\/webhooks\// nocase
    $telegram = "api.telegram.org/bot" nocase
    $webhook = /https?:\/\/webhook\.site\// nocase
    $paste = "pastebin.com/api" nocase
    $tunnel = /https?:\/\/[\w.-]+\.(pipedream\.net|ngrok(-free)?\.(io|app)|oast\.(fun|pro|live|site))/ nocase
    $bin = /requestbin\.(com|net)\// nocase
    $transfer = /https?:\/\/transfer\.sh\// nocase
  condition:
    any of them
}

rule tsuba_credential_files
{
  meta:
    severity = "medium"
    message = "Reads SSH private keys or cloud account and package manager credential files"
    message_zh = "读取 SSH 私钥、云账号或包管理器的凭证文件"
    message_zh_hant = "讀取 SSH 私密金鑰、雲端帳號或套件管理工具的憑證檔案"
    message_ja = "SSH 秘密鍵や、クラウドアカウント、パッケージマネージャの認証情報ファイルを読み取ります"
    message_ko = "SSH 개인 키나 클라우드 계정, 패키지 관리자의 자격 증명 파일을 읽습니다"
    message_es = "Lee claves privadas SSH o archivos de credenciales de cuentas en la nube y gestores de paquetes"
    message_fr = "Lit des clés privées SSH ou des fichiers d'identifiants de comptes cloud et de gestionnaires de paquets"
    message_de = "Liest private SSH-Schlüssel oder Zugangsdaten-Dateien von Cloud-Konten und Paketmanagern"
    message_pt_br = "Lê chaves privadas SSH ou arquivos de credenciais de contas na nuvem e de gerenciadores de pacotes"
    message_ru = "Читает закрытые ключи SSH или файлы учётных данных облачных аккаунтов и менеджеров пакетов"
  strings:
    $ssh = /\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/
    $aws = ".aws/credentials"
    $git = ".git-credentials"
    $gcloud = /\.config\/gcloud\/(credentials|application_default)/
    $kube = /\.kube\/config\b/
  condition:
    any of them
}

rule tsuba_sudo
{
  meta:
    severity = "low"
    message = "Uses sudo to gain root privileges"
    message_zh = "使用 sudo 提权"
    message_zh_hant = "使用 sudo 取得 root 權限"
    message_ja = "sudo で root 権限を取得します"
    message_ko = "sudo로 root 권한을 얻습니다"
    message_es = "Usa sudo para obtener privilegios de root"
    message_fr = "Utilise sudo pour obtenir les privilèges root"
    message_de = "Verschafft sich mit sudo Root-Rechte"
    message_pt_br = "Usa sudo para obter privilégios de root"
    message_ru = "Использует sudo для получения прав root"
  strings:
    $a = /(^|\s)sudo\s/
  condition:
    $a
}

rule tsuba_resource_fork_dropper
{
  meta:
    severity = "high"
    message = "The script cuts data out of a file's resource fork, then unpacks or decrypts it (Bundlore hides its payload in the resource fork to evade scans that only read file contents)"
    message_zh = "脚本从文件的资源派生里截取数据再解压或解密（Bundlore 把载荷藏在资源派生里，躲过只看文件内容的扫描）"
    message_zh_hant = "腳本從檔案的資源分支中擷取資料再解壓縮或解密（Bundlore 把酬載藏在資源分支裡，躲過只讀取檔案內容的掃描）"
    message_ja = "スクリプトがファイルのリソースフォークからデータを切り出し、展開または復号します（Bundlore はファイルの内容しか読まないスキャンを逃れるため、ペイロードをリソースフォークに隠します）"
    message_ko = "스크립트가 파일의 리소스 포크에서 데이터를 잘라 낸 뒤 압축을 풀거나 복호화합니다(Bundlore는 파일 내용만 읽는 스캔을 피하려고 리소스 포크에 페이로드를 숨깁니다)"
    message_es = "El script extrae datos de la bifurcación de recursos de un archivo y luego los descomprime o descifra (Bundlore oculta su carga en la bifurcación de recursos para evadir los escaneos que solo leen el contenido de los archivos)"
    message_fr = "Le script extrait des données de la resource fork d'un fichier, puis les décompresse ou les déchiffre (Bundlore cache sa charge dans la resource fork pour échapper aux analyses qui ne lisent que le contenu des fichiers)"
    message_de = "Das Skript schneidet Daten aus dem Resource Fork einer Datei und entpackt oder entschlüsselt sie (Bundlore versteckt seine Nutzlast im Resource Fork, um Scans zu entgehen, die nur den Dateiinhalt lesen)"
    message_pt_br = "O script extrai dados do resource fork de um arquivo e depois os descompacta ou descriptografa (o Bundlore esconde sua carga no resource fork para escapar de varreduras que só leem o conteúdo dos arquivos)"
    message_ru = "Скрипт извлекает данные из ресурсной ветви файла, затем распаковывает или расшифровывает их (Bundlore прячет нагрузку в ресурсной ветви, чтобы обойти сканеры, читающие только содержимое файла)"
  strings:
    $fork1 = "..namedfork/rsrc"
    $fork2 = "com.apple.ResourceFork"
    $cut1 = /tail\s+-c\s*\+?\d+/
    $cut2 = /dd\s+[^\n]*skip=/
    $unpack1 = /funzip\s+-\S+/
    $unpack2 = /unzip\s+[^\n]*-P\s/
    $unpack3 = /openssl\s+(enc\s+)?-d/
  condition:
    any of ($fork*) and (any of ($cut*) or any of ($unpack*))
}
