/*
  Tsuba's own detection rules.

  Drawn from what real attack samples have in common: Contagious Interview / BeaverTail / OtterCookie / InvisibleFerret,
  the fake meeting app Zeff, ClickFix, malicious npm packages, malicious editor extensions and AI tool skills.
  A match does not mean malicious: it is evidence for the model, or is scored when offline.

  meta fields:
    severity     high / medium / low. low is evidence only and does not affect the verdict
    message      explanation shown to the user, in English
    message_zh   the same explanation in Simplified Chinese. The pack carries its own translation because it
                 updates without a release, so the app's catalog can't know about new rules
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
