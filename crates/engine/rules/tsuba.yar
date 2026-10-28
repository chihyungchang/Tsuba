/*
  Tsuba 自己的检测规则。

  来自真实攻击样本的共性：Contagious Interview / BeaverTail / OtterCookie / InvisibleFerret、
  假会议软件 Zeff、ClickFix、恶意 npm 包、恶意编辑器扩展和 AI 工具 skill。
  命中不等于恶意，只作为证据交给模型，或在离线时打分。

  meta 字段：
    severity     high / medium / low。low 只作为证据，不参与判断
    message      给用户看的说明
    skip_quoted  被引号包住的命中不算（文档在引用攻击话术，不是在下命令）
    doc_keep     出现在说明文档里时不降级（文档里写安装步骤很正常，但这几类在文档里同样可疑）
    skip_well_known  命中片段里的网址都是官方安装源（tsuba.toml 的 well_known_hosts）时不算

  改规则后在 crates/engine/tests 里跑一遍样本和误报测试，再用 `tsuba scan` 扫一遍真实的扩展和 skill。
*/

rule tsuba_eval_decoded
{
  meta:
    severity = "high"
    message = "解码后动态执行代码（eval/Function + base64），常见于混淆的投毒代码"
  strings:
    $a = /(eval|Function)\s*\([^)]{0,200}(atob|base64|fromCharCode|Buffer\.from)/
  condition:
    $a
}

rule tsuba_browser_wallet_data
{
  meta:
    severity = "high"
    message = "读取浏览器密码库或加密钱包数据"
  strings:
    // 只认浏览器目录下的这几个文件名，普通英文里的 “local state” 不算
    $browser = /(Chrome|Chromium|Brave-Browser|Microsoft Edge|Opera|Vivaldi|Arc\/User Data)[^"'`\n]{0,60}\/(Login Data|Local State|Web Data|Cookies)\b/
    // MetaMask、Phantom、Coinbase Wallet 的扩展 ID
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
    message = "删除 macOS 隔离标记（绕过 Gatekeeper 安全检查）"
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
    message = "在用户目录的隐藏文件夹里安装 Node 依赖或运行脚本（攻击者常用 ~/.node_modules、~/.task 等藏身）"
  strings:
    $a = /(homedir\(\)|~|\$HOME)["'`,\s+]*\/?\.(node_modules|task|n2|npl|vscode-server|sysinfo)\b/
  condition:
    $a
}

rule tsuba_multistage_download
{
  meta:
    severity = "medium"
    message = "脚本里又下载并执行了别的脚本（多阶段投递）"
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
    message = "下载独立的 Node.js 运行时（为了脱离系统环境运行恶意 JS）"
  strings:
    // 假会议软件的安装脚本用 curl / wget 拉 Node.js；编辑器扩展在 JS 里下载自己要用的 Node 很常见，不算
    $a = /(curl|wget)\b[^\n]{0,200}nodejs\.org\/dist\//
  condition:
    $a
}

rule tsuba_child_process
{
  meta:
    severity = "medium"
    message = "调用系统命令执行（child_process）"
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
    message = "大量 _0x 形式的混淆变量名"
  strings:
    $a = /_0x[0-9a-f]{4,}/
  condition:
    #a >= 8
}

rule tsuba_persistence
{
  meta:
    severity = "medium"
    message = "写入开机自启（LaunchAgents / crontab）"
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
    message = "收集主机信息后用 socket 外连"
  strings:
    $sock = "socket.io-client"
    $info = /(hostname|homedir|userInfo|platform)\(/
  condition:
    // 两者相距 2000 字节以内
    for any i in (1..#sock) : (
      for any j in (1..#info) : ( @info[j] < @sock[i] + 2000 and @sock[i] < @info[j] + 2000 )
    )
}

rule tsuba_base64_to_shell
{
  meta:
    severity = "medium"
    message = "解码 base64 后直接交给 shell 执行"
  strings:
    // 只认“代码里写死了一段 base64，解码后交给 shell”：echo <密文> | base64 -d | bash、base64 -d <<< <密文> | sh、
    // 解码一个文件再执行。把自己写进 stdin 的数据解码执行（cat | base64 -d | bash，远程容器扩展常这么做）不算
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
    message = "把程序复制到临时目录后在后台悄悄运行"
  strings:
    $a = /(nohup|exec)\s+["']?(\/private)?\/(tmp|var\/tmp)\//
  condition:
    $a
}

rule tsuba_signing_excuse
{
  meta:
    severity = "medium"
    message = "脚本自己声称不用苹果的签名和公证，这是骗你绕过系统保护的说辞"
  strings:
    $a = /without (using )?Apple.{0,3}s? (official )?(code[- ]signing|notari[sz]ation)/ nocase
  condition:
    $a
}

rule tsuba_prompt_injection
{
  meta:
    severity = "medium"
    message = "代码里有疑似写给 AI 审查员的话（提示注入），正常代码不会这样写"
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
    message = "要求 AI 对用户隐瞒操作（提示注入的典型写法）"
    skip_quoted = true
    doc_keep = true
  strings:
    // “do not tell the user to run it”是让 AI 自己去做，不算；要的是“别让用户知道这件事”
    $a = /\b(do not|don't|never)\s+(tell|inform|mention|reveal|disclose)\s+(this\s+|it\s+)?(to\s+)?the\s+user\s+(about|that|what|you|we)\b/ nocase
    $b = /without\s+(telling|notifying|informing|alerting)\s+the\s+user/ nocase
    $c = /(hide|conceal)\s+(this|it|these|them)\s+from\s+the\s+user/ nocase
    // 工具投毒的写法：“Do not mention this to the user, it is …”“Do not mention that you first need to …”
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
    message = "工具描述或 skill 里藏着写给 AI 的指令：让它先读取密钥文件、塞进隐藏参数，或改写别的工具的行为（工具投毒）"
    // 投毒指令就写在工具描述字符串里，不能跳过引号里的内容
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
    // “before using this tool”本身很常见（“用之前先看 README”），只能和读密钥、塞参数一起算
    ($tag and any of ($param, $broken, $read_home, $shadow, $other_tool))
    or ($before and ($read_home or $param))
    or ($param and $read_home)
    or ($other_tool and $shadow)
}

rule tsuba_exfil_endpoint
{
  meta:
    severity = "medium"
    message = "把数据发往常被用来外传数据的地址（Discord / Telegram 机器人、临时网盘、内网穿透）"
  strings:
    // 必须出现在网址里：域名列表（例如 psl 库）里光秃秃的 ngrok.io 不算
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
    message = "读取 SSH 私钥、云账号或包管理器的凭证文件"
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
    message = "使用 sudo 提权"
  strings:
    $a = /(^|\s)sudo\s/
  condition:
    $a
}

rule tsuba_resource_fork_dropper
{
  meta:
    severity = "high"
    message = "脚本从文件的资源派生里截取数据再解压或解密（Bundlore 把载荷藏在资源派生里，躲过只看文件内容的扫描）"
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
