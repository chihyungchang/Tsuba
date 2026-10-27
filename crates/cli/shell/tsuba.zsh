# Tsuba zsh 集成：粘贴进终端时先提醒一次，按下回车后、命令真正执行前再做完整检查。
#
# 由 Tsuba App 安装，在 ~/.zshrc 里 source 这个文件。
# 临时关闭：export TSUBA_DISABLE=1
# 跳过单条命令：在命令前加 tskip，例如  tskip npm install

typeset -g TSUBA_BIN=${TSUBA_BIN:-"$HOME/.tsuba/bin/tsuba"}

# 先用一个便宜的正则粗筛，只有可能危险的命令才启动检查程序
typeset -g _TSUBA_RE='(curl|wget)[^|]*[|][[:space:]]*(sudo[[:space:]]+)?[A-Za-z/]*(sh|python3?|node|perl|ruby|osascript)([[:space:]]|$)|<[(][[:space:]]*(curl|wget)|[$][(][[:space:]]*(curl|wget)|base64[[:space:]]+-[[:alnum:]-]*[dD]|(^|[;&|[:space:]])(npm|pnpm|yarn|bun|npx|pnpx|bunx|node|hdiutil|installer|xattr|spctl|osascript|code|code-insiders|cursor|windsurf|codium)([[:space:]]|$)|open[[:space:]].*[.](dmg|pkg|mpkg|app)'

typeset -g _TSUBA_PASTED=

tskip() { TSUBA_DISABLE=1 "$@" }

zmodload zsh/zleparameter 2>/dev/null

# 如果别的插件（oh-my-zsh、autosuggestions 等）已经接管了这两个 widget，检查完后交还给它
if [[ ${widgets[accept-line]} == user:* && ${widgets[accept-line]} != user:_tsuba_accept_line ]]; then
  zle -N _tsuba_prev_accept_line ${widgets[accept-line]#user:}
fi
if [[ ${widgets[bracketed-paste]} == user:* && ${widgets[bracketed-paste]} != user:_tsuba_bracketed_paste ]]; then
  zle -N _tsuba_prev_bracketed_paste ${widgets[bracketed-paste]#user:}
fi

_tsuba_bracketed_paste() {
  if (( ${+widgets[_tsuba_prev_bracketed_paste]} )); then
    zle _tsuba_prev_bracketed_paste "$@"
  else
    zle .bracketed-paste "$@"
  fi
  emulate -L zsh
  setopt no_re_match_pcre
  if [[ -z $TSUBA_DISABLE && -x $TSUBA_BIN && $BUFFER =~ $_TSUBA_RE ]]; then
    _TSUBA_PASTED=1
    zle -I
    "$TSUBA_BIN" check --paste -- "$BUFFER" </dev/null
  elif [[ -n $BUFFER ]]; then
    _TSUBA_PASTED=1
  fi
}

_tsuba_accept_line() {
  emulate -L zsh
  setopt no_re_match_pcre
  local cmd=$BUFFER pasted=$_TSUBA_PASTED
  _TSUBA_PASTED=
  if [[ -z $TSUBA_DISABLE && -x $TSUBA_BIN && $cmd != tskip\ * && $cmd =~ $_TSUBA_RE ]]; then
    zle -I
    local -a flags
    [[ -n $pasted ]] && flags=(--pasted)
    if ! "$TSUBA_BIN" check $flags -- "$cmd" </dev/tty; then
      print -s -- "$cmd"   # 保留在历史里，方便核实后再执行
      BUFFER=""
      zle reset-prompt
      return 0
    fi
  fi
  if (( ${+widgets[_tsuba_prev_accept_line]} )); then
    zle _tsuba_prev_accept_line
  else
    zle .accept-line
  fi
}

zle -N accept-line _tsuba_accept_line
zle -N bracketed-paste _tsuba_bracketed_paste
