# Tsuba zsh integration: a quick warning when something is pasted into the terminal, then a full check
# after Return is pressed and before the command actually runs.
#
# Installed by the Tsuba App, which sources this file from ~/.zshrc.
# Turn off for now: export TSUBA_DISABLE=1
# Skip one command: prefix it with tskip, e.g.  tskip npm install
# Messages are printed by the tsuba binary (localized there); this script prints nothing itself.

typeset -g TSUBA_BIN=${TSUBA_BIN:-"$HOME/.tsuba/bin/tsuba"}

# A cheap regex prefilter: only start the checker for commands that might be dangerous
typeset -g _TSUBA_RE='(curl|wget)[^|]*[|][[:space:]]*(sudo[[:space:]]+)?[A-Za-z/]*(sh|python3?|node|perl|ruby|osascript)([[:space:]]|$)|<[(][[:space:]]*(curl|wget)|[$][(][[:space:]]*(curl|wget)|base64[[:space:]]+-[[:alnum:]-]*[dD]|(^|[;&|[:space:]])(npm|pnpm|yarn|bun|npx|pnpx|bunx|node|hdiutil|installer|xattr|spctl|osascript|code|code-insiders|cursor|windsurf|codium)([[:space:]]|$)|open[[:space:]].*[.](dmg|pkg|mpkg|app)'

# git clone itself only downloads and runs nothing, so let it through; check the new repository when the prompt returns
typeset -g _TSUBA_CLONE_RE='(^|[;&|[:space:]])(git[[:space:]]+clone|gh[[:space:]]+repo[[:space:]]+clone)[[:space:]]'

typeset -g _TSUBA_PASTED=
typeset -g _TSUBA_CLONE=

tskip() { TSUBA_DISABLE=1 "$@" }

zmodload zsh/zleparameter 2>/dev/null

# If another plugin (oh-my-zsh, autosuggestions, ...) already wraps these widgets, hand back to it after checking
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
    # The report goes to stderr/the terminal and prompts to /dev/tty; stdout is captured for "run the checked script directly"
    local out
    out=$("$TSUBA_BIN" check $flags -- "$cmd" </dev/tty)
    if (( $? != 0 )); then
      print -s -- "$cmd"   # keep it in history so it can be run after verifying
      BUFFER=""
      zle reset-prompt
      return 0
    fi
    # TOCTOU guard: when a remote script is confirmed, run the copy Tsuba pinned and checked instead of letting
    # the shell curl it again (the server could serve malicious content the second time). History keeps what the user typed.
    if [[ $out == *TSUBA_EXEC:* ]]; then
      local run=${out##*TSUBA_EXEC:}
      run=${run%%$'\n'*}
      print -s -- "$cmd"
      BUFFER=$run
    fi
  fi
  if [[ -z $TSUBA_DISABLE && $cmd != tskip\ * && $cmd =~ $_TSUBA_CLONE_RE ]]; then
    _TSUBA_CLONE=$cmd
  fi
  if (( ${+widgets[_tsuba_prev_accept_line]} )); then
    zle _tsuba_prev_accept_line
  else
    zle .accept-line
  fi
}

_tsuba_precmd() {
  local st=$?
  [[ -z $_TSUBA_CLONE ]] && return
  local cmd=$_TSUBA_CLONE
  _TSUBA_CLONE=
  if (( st == 0 )) && [[ -z $TSUBA_DISABLE && -x $TSUBA_BIN ]]; then
    "$TSUBA_BIN" after-clone -- "$cmd" </dev/null
  fi
}

autoload -Uz add-zsh-hook
add-zsh-hook precmd _tsuba_precmd

zle -N accept-line _tsuba_accept_line
zle -N bracketed-paste _tsuba_bracketed_paste
