# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
# Shared ANSI-colour output helpers — all output to stderr.
# Respects NO_COLOR (https://no-color.org) and TERM=dumb.
# Source this file, then use: as_ok / as_info / as_warn / as_error.

# as_color_enabled — the library's single color gate: succeed (0) when stderr is a
# real terminal that hasn't opted out of color, fail (1) otherwise. The one place
# the NO_COLOR / TERM=dumb / `-t 2` predicate lives, so the spinner (progress.bash),
# the posture box (settings-box.bash), and the as_* status helpers below all decide
# color identically — change the policy here and every renderer follows.
as_color_enabled() {
  [[ -z "${NO_COLOR:-}" ]] && [[ "${TERM:-}" != "dumb" ]] && [[ -t 2 ]]
}

_as_use_color=false
as_color_enabled && _as_use_color=true

if "$_as_use_color"; then
  _AS_RST=$'\033[0m'
  _AS_BOLD=$'\033[1m'
  _AS_RED=$'\033[31m'
  _AS_YEL=$'\033[33m'
  _AS_GRN=$'\033[32m'
  _AS_CYN=$'\033[36m'
else
  _AS_RST='' _AS_BOLD='' _AS_RED='' _AS_YEL='' _AS_GRN='' _AS_CYN=''
fi

# Cursor glyph for the selection menu (as_choose). Independent of colour: it marks
# the highlighted row even when colour is off.
_AS_CURSOR='❯'

# ok/info color only the glyph (neutral status shouldn't dominate the screen);
# warn/error color the whole message body (bold) so they stand out from it.
# as_ok <msg>    — ✓ green, success/info
as_ok() { printf '%s✓%s %s\n' "${_AS_GRN}${_AS_BOLD}" "$_AS_RST" "$*" >&2; }
# as_info <msg>  — ▸ cyan, neutral status
as_info() { printf '%s▸%s %s\n' "${_AS_CYN}${_AS_BOLD}" "$_AS_RST" "$*" >&2; }
# as_warn <msg>  — ⚠ yellow, warning
as_warn() { printf '%s⚠ %s%s\n' "${_AS_YEL}${_AS_BOLD}" "$*" "$_AS_RST" >&2; }
# as_error <msg> — ✗ red, error
as_error() { printf '%s✗ %s%s\n' "${_AS_RED}${_AS_BOLD}" "$*" "$_AS_RST" >&2; }

# Greedy word-wrap one content line to at most `width` columns, hanging any
# continuation rows under the value (beneath the "Label  " prefix). Appends the
# resulting row(s) to the caller's `wrapped` array.
_as_box_wrap() {
  local line="$1" width="$2"
  if ((${#line} <= width)); then
    wrapped+=("$line")
    return
  fi
  # Split off a leading "Label<spaces>" prefix so continuation rows line up under
  # the value column rather than the box border.
  local prefix="" rest="$line"
  if [[ "$line" =~ ^([^[:space:]]+[[:space:]]+)(.*)$ ]]; then
    prefix="${BASH_REMATCH[1]}"
    rest="${BASH_REMATCH[2]}"
  fi
  local indent="${prefix//?/ }"
  local -a words
  read -ra words <<<"$rest"
  local cur="$prefix" word
  for word in "${words[@]}"; do
    if [[ "$cur" == "$prefix" ]]; then
      cur="${cur}${word}" # first word sits flush against the prefix
    elif ((${#cur} + 1 + ${#word} > width)); then
      wrapped+=("$cur")
      cur="${indent}${word}"
    else
      cur="${cur} ${word}"
    fi
  done
  wrapped+=("$cur")
}

# _as_hrule <n> — a string of n ─ chars, built by counted repetition rather than
# measuring a multibyte string (${#var} on box-drawing chars miscounts under a C
# locale). Shared by as_box (its rules) and as_choose (its top/bottom delimiters).
_as_hrule() {
  local n="$1" out="" i
  for ((i = 0; i < n; i++)); do out+="─"; done
  printf '%s' "$out"
}

# _as_terminal_cols — echo the terminal's column count when stderr is a real
# terminal, or nothing when piped/captured. Prefers the already-measured COLUMNS
# env var over a live tput query. Shared by as_box and as_choose so both clamp
# their output width through the same code path.
_as_terminal_cols() {
  [[ -t 2 ]] || return 0
  if [[ "${COLUMNS:-}" =~ ^[0-9]+$ ]]; then
    printf '%s' "$COLUMNS"
  else
    tput cols 2>/dev/null || true
  fi
}

# as_box <title> <line>... — draw a titled box (to stderr) around the given
# content lines, auto-sized to the widest line. Content lines must be plain
# ASCII (no embedded ANSI) so a column's display width equals its character
# count; only the border is colored. Used for the orientation notices, which land
# as one framed block instead of a scattered paragraph.
#
# Over-wide rows are word-wrapped to the terminal width so the right border never
# spills off-screen — which a narrow terminal re-wraps into broken/overlapping
# boxes. The width comes from COLUMNS (when exported) or the live terminal; when
# neither is known (output piped/captured, e.g. tests) wrapping is off and the
# box keeps its full natural width.
as_box() {
  local title="$1"
  shift
  # Wrap only when writing to a real terminal: piped/captured output (tests,
  # logs) has no width to fit and must keep the box verbatim.
  local cols
  cols="$(_as_terminal_cols)"
  # content_max excludes the 4 border/padding columns ("│ " + " │"); a sentinel
  # wide value disables wrapping when the terminal width is unknown.
  local content_max=9999
  if [[ "$cols" =~ ^[0-9]+$ ]]; then
    content_max=$((cols - 4))
    ((content_max < 16)) && content_max=16
  fi
  local -a wrapped=()
  local _src
  for _src in "$@"; do _as_box_wrap "$_src" "$content_max"; done
  set -- "${wrapped[@]}"

  local line width=0 i
  for line in "$@"; do ((${#line} > width)) && width=${#line}; done
  local inner=$((width + 2)) # one space of padding each side of the content
  local rule
  rule="$(_as_hrule "$inner")"
  # An empty title draws a plain top rule (matching the bottom); a non-empty one
  # is inset as "─ title ─…". Callers that already name the box elsewhere (e.g. a
  # banner above it) pass "" so the title isn't repeated.
  local top fill
  if [[ -n "$title" ]]; then
    top="─ $title "
    fill=$((inner - ${#title} - 3))
  else
    top=""
    fill=$inner
  fi
  ((fill < 0)) && fill=0
  top+="$(_as_hrule "$fill")"
  {
    printf '%s┌%s┐%s\n' "${_AS_CYN}${_AS_BOLD}" "$top" "$_AS_RST"
    for line in "$@"; do
      # Pad by character count (width - ${#line} spaces): printf's %-*s field width
      # counts bytes, which over-pads lines holding multibyte glyphs (— and box
      # chars), breaking the right border on a UTF-8 terminal.
      printf '%s│%s %s%*s %s│%s\n' "${_AS_CYN}${_AS_BOLD}" "$_AS_RST" "$line" "$((width - ${#line}))" "" "${_AS_CYN}${_AS_BOLD}" "$_AS_RST"
    done
    printf '%s└%s┘%s\n' "${_AS_CYN}${_AS_BOLD}" "$rule" "$_AS_RST"
    # Trailing blank line so the box doesn't butt up against the launch output
    # that follows.
    printf '\n'
  } >&2
}

# as_rule_frame <line>... — frame the content lines between two bold-cyan top/bottom
# rules that span the whole terminal width, with each line centered and NO side
# borders. The rules-only counterpart to as_box: a full box's side borders get dragged
# into the selection when the user copies a command out of it, so command-bearing
# output (the worktree merge hint, the doctor verdict) is set off with rules alone.
# Output to stderr; no lines is a no-op. Content must be plain ASCII so a column's
# display width equals its character count (same limit as as_box).
#
# Width is the terminal's (COLUMNS / tput, via the shared _as_terminal_cols gate);
# piped/captured output (tests, logs) has no terminal to fill, so it falls back to the
# widest content line — there the widest line sits flush-left at column 0.
as_rule_frame() {
  (($# == 0)) && return 0 # no-lines guard
  local line width=0
  for line in "$@"; do ((${#line} > width)) && width=${#line}; done
  local cols
  cols="$(_as_terminal_cols)"
  [[ "$cols" =~ ^[0-9]+$ ]] && ((cols > width)) && width=$cols
  local rule
  rule="$(_as_hrule "$width")"
  {
    printf '%s%s%s\n' "${_AS_CYN}${_AS_BOLD}" "$rule" "$_AS_RST"
    for line in "$@"; do printf '%*s%s\n' "$(((width - ${#line}) / 2))" '' "$line"; done
    printf '%s%s%s\n' "${_AS_CYN}${_AS_BOLD}" "$rule" "$_AS_RST"
  } >&2
}

# _as_choose_prefix_cols <num> — the display width of the fixed part of a menu row
# that precedes the label: a 2-column lead ("❯ " on the selected row, "  " elsewhere),
# then "<num>. ". The SSOT both the rule-width sizing and the per-row label clip read,
# so the two cannot disagree on where the label starts — and it tracks a multi-digit
# <num> instead of assuming the option count stays ≤ 9.
_as_choose_prefix_cols() {
  printf '%s' "$((2 + ${#1} + 2))" # "  " + "<num>" + ". "
}

# Render one menu row in place (clearing the line first so an in-place redraw can't
# leave stale glyphs behind). The highlighted row carries the ❯ cursor and bold
# colour; the rest are indented to line up under it.
#
# A row is a prefix (_as_choose_prefix_cols) plus the label, so when `maxwidth` is
# given the label is clipped to maxwidth-prefix columns (with a trailing … to mark the
# cut). This keeps every row on ONE physical terminal line: as_choose's in-place redraw
# rewinds a FIXED count of lines, and a label that wrapped onto a second physical line
# would slip past the rewind and pile up stale copies on each keypress. maxwidth empty/0
# (width unknown, e.g. piped) disables the clip and prints the row in full.
_as_choose_row() {
  local idx="$1" sel="$2" num="$3" label="$4" maxwidth="${5:-0}"
  local avail=$((maxwidth - $(_as_choose_prefix_cols "$num")))
  if ((maxwidth > 0 && avail >= 1 && ${#label} > avail)); then
    label="${label:0:avail-1}…"
  fi
  if ((idx == sel)); then
    printf '\033[2K%s%s %s. %s%s\n' "${_AS_CYN}${_AS_BOLD}" "$_AS_CURSOR" "$num" "$label" "$_AS_RST" >&2
  else
    printf '\033[2K  %s. %s\n' "$num" "$label" >&2
  fi
}

# as_choose <prompt> <default-1based> <hotkey:Label>... — draw a single-select menu
# (the question and its numbered options framed between two equal-
# width horizontal rules, a ❯ cursor on the highlighted row) and echo the chosen
# 1-based index to stdout.
#
# Navigation: ↑/↓ (or k/j) move the cursor; Enter confirms the highlighted row;
# Esc, q, or Ctrl-D cancels and echoes 0 (no option is 0, so a caller can tell a
# back-out from a pick — as_confirm maps it to No). Each option is "<hotkey>:<Label>",
# and pressing a digit or an option's hotkey letter jumps the cursor to that row — the
# hotkeys are the letters the old single-key prompts accepted (y/n/a/w/g…), kept so
# muscle memory and the line-based tests still work: press the letter, then Enter.
#
# With no interactive terminal (piped/CI) it echoes <default> without drawing, so a
# caller that doesn't pre-gate on a TTY still gets a deterministic answer.
as_choose() {
  local prompt="$1" def="$2"
  shift 2
  local -a keys=() labels=()
  local opt
  for opt in "$@"; do
    keys+=("${opt%%:*}")
    labels+=("${opt#*:}")
  done
  local n=${#labels[@]}
  ((def < 1)) && def=1
  ((def > n)) && def=$n
  if [[ ! -t 0 || ! -t 2 ]]; then
    printf '%s\n' "$def"
    return 0
  fi

  # This interactive body runs only on a real terminal (the TTY guard above
  # returns first otherwise); its navigation is asserted by the pty tests
  # (test_msg_menu.py).
  local sel=$((def - 1)) i key rest pick=0 cancel=0
  # Rule width spans the widest of the prompt and the option rows. A rendered row is
  # "  N. label" / "❯ N. label" — _as_choose_prefix_cols columns of prefix, then the
  # label — so its width is that prefix plus the label length.
  local width=${#prompt} rowlen cols rule
  for ((i = 0; i < n; i++)); do
    rowlen=$(($(_as_choose_prefix_cols "$((i + 1))") + ${#labels[i]}))
    ((rowlen > width)) && width=$rowlen
  done
  cols="$(_as_terminal_cols)"
  [[ "$cols" =~ ^[0-9]+$ ]] && ((cols > 0 && width > cols)) && width=$cols
  rule="$(_as_hrule "$width")"

  printf '%s%s%s\n' "${_AS_CYN}${_AS_BOLD}" "$rule" "$_AS_RST" >&2 # top delimiter
  printf '%s\n' "$prompt" >&2
  printf '\033[?25l' >&2 # hide the cursor while the menu owns the screen
  # Restore the cursor on return — the normal pick/cancel exit and a set -e abort
  # both fire RETURN. (A SIGINT that kills the shell outright won't, but the
  # callers treat Ctrl-C as terminating the whole launch anyway.)
  trap 'printf "\033[?25h" >&2' RETURN
  for ((i = 0; i < n; i++)); do _as_choose_row "$i" "$sel" "$((i + 1))" "${labels[i]}" "$width"; done
  printf '%s%s%s\n' "${_AS_CYN}${_AS_BOLD}" "$rule" "$_AS_RST" >&2 # bottom delimiter

  while ((pick == 0)); do
    IFS= read -rsn1 key || {
      cancel=1
      break
    } # EOF (Ctrl-D) cancels
    case "$key" in
    $'\033') # Esc: a lone Esc cancels; an arrow key arrives as Esc-[-A/B/C/D.
      # A real arrow delivers its [A/[B… in the same terminal write as the Esc, so
      # the two bytes are already buffered; the 50ms wait only ever elapses on a
      # bare Esc (no sequence follows), which we treat as cancel.
      IFS= read -rsn2 -t 0.05 rest || rest=""
      case "$rest" in
      '[A' | '[D') ((sel = (sel - 1 + n) % n)) ;;
      '[B' | '[C') ((sel = (sel + 1) % n)) ;;
      '') cancel=1 pick=1 ;;
      esac
      ;;
    k | K) ((sel = (sel - 1 + n) % n)) ;;
    j | J) ((sel = (sel + 1) % n)) ;;
    # q or Ctrl-D cancels. In the menu's raw mode Ctrl-D is delivered as the byte
    # 0x04, NOT an EOF that fails the read, so it must be matched explicitly — it is
    # how the onboarding prompts let an absent user decline (don't auto-run anything).
    q | Q | $'\004') cancel=1 pick=1 ;;
    '' | $'\n' | $'\r') pick=1 ;;
    *) # a digit or an option hotkey jumps to that row
      for ((i = 0; i < n; i++)); do
        [[ "$key" == "$((i + 1))" || "$key" == "${keys[i]}" ]] && {
          sel=$i
          break
        }
      done
      ;;
    esac
    # Rewind over the option rows AND the bottom rule, then repaint both (the top rule
    # and the prompt above them stay put). The rule never changes, but reprinting it
    # is what lands the cursor back below the frame for the next iteration.
    printf '\033[%dA' "$((n + 1))" >&2
    for ((i = 0; i < n; i++)); do _as_choose_row "$i" "$sel" "$((i + 1))" "${labels[i]}" "$width"; done
    printf '\033[2K%s%s%s\n' "${_AS_CYN}${_AS_BOLD}" "$rule" "$_AS_RST" >&2
  done

  # Cancel (Esc/q/EOF) returns 0 — distinct from every 1-based option — so a caller
  # can tell "backed out" from "picked the default"; as_confirm maps it to No.
  ((cancel)) && printf '0\n' || printf '%s\n' "$((sel + 1))"
}

# as_confirm <prompt> [default] — a yes/no as_choose. default is "y" or "n"
# (default "n", the fail-closed choice). Returns 0 when Yes is chosen, 1 for No.
# Use in a condition: `if as_confirm "Proceed?" y; then …`.
as_confirm() {
  local prompt="$1" default="${2:-n}" def_idx=2
  [[ "$default" == [Yy]* ]] && def_idx=1
  local idx
  idx=$(as_choose "$prompt" "$def_idx" "y:Yes" "n:No")
  [[ "$idx" == 1 ]]
}

# as_pause [prompt] — block until the user presses Enter, so a wall of manual
# follow-up steps (e.g. "install the app and subscribe to this topic on your
# phone") isn't immediately scrolled away by the next prompt. No-op when stdin
# isn't a terminal so scripted/CI runs never hang. EOF (Ctrl-D) also returns —
# an absent user is never stuck. The prompt goes to stderr (read -p's default).
as_pause() {
  local prompt="${1:-Press Enter to continue.}"
  [[ -t 0 ]] || return 0
  local _discard
  read -rp "$prompt" _discard || true # allow-exit-suppress: read returns 1 on EOF (Ctrl-D); an absent user must continue, not stall, and the line is intentionally discarded
}
