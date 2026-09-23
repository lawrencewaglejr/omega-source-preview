#!/bin/sh

trap 'trap "" HUP INT TERM; printf "\nOMEGA_RESULT=UNKNOWN\n"; exit 2' HUP INT TERM
omega_bootstrap_result() {
  trap '' HUP INT TERM
  printf '\nOMEGA_RESULT=UNKNOWN\n'
  exit 2
}
omega_bootstrap_reject() {
  trap '' HUP INT TERM
  printf 'OMEGA bootstrap rejected an unsupported invocation.\n' >&2
  exit 125
}
omega_bootstrap_child=""
omega_bootstrap_signal=""
omega_bootstrap_transition=false
omega_bootstrap_transition_done=false
omega_bootstrap_ready_event=false
omega_bootstrap_ready=false
omega_bootstrap_forwarded=false
omega_bootstrap_catch_signal() {
  [ -n "$omega_bootstrap_signal" ] || omega_bootstrap_signal="$1"
  trap '' HUP INT TERM
}
omega_bootstrap_note_transition() { omega_bootstrap_transition=true; }
omega_bootstrap_note_ready() { omega_bootstrap_ready_event=true; }
omega_bootstrap_wait_stopped() {
  omega_bootstrap_state=
  while [ -r "/proc/$omega_bootstrap_child/status" ]; do
    while IFS=: read -r omega_bootstrap_key omega_bootstrap_value; do
      if [ "$omega_bootstrap_key" = State ]; then omega_bootstrap_state=$omega_bootstrap_value; break; fi
    done < "/proc/$omega_bootstrap_child/status"
    case "$omega_bootstrap_state" in *T*) return 0 ;; esac
    [ -z "$omega_bootstrap_signal" ] || return 1
  done
  return 1
}
omega_bootstrap_forward_signal() {
  [ -n "$omega_bootstrap_child" ] && [ "$omega_bootstrap_forwarded" = false ] || return 0
  omega_bootstrap_forwarded=true
  omega_bootstrap_forward=TERM
  if [ "$omega_bootstrap_ready" = true ] && [ "$omega_bootstrap_signal" != INT ]; then
    omega_bootstrap_forward=$omega_bootstrap_signal
  fi
  kill -"$omega_bootstrap_forward" "$omega_bootstrap_child" 2>/dev/null || :
  kill -CONT "$omega_bootstrap_child" 2>/dev/null || :
}
omega_bootstrap_inject_test_signal() {
  [ "$omega_bootstrap_test_enabled" = true ] && [ "$omega_bootstrap_test_phase" = "$1" ] || return 0
  kill -"$omega_bootstrap_test_signal" "$$" 2>/dev/null || omega_bootstrap_reject
}
trap 'omega_bootstrap_catch_signal HUP' HUP
trap 'omega_bootstrap_catch_signal INT' INT
trap 'omega_bootstrap_catch_signal TERM' TERM
trap omega_bootstrap_note_transition USR2
trap omega_bootstrap_note_ready USR1
if [ -n "${BASH_VERSION-}" ]; then omega_bootstrap_reject; fi
omega_bootstrap_home=${HOME-}
omega_bootstrap_tmpdir=
omega_bootstrap_test_phase=${OMEGA_TEST_BOOTSTRAP_PHASE-}
omega_bootstrap_test_signal=${OMEGA_TEST_BOOTSTRAP_SIGNAL-}
omega_bootstrap_test_enabled=false
if [ -n "$omega_bootstrap_test_phase" ] || [ -n "$omega_bootstrap_test_signal" ]; then
  omega_bootstrap_test_guard=/usr/local/libexec/omega-test-guard
  [ "${BASH_ENV-}" = "$omega_bootstrap_test_guard" ] && [ ! -L "$omega_bootstrap_test_guard" ] &&
    [ ! -L /usr/local/libexec ] || omega_bootstrap_reject
  omega_bootstrap_guard_meta=$(/usr/bin/stat -c '%F|%u|%a' -- "$omega_bootstrap_test_guard" 2>/dev/null) || omega_bootstrap_reject
  omega_bootstrap_guard_parent_meta=$(/usr/bin/stat -c '%F|%u|%a' -- /usr/local/libexec 2>/dev/null) || omega_bootstrap_reject
  [ "$omega_bootstrap_guard_meta" = 'regular file|0|644' ] &&
    [ "$omega_bootstrap_guard_parent_meta" = 'directory|0|755' ] || omega_bootstrap_reject
  case "$omega_bootstrap_test_phase:$omega_bootstrap_test_signal" in
    startup:HUP|startup:INT|startup:TERM|transition:HUP|transition:INT|transition:TERM|ready:HUP|ready:INT|ready:TERM)
      omega_bootstrap_test_enabled=true ;;
    *) omega_bootstrap_reject ;;
  esac
fi
omega_bootstrap_inject_test_signal startup
[ -z "$omega_bootstrap_signal" ] || omega_bootstrap_result
exec 8< "$0" || omega_bootstrap_result
exec 9< "$0" || omega_bootstrap_result
omega_bootstrap_source_id=$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/8" 2>/dev/null) || omega_bootstrap_result
[ "$omega_bootstrap_source_id" = "$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/9" 2>/dev/null)" ] &&
  [ "$omega_bootstrap_source_id" = "$(/usr/bin/stat -Lc '%d:%i' -- "$0" 2>/dev/null)" ] || omega_bootstrap_result
case "$omega_bootstrap_source_id" in *[!0-9:]*|:*|*:) omega_bootstrap_result ;; esac
omega_bootstrap_found=false
while IFS= read -r omega_bootstrap_line <&8; do
  if [ "$omega_bootstrap_line" = '# OMEGA_BASH_BODY_V1' ]; then omega_bootstrap_found=true; break; fi
done
exec 8<&-
[ "$omega_bootstrap_found" = true ] || omega_bootstrap_result
omega_bootstrap_bash='
trap '"'"'trap - EXIT; trap "" HUP INT TERM; builtin printf "\nOMEGA_RESULT=FAILURE\n"; exit 3'"'"' EXIT
trap '"'"'trap - EXIT; trap "" HUP INT TERM; builtin printf "\nOMEGA_RESULT=UNKNOWN\n"; exit 2'"'"' HUP INT TERM
omega_body_parent_pid=$BASHPID
source <(
  omega_body_copy=false
  while IFS= read -r omega_body_line; do
    if [ "$omega_body_copy" = true ]; then builtin printf "%s\n" "$omega_body_line"
    elif [ "$omega_body_line" = "# OMEGA_BASH_BODY_V1" ]; then omega_body_copy=true; fi
  done < "/proc/$omega_body_parent_pid/fd/0"
)
'
/bin/sh -c '
  trap '"'"'exit 125'"'"' HUP INT TERM
  trap - USR1 USR2
  omega_gate_parent=$1; shift
  kill -USR2 "$omega_gate_parent" || exit 125
  kill -STOP "$$" || exit 125
  exec "$@"
' omega-gate "$$" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
  /bin/bash --noprofile --norc -c "$omega_bootstrap_bash" omega-bootstrap \
  "$omega_bootstrap_home" "$omega_bootstrap_tmpdir" "$$" <&9 &
omega_bootstrap_child=$!
while :; do
  if [ -n "$omega_bootstrap_signal" ]; then omega_bootstrap_forward_signal; fi
  if [ "$omega_bootstrap_transition" = true ] && [ "$omega_bootstrap_transition_done" = false ]; then
    omega_bootstrap_transition_done=true
    if omega_bootstrap_wait_stopped; then
      omega_bootstrap_inject_test_signal transition
      if [ -n "$omega_bootstrap_signal" ]; then omega_bootstrap_forward_signal
      else kill -CONT "$omega_bootstrap_child" 2>/dev/null || :; fi
    fi
  fi
  if [ "$omega_bootstrap_ready_event" = true ] && [ "$omega_bootstrap_ready" = false ]; then
    if omega_bootstrap_wait_stopped; then
      omega_bootstrap_ready=true
      omega_bootstrap_inject_test_signal ready
      if [ -n "$omega_bootstrap_signal" ]; then omega_bootstrap_forward_signal
      else kill -CONT "$omega_bootstrap_child" 2>/dev/null || :; fi
    fi
  fi
  wait "$omega_bootstrap_child"
  omega_bootstrap_status=$?
  if kill -0 "$omega_bootstrap_child" 2>/dev/null; then continue; fi
  case "$omega_bootstrap_status" in 0|1|2|3) break ;; esac
  break
done
trap '' HUP INT TERM USR1 USR2
case "$omega_bootstrap_status" in 0|1|2|3) exit "$omega_bootstrap_status" ;; esac
omega_bootstrap_result

# OMEGA_BASH_BODY_V1
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
OMEGA_BOOTSTRAP_HOME_INPUT="${1-}"
OMEGA_BOOTSTRAP_TMPDIR_INPUT="${2-}"
OMEGA_BOOTSTRAP_SUPERVISOR_PID="${3-}"
set -uo pipefail

RESULT_CODE=0
RESULT_EMITTED=false
RESULT_FD=1
ERROR_FD=2
omega_early_result_name() {
  case "$RESULT_CODE" in 0) builtin printf SUCCESS ;; 1) builtin printf WARNING ;;
    2) builtin printf UNKNOWN ;; *) builtin printf FAILURE ;; esac
}
emit_result_marker() {
  local name
  trap '' HUP INT TERM
  [ "$RESULT_EMITTED" = false ] || return 0
  RESULT_EMITTED=true
  name=$(omega_early_result_name)
  builtin printf '\nOMEGA_RESULT=%s\n' "$name" >&"$RESULT_FD"
}
omega_early_promote() {
  local code="$1"
  if (( code > RESULT_CODE )); then RESULT_CODE="$code"; fi
}
omega_early_signal() {
  trap - EXIT; trap '' HUP INT TERM
  omega_early_promote 2
  emit_result_marker
  exit "$RESULT_CODE"
}
omega_early_exit() {
  trap - EXIT; trap '' HUP INT TERM
  if [ "$RESULT_EMITTED" = false ]; then omega_early_promote 3; emit_result_marker; fi
  exit "$RESULT_CODE"
}
trap omega_early_signal HUP INT TERM
trap omega_early_exit EXIT
omega_bootstrap_child_ready() {
  [ -n "$OMEGA_BOOTSTRAP_SUPERVISOR_PID" ] || return 0
  [[ "$OMEGA_BOOTSTRAP_SUPERVISOR_PID" =~ ^[0-9]+$ ]] &&
    [ "$OMEGA_BOOTSTRAP_SUPERVISOR_PID" = "$PPID" ] || return 1
  builtin kill -USR1 "$OMEGA_BOOTSTRAP_SUPERVISOR_PID" || return 1
  builtin kill -STOP "$BASHPID"
}
if ! omega_bootstrap_child_ready; then omega_early_promote 3; exit 3; fi

# OMEGA_TRUSTED_EXEC_V1_BEGIN
OMEGA_TRUSTED_DIRS=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)
OMEGA_TRUSTED_MAX_SYMLINKS=16
OMEGA_TRUSTED_MAX_COMPONENTS=128
TRUSTED_CANONICAL="" TRUSTED_MODE="" TRUSTED_ID=""
trusted_executable_path() {
  local input="$1" current=/ pending component candidate metadata type uid mode dev ino target final_metadata
  local steps=0 links=0 seen=:; local LC_ALL=C; export LC_ALL
  TRUSTED_CANONICAL="" TRUSTED_MODE="" TRUSTED_ID=""
  [[ "$input" = /* && "$input" != *[[:cntrl:]]* ]] || return 1
  metadata=$(/usr/bin/stat -c $'%F\t%u\t%a\t%d\t%i' -- / 2>/dev/null) || return 1
  IFS=$'\t' read -r type uid mode dev ino <<< "$metadata"
  [[ "$type" = directory && "$uid" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  pending="${input#/}"
  while [ -n "$pending" ]; do
    steps=$((steps+1)); (( steps <= OMEGA_TRUSTED_MAX_COMPONENTS )) || return 1
    component="${pending%%/*}"
    if [[ "$pending" = */* ]]; then pending="${pending#*/}"; else pending=""; fi
    case "$component" in
      ''|.) continue ;;
      ..) current="${current%/*}"; [ -n "$current" ] || current=/; continue ;;
    esac
    if [ "$current" = / ]; then candidate="/$component"; else candidate="$current/$component"; fi
    metadata=$(/usr/bin/stat -c $'%F\t%u\t%a\t%d\t%i' -- "$candidate" 2>/dev/null) || return 1
    IFS=$'\t' read -r type uid mode dev ino <<< "$metadata"
    if [ "$type" = "symbolic link" ]; then
      links=$((links+1)); (( links <= OMEGA_TRUSTED_MAX_SYMLINKS )) || return 1
      [ "$uid" = 0 ] && [[ "$seen" != *":$dev:$ino:"* ]] || return 1
      seen="$seen$dev:$ino:"
      target=$(/usr/bin/readlink -- "$candidate" 2>/dev/null) || return 1
      [[ -n "$target" && "$target" != *[[:cntrl:]]* ]] || return 1
      if [[ "$target" = /* ]]; then current=/; target="${target#/}"; fi
      pending="$target${pending:+/$pending}"
      continue
    fi
    if [ -n "$pending" ]; then
      [[ "$type" = directory && "$uid" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
      (( (8#$mode & 8#022) == 0 )) || return 1
      current="$candidate"
      continue
    fi
    [[ ( "$type" = "regular file" || "$type" = "regular empty file" ) && "$uid" = 0 &&
       "$mode" =~ ^[0-7]{3,4}$ && -x "$candidate" ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || return 1
    TRUSTED_CANONICAL="$candidate" TRUSTED_MODE="$mode" TRUSTED_ID="$dev:$ino"
    final_metadata=$(/usr/bin/stat -c $'%F\t%u\t%a\t%d\t%i' -- "$TRUSTED_CANONICAL" 2>/dev/null) || return 1
    [ "$final_metadata" = "$metadata" ] || return 1
  done
  [ -n "$TRUSTED_CANONICAL" ]
}
resolve_trusted_command() {
  local name="$1" directory candidate=""
  [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]] || return 1
  for directory in "${OMEGA_TRUSTED_DIRS[@]}"; do
    if [[ -e "$directory/$name" || -L "$directory/$name" ]]; then candidate="$directory/$name"; break; fi
  done
  [[ -n "$candidate" ]] && trusted_executable_path "$candidate" || return 1
  builtin printf '%s\n' "$TRUSTED_CANONICAL"
}
# OMEGA_TRUSTED_EXEC_V1_END

# OMEGA_RUNTIME_INPUT_V1_BEGIN
OMEGA_CONFIG_FILE="/etc/omega/omega.conf"
OMEGA_DEFAULT_EVE="/var/log/suricata/eve.json"
EVE="$OMEGA_DEFAULT_EVE"
CONFIG_ERROR_KIND="invalid"
TELEMETRY_FD="" TELEMETRY_ID=""
load_omega_config() {
  local etc_meta dir_meta meta fd_meta current line1 line2 extra expected_size type uid mode dev ino size config_fd="" component
  local -a components; local LC_ALL=C; export LC_ALL
  EVE="$OMEGA_DEFAULT_EVE"; CONFIG_ERROR_KIND="invalid"
  [ -n "${OMEGA_STAT:-}" ] || { CONFIG_ERROR_KIND="unknown"; return 1; }
  [ ! -L /etc ] || return 1
  etc_meta=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- /etc 2>/dev/null) || { CONFIG_ERROR_KIND="unknown"; return 1; }
  IFS=$'\t' read -r type uid mode dev ino <<< "$etc_meta"
  [[ "$type" = "directory" && "$uid" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  [ -x /etc ] || { CONFIG_ERROR_KIND="unknown"; return 1; }
  if [ ! -e /etc/omega ] && [ ! -L /etc/omega ]; then return 0; fi
  [ ! -L /etc/omega ] || return 1
  dir_meta=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- /etc/omega 2>/dev/null) || { CONFIG_ERROR_KIND="unknown"; return 1; }
  IFS=$'\t' read -r type uid mode dev ino <<< "$dir_meta"
  [[ "$type" = "directory" && "$uid" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  [ -x /etc/omega ] || { CONFIG_ERROR_KIND="unknown"; return 1; }
  if [ ! -e "$OMEGA_CONFIG_FILE" ] && [ ! -L "$OMEGA_CONFIG_FILE" ]; then return 0; fi
  [ ! -L "$OMEGA_CONFIG_FILE" ] || return 1
  meta=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i\t%s' -- "$OMEGA_CONFIG_FILE" 2>/dev/null) || { CONFIG_ERROR_KIND="unknown"; return 1; }
  IFS=$'\t' read -r type uid mode dev ino size <<< "$meta"
  [[ ("$type" = "regular file" || "$type" = "regular empty file") && "$uid" = 0 && "$mode" = 644 && "$size" =~ ^[0-9]+$ ]] && (( size <= 4096 )) || return 1
  if ! { exec {config_fd}< "$OMEGA_CONFIG_FILE"; } 2>/dev/null; then CONFIG_ERROR_KIND="unknown"; return 1; fi
  fd_meta=$("$OMEGA_STAT" -Lc $'%F\t%u\t%a\t%d\t%i\t%s' -- "/proc/self/fd/$config_fd" 2>/dev/null) || { exec {config_fd}<&-; CONFIG_ERROR_KIND="unknown"; return 1; }
  current=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i\t%s' -- "$OMEGA_CONFIG_FILE" 2>/dev/null) || { exec {config_fd}<&-; CONFIG_ERROR_KIND="unknown"; return 1; }
  if [ "$fd_meta" != "$meta" ] || [ "$current" != "$meta" ]; then
    exec {config_fd}<&-; CONFIG_ERROR_KIND="unknown"; return 1
  fi
  if ! IFS= read -r line1 <&"$config_fd" || ! IFS= read -r line2 <&"$config_fd" || IFS= read -r extra <&"$config_fd"; then
    exec {config_fd}<&-; return 1
  fi
  exec {config_fd}<&-
  expected_size=$((${#line1} + ${#line2} + 2))
  [ "$expected_size" = "$size" ] && (( ${#line1} <= 2048 && ${#line2} <= 2048 )) || return 1
  [[ "$line1" = OMEGA_CONFIG_V1 && "$line2" = suricata_eve_path=* && "$line1" != *[[:cntrl:]]* && "$line2" != *[[:cntrl:]]* ]] || return 1
  [[ "$line1" != ' '* && "$line1" != *' ' && "$line2" != ' '* && "$line2" != *' ' ]] || return 1
  EVE="${line2#suricata_eve_path=}"
  [[ -n "$EVE" && "$EVE" = /* && "$EVE" != / && ${#EVE} -le 2000 && "$EVE" != *//* && "$EVE" != */ && "$EVE" != *[[:cntrl:]]* ]] || return 1
  IFS=/ read -r -a components <<< "${EVE#/}"
  for component in "${components[@]}"; do [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1; done
  current=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i\t%s' -- "$OMEGA_CONFIG_FILE" 2>/dev/null) || { CONFIG_ERROR_KIND="unknown"; return 1; }
  [ "$current" = "$meta" ] &&
    [ "$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- /etc 2>/dev/null)" = "$etc_meta" ] &&
    [ "$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- /etc/omega 2>/dev/null)" = "$dir_meta" ] || { CONFIG_ERROR_KIND="unknown"; return 1; }
}
open_telemetry() {
  local meta fd_meta type dev ino; local LC_ALL=C; export LC_ALL
  TELEMETRY_FD=""
  [ ! -L "$EVE" ] || return 1
  meta=$("$OMEGA_STAT" -c $'%F\t%d\t%i' -- "$EVE" 2>/dev/null) || return 1
  IFS=$'\t' read -r type dev ino <<< "$meta"
  [[ "$type" = "regular file" || "$type" = "regular empty file" ]] || return 1
  if ! { exec {TELEMETRY_FD}< "$EVE"; } 2>/dev/null; then TELEMETRY_FD=""; return 1; fi
  fd_meta=$("$OMEGA_STAT" -Lc $'%F\t%d\t%i' -- "/proc/self/fd/$TELEMETRY_FD" 2>/dev/null) || fd_meta=""
  if [ "$fd_meta" != "$meta" ] || [ "$("$OMEGA_STAT" -c $'%F\t%d\t%i' -- "$EVE" 2>/dev/null)" != "$meta" ]; then
    exec {TELEMETRY_FD}<&-; TELEMETRY_FD=""; return 1
  fi
  TELEMETRY_ID="$dev:$ino"
}
telemetry_path_unchanged() {
  local meta type dev ino; local LC_ALL=C; export LC_ALL
  [ -n "$TELEMETRY_FD" ] && [ ! -L "$EVE" ] || return 1
  meta=$("$OMEGA_STAT" -c $'%F\t%d\t%i' -- "$EVE" 2>/dev/null) || return 1
  IFS=$'\t' read -r type dev ino <<< "$meta"
  [[ "$type" = "regular file" || "$type" = "regular empty file" ]] && [ "$dev:$ino" = "$TELEMETRY_ID" ]
}
close_telemetry_fd() {
  if [ -n "$TELEMETRY_FD" ]; then { exec {TELEMETRY_FD}<&-; } 2>/dev/null || true; fi
  TELEMETRY_FD=""
}
# OMEGA_RUNTIME_INPUT_V1_END
TMP_WORK=""
PUBLISHED_FILE=""
PUBLISH_STAGE=""
PUBLISH_STAGE_ID=""
PUBLISHED_ID=""
REPORT_FD=""
COPY_FD=""
STAGE_FD=""
HOME_ID=""
OUT_DIR_ID=""
TMP_WORK_ID=""
TMP_REPORT_ID=""
PARSED_EVENTS_ID=""
EVENT_TYPES_ID=""
DNS_ID=""
ALERTS_ID=""
FINALIZING=false
PENDING_SIGNAL=""
CLEANUP_ATTEMPTED=false
PUBLISH_CLEANUP_ATTEMPTED=false
RETAIN_EVIDENCE=false

promote_result() {
  local code="$1"
  if (( code > RESULT_CODE )); then
    RESULT_CODE="$code"
  fi
}

result_name() {
  case "$RESULT_CODE" in
    0) echo "SUCCESS" ;;
    1) echo "WARNING" ;;
    2) echo "UNKNOWN" ;;
    3) echo "FAILURE" ;;
  esac
}

close_display_fd() {
  local close_ok=true
  if [ -n "${REPORT_FD:-}" ]; then
    { exec {REPORT_FD}<&-; } 2>/dev/null || close_ok=false
    REPORT_FD=""
  fi
  [ "$close_ok" = true ]
}

close_copy_fd() {
  local close_ok=true
  if [ -n "${COPY_FD:-}" ]; then
    { exec {COPY_FD}<&-; } 2>/dev/null || close_ok=false
    COPY_FD=""
  fi
  [ "$close_ok" = true ]
}

close_stage_fd() {
  local close_ok=true
  if [ -n "${STAGE_FD:-}" ]; then
    { exec {STAGE_FD}>&-; } 2>/dev/null || close_ok=false
    STAGE_FD=""
  fi
  [ "$close_ok" = true ]
}

close_report_fd() {
  local close_ok=true
  close_display_fd || close_ok=false
  close_copy_fd || close_ok=false
  close_stage_fd || close_ok=false
  [ "$close_ok" = true ]
}

safe_directory_tree() {
  local value="$1" final_policy="$2" component current=/ metadata type uid mode dev ino
  local -a components
  local LC_ALL=C
  SAFE_DIRECTORY_ID="" SAFE_DIRECTORY_UID="" SAFE_DIRECTORY_MODE=""
  [[ -n "$OMEGA_STAT" && -n "$value" && "$value" = /* && "$value" != / &&
     "$value" != *[[:cntrl:]]* && "$value" != *//* && "$value" != */ ]] || return 1
  metadata=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- / 2>/dev/null) || return 1
  IFS=$'\t' read -r type uid mode dev ino <<< "$metadata"
  [[ "$type" = directory && "$uid" = 0 && "$mode" =~ ^[0-7]{3,4}$ &&
     "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ ]] || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  IFS=/ read -r -a components <<< "${value#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
    if [ "$current" = / ]; then current="/$component"; else current="$current/$component"; fi
    [ ! -L "$current" ] || return 1
    metadata=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- "$current" 2>/dev/null) || return 1
    IFS=$'\t' read -r type uid mode dev ino <<< "$metadata"
    [[ "$type" = directory && "$uid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ &&
       "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ ]] || return 1
    if (( (8#$mode & 8#022) != 0 )); then
      [ "$uid" = 0 ] && [ "$mode" = 1777 ] || return 1
    else
      [ "$uid" = 0 ] || [ "$uid" = "$EUID" ] || return 1
    fi
    [ -x "$current" ] || return 1
  done
  if [ "$final_policy" = user ]; then
    [ "$uid" = "$EUID" ] && (( (8#$mode & 8#022) == 0 )) || return 1
  fi
  [ -w "$value" ] && [ -x "$value" ] || return 1
  SAFE_DIRECTORY_ID="$dev:$ino" SAFE_DIRECTORY_UID="$uid" SAFE_DIRECTORY_MODE="$mode"
}

private_directory_identity() {
  local value="$1" expected="$2" metadata type uid mode dev ino
  PRIVATE_DIRECTORY_ID=""
  [ ! -L "$value" ] || return 1
  metadata=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i' -- "$value" 2>/dev/null) || return 1
  IFS=$'\t' read -r type uid mode dev ino <<< "$metadata"
  [[ "$type" = directory && "$uid" = "$EUID" && "$mode" = 700 &&
     "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ ]] || return 1
  PRIVATE_DIRECTORY_ID="$dev:$ino"
  [ -z "$expected" ] || [ "$PRIVATE_DIRECTORY_ID" = "$expected" ]
}

private_file_identity() {
  local value="$1" expected="$2" metadata type uid mode dev ino links
  PRIVATE_FILE_ID=""
  [ ! -L "$value" ] || return 1
  metadata=$("$OMEGA_STAT" -c $'%F\t%u\t%a\t%d\t%i\t%h' -- "$value" 2>/dev/null) || return 1
  IFS=$'\t' read -r type uid mode dev ino links <<< "$metadata"
  [[ ( "$type" = "regular file" || "$type" = "regular empty file" ) && "$uid" = "$EUID" &&
     "$mode" = 600 && "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ && "$links" = 1 ]] || return 1
  PRIVATE_FILE_ID="$dev:$ino"
  [ -z "$expected" ] || [ "$PRIVATE_FILE_ID" = "$expected" ]
}

private_file_descriptor_identity() {
  local descriptor="$1" expected="$2" metadata type uid mode dev ino links
  PRIVATE_FILE_ID=""
  metadata=$("$OMEGA_STAT" -Lc $'%F\t%u\t%a\t%d\t%i\t%h' -- "/proc/self/fd/$descriptor" 2>/dev/null) || return 1
  IFS=$'\t' read -r type uid mode dev ino links <<< "$metadata"
  [[ ( "$type" = "regular file" || "$type" = "regular empty file" ) && "$uid" = "$EUID" &&
     "$mode" = 600 && "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ && "$links" = 1 ]] || return 1
  PRIVATE_FILE_ID="$dev:$ino"
  [ "$PRIVATE_FILE_ID" = "$expected" ]
}

home_unchanged() {
  safe_directory_tree "$HOME_VALUE" user && [ "$SAFE_DIRECTORY_ID" = "$HOME_ID" ]
}

output_directory_unchanged() {
  [ -n "$OUT_DIR_ID" ] && home_unchanged && safe_directory_tree "$OUT_DIR" user &&
    [ "$SAFE_DIRECTORY_ID" = "$OUT_DIR_ID" ]
}

workspace_unchanged() {
  [ -n "$TMP_WORK_ID" ] && output_directory_unchanged &&
    private_directory_identity "$TMP_WORK" "$TMP_WORK_ID"
}

report_temp_file_unchanged() {
  workspace_unchanged && private_file_identity "$TMP_REPORT" "$TMP_REPORT_ID"
}

publish_stage_unchanged() {
  [ -n "$PUBLISH_STAGE_ID" ] && output_directory_unchanged &&
    private_file_identity "$PUBLISH_STAGE" "$PUBLISH_STAGE_ID"
}

published_report_unchanged() {
  [ -n "$PUBLISHED_FILE" ] && [ -n "$PUBLISHED_ID" ] && output_directory_unchanged &&
    private_file_identity "$PUBLISHED_FILE" "$PUBLISHED_ID"
}

cleanup_publish_stage() {
  local retained_path
  [ -n "$PUBLISH_STAGE" ] || return 0
  [ "$PUBLISH_CLEANUP_ATTEMPTED" = false ] || return 1
  PUBLISH_CLEANUP_ATTEMPTED=true
  close_stage_fd || promote_result 3
  if publish_stage_unchanged && [ -n "${OMEGA_RM:-}" ] &&
     "$OMEGA_RM" -rf -- "$PUBLISH_STAGE" 2>&"$ERROR_FD"; then
    PUBLISH_STAGE=""
    PUBLISH_STAGE_ID=""
    return 0
  fi
  builtin printf -v retained_path '%q' "$PUBLISH_STAGE"
  echo "Report publication-stage cleanup failed; evidence was retained: $retained_path" >&"$RESULT_FD"
  promote_result 3
  return 1
}

cleanup_workspace() {
  close_telemetry_fd
  [ "$CLEANUP_ATTEMPTED" = false ] || return 0
  CLEANUP_ATTEMPTED=true
  if [ -n "$TMP_WORK" ]; then
    if workspace_unchanged && [ -n "${OMEGA_RM:-}" ] &&
       "$OMEGA_RM" -rf -- "$TMP_WORK" 2>&"$ERROR_FD"; then
      TMP_WORK=""
      TMP_WORK_ID=""
    else
      RETAIN_EVIDENCE=true
      builtin printf -v retained_path '%q' "$TMP_WORK"
      echo "Report temporary-workspace cleanup failed; evidence was retained: $retained_path" >&"$RESULT_FD"
      promote_result 3
      return 1
    fi
  fi
  return 0
}

build_failure_evidence_stage() {
  local stage_candidate="" report_line copy_ok=true

  if [ -n "${OMEGA_MKTEMP:-}" ]; then
    stage_candidate=$("$OMEGA_MKTEMP" -- "$OUT_DIR/.omega-report-stage.XXXXXX" 2>&"$ERROR_FD") ||
      stage_candidate=""
  fi
  if [[ "$stage_candidate" != "$OUT_DIR"/.omega-report-stage.* ]] ||
     ! output_directory_unchanged || ! private_file_identity "$stage_candidate" ""; then
    return 1
  fi
  PUBLISH_STAGE="$stage_candidate"
  PUBLISH_STAGE_ID="$PRIVATE_FILE_ID"

  if ! published_report_unchanged || ! exec {COPY_FD}< "$PUBLISHED_FILE" ||
     ! private_file_descriptor_identity "$COPY_FD" "$PUBLISHED_ID" ||
     ! published_report_unchanged || ! publish_stage_unchanged ||
     ! exec {STAGE_FD}>> "$PUBLISH_STAGE" ||
     ! private_file_descriptor_identity "$STAGE_FD" "$PUBLISH_STAGE_ID" ||
     ! publish_stage_unchanged; then
    close_copy_fd || true
    close_stage_fd || true
    return 1
  fi

  while IFS= read -r report_line <&"$COPY_FD" || [ -n "$report_line" ]; do
    case "$report_line" in
      OMEGA_RESULT=SUCCESS|OMEGA_RESULT=WARNING|OMEGA_RESULT=UNKNOWN|OMEGA_RESULT=FAILURE) continue ;;
    esac
    builtin printf '%s\n' "$report_line" >&"$STAGE_FD" || { copy_ok=false; break; }
  done
  close_copy_fd || copy_ok=false
  if [ "$copy_ok" = true ]; then
    builtin printf '\nOMEGA_RESULT=FAILURE\n' >&"$STAGE_FD" || copy_ok=false
  fi
  if ! private_file_descriptor_identity "$STAGE_FD" "$PUBLISH_STAGE_ID"; then
    copy_ok=false
  fi
  close_stage_fd || copy_ok=false
  [ "$copy_ok" = true ] && publish_stage_unchanged
}

redesignate_interrupted_publication() {
  local original_file="$PUBLISHED_FILE" original_id="$PUBLISHED_ID"
  local evidence_base candidate stage_id
  local attempt=0

  build_failure_evidence_stage || return 1
  stage_id="$PUBLISH_STAGE_ID"
  evidence_base="$original_file.evidence"
  candidate="$evidence_base"

  while (( attempt < 100 )); do
    published_report_unchanged && publish_stage_unchanged && [ -n "${OMEGA_MV:-}" ] || return 1
    "$OMEGA_MV" -n -- "$original_file" "$candidate" 2>/dev/null
    if [ ! -e "$original_file" ] && [ ! -L "$original_file" ]; then
      private_file_identity "$candidate" "$original_id" || return 1
      PUBLISHED_FILE="$candidate"
      PUBLISHED_ID="$PRIVATE_FILE_ID"
      break
    fi
    attempt=$((attempt+1))
    candidate="$evidence_base.$attempt"
  done
  [ "$PUBLISHED_FILE" != "$original_file" ] || return 1

  publish_stage_unchanged && published_report_unchanged && [ "$PUBLISH_STAGE_ID" = "$stage_id" ] || return 1
  "$OMEGA_MV" -f -- "$PUBLISH_STAGE" "$PUBLISHED_FILE" 2>/dev/null
  if [ ! -e "$PUBLISH_STAGE" ] && [ ! -L "$PUBLISH_STAGE" ] &&
     private_file_identity "$PUBLISHED_FILE" "$stage_id"; then
    PUBLISHED_ID="$PRIVATE_FILE_ID"
    PUBLISH_STAGE=""
    PUBLISH_STAGE_ID=""
    return 0
  fi
  return 1
}

remove_interrupted_publication() {
  local retained_path
  [ -n "$PUBLISHED_FILE" ] || return 0
  if published_report_unchanged && [ -n "${OMEGA_RM:-}" ] &&
     "$OMEGA_RM" -f -- "$PUBLISHED_FILE" 2>&"$ERROR_FD"; then
    PUBLISHED_FILE=""
    PUBLISHED_ID=""
    return 0
  fi
  promote_result 3
  if redesignate_interrupted_publication; then
    builtin printf -v retained_path '%q' "$PUBLISHED_FILE"
    echo "Interrupted report publication could not be removed; corrected failure evidence was retained: $retained_path" >&"$RESULT_FD"
  else
    builtin printf -v retained_path '%q' "$PUBLISHED_FILE"
    echo "Interrupted report publication could not be removed or redesignated safely: $retained_path" >&"$RESULT_FD"
  fi
  return 1
}

reconcile_pending_signal() {
  [ -n "$PENDING_SIGNAL" ] || return 0
  trap '' HUP INT TERM
  promote_result 2
  close_report_fd || promote_result 3
  if [ -n "$PUBLISHED_FILE" ]; then
    PUBLISH_STAGE=""
    PUBLISH_STAGE_ID=""
    remove_interrupted_publication || true
  fi
  cleanup_workspace || true
  cleanup_publish_stage || true
  emit_result_marker
  exit "$RESULT_CODE"
}

finish_result() {
  trap '' HUP INT TERM
  cleanup_workspace || true
  cleanup_publish_stage || true
  close_report_fd || promote_result 3
  emit_result_marker
  exit "$RESULT_CODE"
}

finish_without_report() {
  trap '' HUP INT TERM
  {
    echo "Ω OMEGA REPORT"
    echo "===================="
    echo
    echo "$1"
    echo
  } >&"$RESULT_FD"
  finish_result
}

single_line() {
  local value="$1"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  printf '%s' "$value"
}

valid_home_path() {
  safe_directory_tree "$1" user
}

cleanup() {
  local incoming=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [ "$RESULT_EMITTED" = false ]; then
    promote_result 3
    cleanup_workspace || true
    cleanup_publish_stage || true
    close_report_fd || promote_result 3
    emit_result_marker
  else
    close_telemetry_fd
    close_report_fd || true
  fi
  if [ "${ERROR_FD:-2}" != "2" ]; then
    { exec {ERROR_FD}>&-; } 2>/dev/null || true
    ERROR_FD=2
  fi
  if [ "${RESULT_FD:-1}" != "1" ]; then
    exec {RESULT_FD}>&- 2>/dev/null || true
    RESULT_FD=1
  fi
  exit "$RESULT_CODE"
}

handle_signal() {
  local signal_name="$1"
  trap '' HUP INT TERM
  [ -n "$PENDING_SIGNAL" ] || PENDING_SIGNAL="$signal_name"
  promote_result 2
  if [ "$FINALIZING" = true ]; then return 0; fi
  finish_without_report "Report generation interrupted before completion."
}
trap 'handle_signal HUP' HUP
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap cleanup EXIT
umask 077

if ! exec {RESULT_FD}>&1; then
  RESULT_FD=1
  promote_result 3
  finish_result
fi
if ! exec {ERROR_FD}>&2; then
  ERROR_FD=2
  promote_result 3
  finish_result
fi

OMEGA_STAT=$(resolve_trusted_command stat 2>/dev/null) || OMEGA_STAT=""
OMEGA_JQ=$(resolve_trusted_command jq 2>/dev/null) || OMEGA_JQ=""
OMEGA_DATE=$(resolve_trusted_command date 2>/dev/null) || OMEGA_DATE=""
OMEGA_HOSTNAME=$(resolve_trusted_command hostname 2>/dev/null) || OMEGA_HOSTNAME=""
OMEGA_MKDIR=$(resolve_trusted_command mkdir 2>/dev/null) || OMEGA_MKDIR=""
OMEGA_MKTEMP=$(resolve_trusted_command mktemp 2>/dev/null) || OMEGA_MKTEMP=""
OMEGA_MV=$(resolve_trusted_command mv 2>/dev/null) || OMEGA_MV=""
OMEGA_RM=$(resolve_trusted_command rm 2>/dev/null) || OMEGA_RM=""
OMEGA_SORT=$(resolve_trusted_command sort 2>/dev/null) || OMEGA_SORT=""
OMEGA_UNIQ=$(resolve_trusted_command uniq 2>/dev/null) || OMEGA_UNIQ=""
OMEGA_SED=$(resolve_trusted_command sed 2>/dev/null) || OMEGA_SED=""
OMEGA_TAIL=$(resolve_trusted_command tail 2>/dev/null) || OMEGA_TAIL=""

parse_aggregate() {
  local aggregate="$1"
  local pattern=$'^([0-9]+)\t([0-9]+)\t([0-9]+)\t([0-9]+)$'

  if [[ "$aggregate" =~ $pattern ]]; then
    EVENT_COUNT="${BASH_REMATCH[1]}"
    DNS_EVENTS="${BASH_REMATCH[2]}"
    TOTAL_ALERTS="${BASH_REMATCH[3]}"
    HIGH_ALERTS="${BASH_REMATCH[4]}"
    return 0
  fi
  return 1
}

aggregate_telemetry() {
  local input="$1"

  "$OMEGA_JQ" -Rrnc '
    def valid_alert($event):
      ($event.alert | type) == "object" and
      ($event.alert.signature | type) == "string" and
      ($event.alert.signature | length) > 0 and
      ($event.alert.severity | type) == "number" and
      $event.alert.severity >= 1 and
      $event.alert.severity == ($event.alert.severity | floor);
    reduce inputs as $line (
      {events: 0, dns: 0, alerts: 0, high: 0};
      ($line | fromjson) as $event |
      if ($event | type) != "object" then
        error("event record must be an object")
      elif $event.event_type == "alert" then
        if valid_alert($event) then
          .events += 1 |
          .alerts += 1 |
          if $event.alert.severity <= 2 then .high += 1 else . end
        else
          error("invalid alert record")
        end
      else
        .events += 1 |
        if $event.event_type == "dns" then .dns += 1 else . end
      end
    ) | [.events, .dns, .alerts, .high] | @tsv
  ' -- "$input"
}

normalize_telemetry() {
  "$OMEGA_JQ" -Rrc '
    def valid_alert($event):
      ($event.alert | type) == "object" and
      ($event.alert.signature | type) == "string" and
      ($event.alert.signature | length) > 0 and
      ($event.alert.severity | type) == "number" and
      $event.alert.severity >= 1 and
      $event.alert.severity == ($event.alert.severity | floor);
    (. | fromjson) as $event |
    if ($event | type) != "object" then
      error("event record must be an object")
    elif $event.event_type == "alert" then
      if valid_alert($event) then $event else error("invalid alert record") end
    else
      $event
    end
  ' <&"$TELEMETRY_FD"
}

publish_report() {
  local source="$1"
  local base="$2"
  local candidate="$base"
  local attempt=0

  while (( attempt < 100 )); do
    [ -n "$OMEGA_MV" ] && publish_stage_unchanged || return 1
    "$OMEGA_MV" -n -- "$source" "$candidate" 2>/dev/null
    if [ ! -e "$source" ]; then
      private_file_identity "$candidate" "$PUBLISH_STAGE_ID" || return 1
      PUBLISHED_FILE="$candidate"
      PUBLISHED_ID="$PRIVATE_FILE_ID"
      return 0
    fi
    attempt=$((attempt+1))
    candidate="$base.$attempt"
  done

  return 1
}

append_report() {
  report_temp_file_unchanged && printf '%s\n' "$@" >> "$TMP_REPORT" &&
    private_file_identity "$TMP_REPORT" "$TMP_REPORT_ID"
}

HOME_VALUE="$OMEGA_BOOTSTRAP_HOME_INPUT"
if ! valid_home_path "$HOME_VALUE"; then
  promote_result 3
  finish_without_report "Cannot determine report output directory because HOME is unset or invalid."
fi
HOME_ID="$SAFE_DIRECTORY_ID"

OUT_DIR="$HOME_VALUE/omega-reports/output"
if [ -z "$OMEGA_DATE" ]; then
  promote_result 3
  finish_without_report "Cannot locate the trusted date command."
fi
STAMP=$("$OMEGA_DATE" +"%Y-%m-%d_%H-%M-%S")
if [[ ! "$STAMP" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]]; then
  promote_result 3
  finish_without_report "Cannot generate a safe report timestamp."
fi
OUT_FILE="$OUT_DIR/omega-report-$STAMP.txt"

if ! home_unchanged; then
  promote_result 3
  finish_without_report "Report output path is invalid or contains a symbolic link."
fi

if [ -z "$OMEGA_MKDIR" ] || ! home_unchanged || ! "$OMEGA_MKDIR" -p -- "$OUT_DIR"; then
  promote_result 3
  finish_without_report "Cannot create report output directory: $OUT_DIR"
fi

if ! home_unchanged || ! safe_directory_tree "$OUT_DIR" user; then
  promote_result 3
  finish_without_report "Report output path became invalid or contains a symbolic link."
fi
OUT_DIR_ID="$SAFE_DIRECTORY_ID"

if [ -z "$OMEGA_MKTEMP" ] || ! output_directory_unchanged ||
   ! TMP_WORK=$("$OMEGA_MKTEMP" -d -- "$OUT_DIR/.omega-report-work.XXXXXX"); then
  promote_result 3
  finish_without_report "Cannot create a secure report workspace."
fi
if [[ "$TMP_WORK" != "$OUT_DIR"/.omega-report-work.* ]] || ! output_directory_unchanged ||
   ! safe_directory_tree "$TMP_WORK" user || ! private_directory_identity "$TMP_WORK" ""; then
  promote_result 3
  finish_without_report "The report workspace returned by mktemp is unsafe."
fi
TMP_WORK_ID="$PRIVATE_DIRECTORY_ID"

TMP_REPORT="$TMP_WORK/report.tmp"
PARSED_EVENTS="$TMP_WORK/events.jsonl"

if ! workspace_unchanged || ! {
  echo "Ω OMEGA REPORT"
  echo "===================="
  echo
  if [ -n "$OMEGA_HOSTNAME" ]; then DEVICE=$("$OMEGA_HOSTNAME" 2>/dev/null) || DEVICE="Unknown"; else DEVICE="Unknown"; fi
  GENERATED=$("$OMEGA_DATE" 2>/dev/null) || GENERATED="Unknown"
  echo "Device: $(single_line "$DEVICE")"
  echo "Generated: $(single_line "$GENERATED")"
  echo
} > "$TMP_REPORT"; then
  promote_result 3
  finish_without_report "Cannot initialize report output."
fi
if ! private_file_identity "$TMP_REPORT" ""; then
  promote_result 3
  finish_without_report "The report output file has unsafe metadata."
fi
TMP_REPORT_ID="$PRIVATE_FILE_ID"

REPORT_COMPLETE=true
EVENT_COUNT="Unknown"
DNS_EVENTS="Unknown"
TOTAL_ALERTS="Unknown"
HIGH_ALERTS="Unknown"

if [ -z "$OMEGA_STAT" ] || [ -z "$OMEGA_JQ" ]; then
  if ! append_report "Cannot generate report: jq not found."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
  promote_result 2
  REPORT_COMPLETE=false
elif ! load_omega_config; then
  if ! append_report "Cannot generate report: configuration is invalid, unavailable, or changed during validation."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
  promote_result 2
  REPORT_COMPLETE=false
elif ! open_telemetry; then
  if ! append_report "Cannot generate report: configured input is missing, unreadable, symbolic, or not a regular file."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
  promote_result 2
  REPORT_COMPLETE=false
else
  NORMALIZE_OK=true
  PATH_STABLE=true
  if ! workspace_unchanged || ! normalize_telemetry > "$PARSED_EVENTS" 2>/dev/null ||
     ! private_file_identity "$PARSED_EVENTS" ""; then
    NORMALIZE_OK=false
  else
    PARSED_EVENTS_ID="$PRIVATE_FILE_ID"
  fi
  telemetry_path_unchanged || PATH_STABLE=false
  close_telemetry_fd
if [ "$NORMALIZE_OK" = false ]; then
  if ! append_report "Cannot generate report: input is unreadable, malformed, or contains an invalid alert record."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
  promote_result 2
  REPORT_COMPLETE=false
elif [ "$PATH_STABLE" = false ]; then
  if ! append_report "Cannot generate report: the configured input disappeared or was replaced during processing."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
  promote_result 2
  REPORT_COMPLETE=false
elif ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
     ! AGGREGATE=$(aggregate_telemetry "$PARSED_EVENTS" 2>/dev/null) || ! parse_aggregate "$AGGREGATE"; then
  if ! append_report "Cannot generate report: validated telemetry could not be aggregated."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
  promote_result 2
  REPORT_COMPLETE=false
elif [ "$EVENT_COUNT" = "0" ]; then
  promote_result 1
  if ! append_report "Suricata telemetry is empty; alert safety cannot be determined."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
else
  if [ "$HIGH_ALERTS" != "0" ]; then
    promote_result 1
  fi
  if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
     ! "$OMEGA_JQ" -r '(.event_type // "unknown") | @json' -- "$PARSED_EVENTS" > "$TMP_WORK/event-types" 2>/dev/null ||
     ! private_file_identity "$TMP_WORK/event-types" ""; then
    if ! append_report "Cannot generate report: verified telemetry could not be summarized."; then
      promote_result 3
      finish_without_report "Cannot write report output."
    fi
    promote_result 2
    REPORT_COMPLETE=false
  else
    EVENT_TYPES_ID="$PRIVATE_FILE_ID"
    if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
       ! "$OMEGA_JQ" -r 'select(.event_type == "dns" and (.dns.rrname | type) == "string") | .dns.rrname | @json' -- "$PARSED_EVENTS" > "$TMP_WORK/dns" 2>/dev/null ||
       ! private_file_identity "$TMP_WORK/dns" ""; then
      promote_result 2
      REPORT_COMPLETE=false
    else
      DNS_ID="$PRIVATE_FILE_ID"
    fi
    if [ "$REPORT_COMPLETE" = true ] &&
       { ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
         ! "$OMEGA_JQ" -r 'select(.event_type == "alert") | "\((.timestamp // "unknown") | @json) | \((.src_ip // "unknown") | @json) -> \((.dest_ip // "unknown") | @json) | \(.alert.signature | @json)"' -- "$PARSED_EVENTS" > "$TMP_WORK/alerts" 2>/dev/null ||
         ! private_file_identity "$TMP_WORK/alerts" ""; }; then
      promote_result 2
      REPORT_COMPLETE=false
    else
      ALERTS_ID="$PRIVATE_FILE_ID"
    fi
    if [ "$REPORT_COMPLETE" = true ] &&
       { ! report_temp_file_unchanged || ! workspace_unchanged ||
         ! private_file_identity "$TMP_WORK/event-types" "$EVENT_TYPES_ID" ||
         ! private_file_identity "$TMP_WORK/dns" "$DNS_ID" ||
         ! private_file_identity "$TMP_WORK/alerts" "$ALERTS_ID"; }; then
      promote_result 2
      REPORT_COMPLETE=false
    elif ! {
      echo "Suricata Totals"
      echo "--------------------"
      echo "Telemetry records: $EVENT_COUNT"
      echo "DNS events: $DNS_EVENTS"
      echo "Alerts: $TOTAL_ALERTS"
      echo "Higher-priority alerts: $HIGH_ALERTS"
      echo

      echo "Suricata Event Summary"
      echo "--------------------"
      if [ -z "$OMEGA_SORT" ] || [ -z "$OMEGA_UNIQ" ] || [ -z "$OMEGA_SED" ] ||
         ! "$OMEGA_SORT" -- "$TMP_WORK/event-types" | "$OMEGA_UNIQ" -c | "$OMEGA_SORT" -nr | "$OMEGA_SED" -n '1,20p'; then
        echo "Unable to format the event summary."
        promote_result 2
        REPORT_COMPLETE=false
      fi
      echo

      echo "Recent DNS Queries"
      echo "--------------------"
      if [ -z "$OMEGA_TAIL" ] || ! "$OMEGA_TAIL" -n 20 -- "$TMP_WORK/dns"; then
        echo "Unable to format recent DNS queries."
        promote_result 2
        REPORT_COMPLETE=false
      fi
      echo

      echo "Recent Alerts"
      echo "--------------------"
      if [ -z "$OMEGA_TAIL" ] || ! "$OMEGA_TAIL" -n 10 -- "$TMP_WORK/alerts"; then
        echo "Unable to format recent alerts."
        promote_result 2
        REPORT_COMPLETE=false
      fi
      echo
    } >> "$TMP_REPORT" || ! private_file_identity "$TMP_REPORT" "$TMP_REPORT_ID"; then
      promote_result 3
      finish_without_report "Cannot write report output."
    fi
  fi
fi
fi

if [ "$REPORT_COMPLETE" = true ]; then
  if [ "$EVENT_COUNT" = "0" ]; then
    if ! append_report "Report complete with a warning: no telemetry records were available."; then
      promote_result 3
      finish_without_report "Cannot write report output."
    fi
  else
    if ! append_report "Report complete."; then
      promote_result 3
      finish_without_report "Cannot write report output."
    fi
  fi
else
  promote_result 2
  if ! append_report "Report incomplete. Security telemetry could not be evaluated reliably."; then
    promote_result 3
    finish_without_report "Cannot write report output."
  fi
fi

FINALIZING=true
if ! report_temp_file_unchanged || ! exec {REPORT_FD}< "$TMP_REPORT" ||
   ! private_file_descriptor_identity "$REPORT_FD" "$TMP_REPORT_ID" ||
   ! report_temp_file_unchanged; then
  promote_result 3
  finish_without_report "Cannot open finalized report output for stable display."
fi
reconcile_pending_signal
if ! report_temp_file_unchanged || ! exec {COPY_FD}< "$TMP_REPORT" ||
   ! private_file_descriptor_identity "$COPY_FD" "$TMP_REPORT_ID" ||
   ! report_temp_file_unchanged; then
  promote_result 3
  finish_without_report "Cannot open finalized report output for publication."
fi
reconcile_pending_signal

if [ -z "$OMEGA_SED" ] || ! "$OMEGA_SED" -n 'p' <&"$REPORT_FD"; then
  echo "Report output could not be displayed completely." >&"$RESULT_FD"
  promote_result 3
fi
close_display_fd || promote_result 3
reconcile_pending_signal

STAGE_CANDIDATE=""
if [ -n "$OMEGA_MKTEMP" ]; then
  STAGE_CANDIDATE=$("$OMEGA_MKTEMP" -- "$OUT_DIR/.omega-report-stage.XXXXXX" 2>&"$ERROR_FD") || STAGE_CANDIDATE=""
fi
if [[ "$STAGE_CANDIDATE" != "$OUT_DIR"/.omega-report-stage.* ]] ||
   ! output_directory_unchanged || ! private_file_identity "$STAGE_CANDIDATE" ""; then
  builtin printf -v retained_path '%q' "$STAGE_CANDIDATE"
  [ -z "$STAGE_CANDIDATE" ] || echo "An unsafe publication-stage path was rejected: $retained_path" >&"$RESULT_FD"
  promote_result 3
  finish_result
fi
PUBLISH_STAGE="$STAGE_CANDIDATE"
PUBLISH_STAGE_ID="$PRIVATE_FILE_ID"
if ! publish_stage_unchanged || ! exec {STAGE_FD}>> "$PUBLISH_STAGE" ||
   ! private_file_descriptor_identity "$STAGE_FD" "$PUBLISH_STAGE_ID" ||
   ! publish_stage_unchanged; then
  promote_result 3
  finish_without_report "Cannot open a stable publication-stage descriptor."
fi
reconcile_pending_signal
COPY_OK=true
while IFS= read -r report_line <&"$COPY_FD" || [ -n "$report_line" ]; do
  builtin printf '%s\n' "$report_line" >&"$STAGE_FD" || { COPY_OK=false; break; }
done
close_copy_fd || COPY_OK=false
if [ "$COPY_OK" = false ] || ! private_file_descriptor_identity "$STAGE_FD" "$PUBLISH_STAGE_ID" ||
   ! publish_stage_unchanged; then
  echo "Cannot copy finalized report output into the publication stage." >&"$RESULT_FD"
  promote_result 3
  finish_result
fi
reconcile_pending_signal

cleanup_workspace || true
reconcile_pending_signal

REPORT_RESULT=$(result_name)
if ! builtin printf '\nOMEGA_RESULT=%s\n' "$REPORT_RESULT" >&"$STAGE_FD" ||
   ! private_file_descriptor_identity "$STAGE_FD" "$PUBLISH_STAGE_ID" ||
   ! publish_stage_unchanged || ! close_stage_fd; then
  promote_result 3
  finish_without_report "Cannot finalize report output."
fi
reconcile_pending_signal

if [ "$REPORT_COMPLETE" = true ]; then
  PUBLISH_TARGET="$OUT_FILE"
else
  PUBLISH_TARGET="$OUT_FILE.incomplete"
fi

if ! publish_report "$PUBLISH_STAGE" "$PUBLISH_TARGET"; then
  promote_result 3
  finish_without_report "Cannot atomically publish the report. No existing report was replaced."
fi
reconcile_pending_signal
PUBLISH_STAGE=""
PUBLISH_STAGE_ID=""
trap '' HUP INT TERM
reconcile_pending_signal
echo "Saved report:"
echo "$PUBLISHED_FILE"
echo
finish_result
