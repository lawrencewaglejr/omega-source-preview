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
omega_bootstrap_home=
omega_bootstrap_tmpdir=${TMPDIR-}
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
TEMP_BASE_ID=""
TMP_WORK_ID=""
PARSED_EVENTS_ID=""
SIGNATURES_ID=""
RECENT_ID=""
NOISE_ID=""
HIGH_ID=""
CLEANUP_ATTEMPTED=false
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

single_line() {
  local value="$1"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  printf '%s' "$value"
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
  [[ "$type" = directory && "$uid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ &&
     "$dev" =~ ^[0-9]+$ && "$ino" =~ ^[0-9]+$ && "$uid" = 0 ]] || return 1
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

temporary_base_unchanged() {
  safe_directory_tree "$TEMP_BASE" any && [ "$SAFE_DIRECTORY_ID" = "$TEMP_BASE_ID" ]
}

workspace_unchanged() {
  [ -n "$TMP_WORK_ID" ] && temporary_base_unchanged &&
    private_directory_identity "$TMP_WORK" "$TMP_WORK_ID"
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
      echo "Alert triage temporary-workspace cleanup failed; evidence was retained: $retained_path" >&"$RESULT_FD"
      promote_result 3
      return 1
    fi
  fi
  return 0
}

finish_result() {
  trap '' HUP INT TERM
  cleanup_workspace || true
  emit_result_marker
  exit "$RESULT_CODE"
}

cleanup() {
  local incoming=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [ "$RESULT_EMITTED" = false ]; then
    promote_result 3
    cleanup_workspace || true
    emit_result_marker
  else
    close_telemetry_fd
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
  trap '' HUP INT TERM
  echo "Alert triage interrupted before completion." >&"$RESULT_FD"
  promote_result 2
  finish_result
}
trap handle_signal HUP INT TERM
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
OMEGA_HOSTNAME=$(resolve_trusted_command hostname 2>/dev/null) || OMEGA_HOSTNAME=""
OMEGA_DATE=$(resolve_trusted_command date 2>/dev/null) || OMEGA_DATE=""
OMEGA_MKTEMP=$(resolve_trusted_command mktemp 2>/dev/null) || OMEGA_MKTEMP=""
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

echo "Ω OMEGA ALERT TRIAGE"
echo "===================="
echo

if [ -z "$OMEGA_STAT" ] || [ -z "$OMEGA_JQ" ]; then
  echo "Cannot evaluate alerts: jq not found."
  promote_result 2
  finish_result
fi

if ! load_omega_config; then
  echo "Cannot evaluate alerts: configuration is invalid, unavailable, or changed during validation."
  promote_result 2
  finish_result
fi

if [ -n "$OMEGA_HOSTNAME" ]; then DEVICE=$("$OMEGA_HOSTNAME" 2>/dev/null) || DEVICE="Unknown"; else DEVICE="Unknown"; fi
if [ -n "$OMEGA_DATE" ]; then GENERATED=$("$OMEGA_DATE" 2>/dev/null) || GENERATED="Unknown"; else GENERATED="Unknown"; fi
echo "Device: $(single_line "$DEVICE")"
echo "Generated: $(single_line "$GENERATED")"
echo

TEMP_BASE="${OMEGA_BOOTSTRAP_TMPDIR_INPUT:-/tmp}"
if [ -z "$OMEGA_MKTEMP" ] || ! safe_directory_tree "$TEMP_BASE" any; then
  echo "Cannot use the configured temporary directory safely."
  promote_result 3
  finish_result
fi
TEMP_BASE_ID="$SAFE_DIRECTORY_ID"
if ! temporary_base_unchanged ||
   ! TMP_WORK=$("$OMEGA_MKTEMP" -d -- "$TEMP_BASE/omega-alerts.XXXXXX"); then
  echo "Cannot create a secure temporary workspace."
  promote_result 3
  finish_result
fi
if [[ "$TMP_WORK" != "$TEMP_BASE"/omega-alerts.* ]] || ! temporary_base_unchanged ||
   ! safe_directory_tree "$TMP_WORK" user || ! private_directory_identity "$TMP_WORK" ""; then
  echo "The temporary workspace returned by mktemp is unsafe."
  promote_result 3
  finish_result
fi
TMP_WORK_ID="$PRIVATE_DIRECTORY_ID"

PARSED_EVENTS="$TMP_WORK/events.jsonl"
if ! open_telemetry; then
  echo "Alert triage is unknown: configured input is missing, unreadable, symbolic, or not a regular file."
  promote_result 2
  finish_result
fi

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
  echo "Alert triage is unknown: input is unreadable, malformed, or contains an invalid alert record."
  promote_result 2
  finish_result
elif [ "$PATH_STABLE" = false ]; then
  echo "Alert triage is unknown: the configured input disappeared or was replaced during processing."
  promote_result 2
  finish_result
fi

if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
   ! AGGREGATE=$(aggregate_telemetry "$PARSED_EVENTS" 2>/dev/null) || ! parse_aggregate "$AGGREGATE"; then
  echo "Alert triage is unknown: validated telemetry could not be aggregated."
  promote_result 2
  finish_result
fi

if [ "$EVENT_COUNT" = "0" ]; then
  echo "Suricata telemetry is empty; alert safety cannot be determined."
  promote_result 1
  echo
  echo "Alert triage complete."
  finish_result
fi

if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
   ! "$OMEGA_JQ" -r 'select(.event_type == "alert") | .alert.signature | @json' -- "$PARSED_EVENTS" > "$TMP_WORK/signatures" 2>/dev/null ||
   ! private_file_identity "$TMP_WORK/signatures" ""; then
  echo "Alert triage is unknown: parsed data could not be evaluated."
  promote_result 2
  finish_result
fi
SIGNATURES_ID="$PRIVATE_FILE_ID"
if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
   ! "$OMEGA_JQ" -r 'select(.event_type == "alert") | "\((.timestamp // "unknown") | @json) | severity=\(.alert.severity) | \((.src_ip // "unknown") | @json) -> \((.dest_ip // "unknown") | @json) | \(.alert.signature | @json)"' -- "$PARSED_EVENTS" > "$TMP_WORK/recent" 2>/dev/null ||
   ! private_file_identity "$TMP_WORK/recent" ""; then
  echo "Alert triage is unknown: parsed data could not be evaluated."
  promote_result 2
  finish_result
fi
RECENT_ID="$PRIVATE_FILE_ID"
if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
   ! "$OMEGA_JQ" -r 'select(.event_type == "alert" and (.alert.signature | test("STUN|NAT|INFO|IPv6|ICMP"; "i"))) | .alert.signature | @json' -- "$PARSED_EVENTS" > "$TMP_WORK/noise" 2>/dev/null ||
   ! private_file_identity "$TMP_WORK/noise" ""; then
  echo "Alert triage is unknown: parsed data could not be evaluated."
  promote_result 2
  finish_result
fi
NOISE_ID="$PRIVATE_FILE_ID"
if ! workspace_unchanged || ! private_file_identity "$PARSED_EVENTS" "$PARSED_EVENTS_ID" ||
   ! "$OMEGA_JQ" -r 'select(.event_type == "alert" and .alert.severity <= 2) | "\((.timestamp // "unknown") | @json) | severity=\(.alert.severity) | \((.src_ip // "unknown") | @json) -> \((.dest_ip // "unknown") | @json) | \(.alert.signature | @json)"' -- "$PARSED_EVENTS" > "$TMP_WORK/high" 2>/dev/null ||
   ! private_file_identity "$TMP_WORK/high" ""; then
  echo "Alert triage is unknown: parsed data could not be evaluated."
  promote_result 2
  finish_result
fi
HIGH_ID="$PRIVATE_FILE_ID"

echo "Top Alert Signatures"
echo "--------------------"
if ! workspace_unchanged || ! private_file_identity "$TMP_WORK/signatures" "$SIGNATURES_ID" ||
   [ -z "$OMEGA_SORT" ] || [ -z "$OMEGA_UNIQ" ] || [ -z "$OMEGA_SED" ] ||
   ! "$OMEGA_SORT" -- "$TMP_WORK/signatures" | "$OMEGA_UNIQ" -c | "$OMEGA_SORT" -nr | "$OMEGA_SED" -n '1,20p'; then
  echo "Unable to format top alert signatures."
  promote_result 3
fi
echo

echo "Recent Alerts"
echo "--------------------"
if ! workspace_unchanged || ! private_file_identity "$TMP_WORK/recent" "$RECENT_ID" ||
   [ -z "$OMEGA_TAIL" ] || ! "$OMEGA_TAIL" -n 20 -- "$TMP_WORK/recent"; then
  echo "Unable to format recent alerts."
  promote_result 3
fi
echo

echo "Possible Noise / Informational"
echo "--------------------"
if ! workspace_unchanged || ! private_file_identity "$TMP_WORK/noise" "$NOISE_ID" ||
   [ -z "$OMEGA_SORT" ] || [ -z "$OMEGA_UNIQ" ] || [ -z "$OMEGA_SED" ] ||
   ! "$OMEGA_SORT" -- "$TMP_WORK/noise" | "$OMEGA_UNIQ" -c | "$OMEGA_SORT" -nr | "$OMEGA_SED" -n '1,20p'; then
  echo "Unable to format informational alerts."
  promote_result 3
fi
echo

echo "Higher Priority Alerts"
echo "--------------------"
if ! workspace_unchanged || ! private_file_identity "$TMP_WORK/high" "$HIGH_ID" ||
   [ -z "$OMEGA_TAIL" ] || ! "$OMEGA_TAIL" -n 20 -- "$TMP_WORK/high"; then
  echo "Unable to format higher-priority alerts."
  promote_result 3
fi
echo

if [ "$HIGH_ALERTS" != "0" ]; then
  promote_result 1
  echo "Higher-priority alerts detected: $HIGH_ALERTS"
else
  echo "No higher-priority alerts detected in the fully parsed current log."
fi
echo
echo "Alert triage complete."

finish_result
