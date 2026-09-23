#!/bin/sh

if [ -n "${BASH_VERSION-}" ]; then
  printf 'ISOLATION_REJECT\tbootstrap\tunsupported-public-bash\n' >&2
  exit 125
fi
[ "$#" -eq 0 ] || {
  printf 'ISOLATION_REJECT\tbootstrap\tpublic-arguments\n' >&2
  exit 125
}
omega_posix_sigint_state() {
  omega_sigint_mask=
  while IFS=: read -r omega_sigint_key omega_sigint_value; do
    if [ "$omega_sigint_key" = SigIgn ]; then
      set -- $omega_sigint_value
      [ "$#" -eq 1 ] || return 2
      omega_sigint_mask=$1
      break
    fi
  done < /proc/self/status || return 2
  case "$omega_sigint_mask" in ''|*[!0-9A-Fa-f]*) return 2 ;; esac
  omega_sigint_low=${omega_sigint_mask#${omega_sigint_mask%?}}
  case "$omega_sigint_low" in 2|3|6|7|A|B|E|F|a|b|e|f) return 1 ;; esac
  return 0
}
omega_posix_sigint_state
omega_sigint_status=$?
case "$omega_sigint_status" in
  0) ;;
  1) printf 'ISOLATION_REJECT\tbootstrap\tsigint-ignored\n' >&2; exit 125 ;;
  *) printf 'ISOLATION_REJECT\tbootstrap\tsignal-state-unreadable\n' >&2; exit 125 ;;
esac
CDPATH=
case "$0" in /*) harness_path="$0" ;; *) harness_path="$(pwd -P)/$0" ;; esac
host_repo=$(CDPATH= cd -P "${harness_path%/*}/.." 2>/dev/null && pwd -P) || exit 125
exec 3< "$host_repo/tests/test-security-results.sh" || exit 125
stage_found=false
while IFS= read -r stage_line <&3; do
  if [ "$stage_line" = '# OMEGA_BASH_STAGE_BEGIN' ]; then stage_found=true; break; fi
done
[ "$stage_found" = true ] || exit 125
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
  /bin/bash --noprofile --norc -s -- clean "$host_repo" <&3
exit 125

# OMEGA_BASH_STAGE_BEGIN
[ -n "${BASH_VERSION:-}" ] || {
  printf 'ISOLATION_REJECT\tbootstrap\tbash-required\n' >&2
  exit 125
}

set -uo pipefail

STAGE_TOKEN="${1-}"
BODY_REPO_ROOT="${2-}"
shift 2 2>/dev/null || exit 125

isolation_error() {
  local class="$1" reason="${2:-$1}"
  printf 'ISOLATION_REJECT\t%s\t%s\n' "$class" "$reason" >&2
  exit 125
}

fd_identity=$(/usr/bin/stat -Lc '%d:%i' -- /proc/self/fd/0 2>/dev/null) || isolation_error bootstrap unsupported-invocation
source_identity=$(/usr/bin/stat -Lc '%d:%i' -- "$BODY_REPO_ROOT/tests/test-security-results.sh" 2>/dev/null) || isolation_error bootstrap unsupported-invocation
[ "$fd_identity" = "$source_identity" ] || isolation_error bootstrap unsupported-invocation

if [ "$STAGE_TOKEN" = clean ]; then
  [ "$#" -eq 0 ] && [ -z "${BASH_ENV+x}" ] && [ -z "${ENV+x}" ] &&
    [ "$PATH" = /usr/bin:/bin ] && [ "$LC_ALL" = C ] || isolation_error bootstrap inherited-environment
  HOST_REPO_ROOT="$BODY_REPO_ROOT"
  [[ "$HOST_REPO_ROOT" == /* ]] && [ -d "$HOST_REPO_ROOT" ] || isolation_error bootstrap repository-root
  for tool in /usr/bin/unshare /usr/bin/bwrap /usr/bin/env /usr/bin/readlink /usr/bin/ln /usr/bin/mawk \
    /usr/bin/mkdir /usr/bin/rm /usr/bin/sed /usr/bin/touch /usr/bin/id /usr/bin/stat /usr/bin/chmod \
    /usr/bin/cp /usr/bin/cmp /usr/bin/timeout; do
    [ -f "$tool" ] && [ -x "$tool" ] && [ ! -L "$tool" ] || isolation_error bootstrap "boundary-tool:$tool"
  done
  HOST_MNT_NS=$(/usr/bin/readlink /proc/self/ns/mnt) || isolation_error bootstrap host-mount-namespace
  HOST_NET_NS=$(/usr/bin/readlink /proc/self/ns/net) || isolation_error bootstrap host-network-namespace
  HOST_PID_NS=$(/usr/bin/readlink /proc/self/ns/pid) || isolation_error bootstrap host-pid-namespace
  HOST_USER_NS=$(/usr/bin/readlink /proc/self/ns/user) || isolation_error bootstrap host-user-namespace
  exec 4< "$HOST_REPO_ROOT/tests/test-security-results.sh" || isolation_error bootstrap harness-descriptor
  stage_found=false
  while IFS= read -r stage_line <&4; do
    if [ "$stage_line" = '# OMEGA_BASH_STAGE_BEGIN' ]; then stage_found=true; break; fi
  done
  [ "$stage_found" = true ] || isolation_error bootstrap harness-descriptor
  exec /usr/bin/unshare --user --map-root-user --net \
    /usr/bin/bwrap --unshare-pid --unshare-ipc --unshare-uts --die-with-parent --new-session --cap-drop ALL \
    --dir /host-usr --ro-bind /usr /host-usr --tmpfs /usr \
    --symlink /host-usr/bin /usr/bin --symlink /host-usr/sbin /usr/sbin \
    --symlink /host-usr/bin /bin --symlink /host-usr/lib /lib --symlink /host-usr/lib64 /lib64 \
    --dir /usr/local --dir /usr/local/bin --dir /usr/local/sbin --dir /usr/local/libexec \
    --proc /proc --dev /dev --tmpfs /tmp --tmpfs /etc --dir /etc/alternatives \
    --symlink /usr/bin/mawk /etc/alternatives/awk --dir /etc/omega \
    --tmpfs /var --dir /var/log --dir /var/log/suricata \
    --dir /repo --ro-bind "$HOST_REPO_ROOT" /repo --chdir /repo --clearenv \
    --setenv PATH /usr/bin:/bin --setenv LC_ALL C \
    /bin/bash --noprofile --norc -s -- supervisor /repo \
    "$HOST_MNT_NS" "$HOST_NET_NS" "$HOST_PID_NS" "$HOST_USER_NS" <&4
  isolation_error bootstrap namespace-establishment
fi

case "$STAGE_TOKEN" in supervisor|signals|tests) ;; *) isolation_error bootstrap unsupported-invocation ;; esac
[ "$#" -eq 4 ] || isolation_error bootstrap namespace-reference-count
FORBIDDEN_MNT_NS="$1" FORBIDDEN_NET_NS="$2" FORBIDDEN_PID_NS="$3" FORBIDDEN_USER_NS="$4"
shift 4

validate_private_mount() {
  local target="$1" expected_fs="$2" require_ro="$3" mount_line found=false
  local -a fields
  while IFS= read -r mount_line; do
    read -r -a fields <<< "$mount_line"
    [ "${fields[4]:-}" = "$target" ] || continue
    [[ " $mount_line " == *" - $expected_fs "* ]] || return 1
    if [ "$require_ro" = true ]; then
      [[ ",${fields[5]:-}," == *,ro,* ]] || return 1
    fi
    found=true
  done < /proc/self/mountinfo
  [ "$found" = true ]
}

validate_isolation() {
  local class="$1" self_mnt self_net self_pid self_user cap_eff="" cap_prm="" cap_amb="" no_new_privs=""
  local uid_inside uid_outside uid_length route_iface route_rest process_path process_count=0
  [[ "$FORBIDDEN_MNT_NS" =~ ^mnt:\[[0-9]+\]$ && "$FORBIDDEN_NET_NS" =~ ^net:\[[0-9]+\]$ &&
     "$FORBIDDEN_PID_NS" =~ ^pid:\[[0-9]+\]$ && "$FORBIDDEN_USER_NS" =~ ^user:\[[0-9]+\]$ ]] ||
    isolation_error "$class" invalid-namespace-reference
  self_mnt=$(/usr/bin/readlink /proc/self/ns/mnt) || isolation_error "$class" mount-namespace-unreadable
  self_net=$(/usr/bin/readlink /proc/self/ns/net) || isolation_error "$class" network-namespace-unreadable
  self_pid=$(/usr/bin/readlink /proc/self/ns/pid) || isolation_error "$class" pid-namespace-unreadable
  self_user=$(/usr/bin/readlink /proc/self/ns/user) || isolation_error "$class" user-namespace-unreadable
  [ "$self_mnt" != "$FORBIDDEN_MNT_NS" ] || isolation_error "$class" mount-namespace-not-private
  [ "$self_net" != "$FORBIDDEN_NET_NS" ] || isolation_error "$class" network-namespace-not-private
  [ "$self_pid" != "$FORBIDDEN_PID_NS" ] || isolation_error "$class" pid-namespace-not-private
  [ "$self_user" != "$FORBIDDEN_USER_NS" ] || isolation_error "$class" user-namespace-not-private
  [ "$(/usr/bin/id -u)" = 0 ] || isolation_error "$class" namespace-uid
  read -r uid_inside uid_outside uid_length < /proc/self/uid_map || isolation_error "$class" uid-map-unreadable
  [ "$uid_inside" = 0 ] && [ "$uid_length" = 1 ] || isolation_error "$class" uid-map-invalid
  while read -r key value _; do
    case "$key" in
      CapEff:) cap_eff="$value" ;; CapPrm:) cap_prm="$value" ;; CapAmb:) cap_amb="$value" ;;
      NoNewPrivs:) no_new_privs="$value" ;;
    esac
  done < /proc/self/status
  [ "$cap_eff" = 0000000000000000 ] && [ "$cap_prm" = 0000000000000000 ] &&
    [ "$cap_amb" = 0000000000000000 ] && [ "$no_new_privs" = 1 ] ||
    isolation_error "$class" capabilities-not-dropped
  validate_private_mount /etc tmpfs false || isolation_error "$class" etc-not-private
  validate_private_mount /var tmpfs false || isolation_error "$class" var-not-private
  validate_private_mount /tmp tmpfs false || isolation_error "$class" tmp-not-private
  repo_mount=false
  while IFS= read -r mount_line; do
    read -r -a fields <<< "$mount_line"
    if [ "${fields[4]:-}" = /repo ] && [[ ",${fields[5]:-}," == *,ro,* ]]; then repo_mount=true; fi
  done < /proc/self/mountinfo
  [ "$repo_mount" = true ] || isolation_error "$class" repository-not-read-only
  [ -d /etc/omega ] && [ -d /var/log/suricata ] && [ ! -e /etc/passwd ] && [ ! -e /var/lib ] ||
    isolation_error "$class" host-canonical-path-visible
  while read -r route_iface route_rest; do
    [ "$route_iface" = Iface ] || isolation_error "$class" network-route-visible
  done < /proc/net/route
  for process_path in /proc/[0-9]*; do process_count=$((process_count+1)); done
  (( process_count > 0 && process_count <= 6 )) || isolation_error "$class" pid-namespace-not-private
  [ -f /repo/tests/test-security-results.sh ] || isolation_error "$class" repository-not-visible
}

if [ "$STAGE_TOKEN" = supervisor ]; then
  validate_isolation supervisor-invariant
  hostile_startup=/tmp/omega-hostile-bash-env
  hostile_startup_sentinel=/tmp/omega-hostile-bash-env.executed
  printf '/usr/bin/touch /tmp/omega-hostile-bash-env.executed\nexport OMEGA_HARNESS_STAGE=clean\n' > "$hostile_startup" ||
    isolation_error bootstrap-regression hostile-startup-setup
  bootstrap_output=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C BASH_ENV="$hostile_startup" \
    /bin/bash /repo/tests/test-security-results.sh 3<&- 2>&1)
  bootstrap_code=$?
  [ "$bootstrap_code" -eq 125 ] && [ -f "$hostile_startup_sentinel" ] &&
    [[ "$bootstrap_output" == *$'ISOLATION_REJECT\tbootstrap\tunsupported-public-bash'* ]] &&
    [[ "$bootstrap_output" != *'tests passed'* ]] || isolation_error bootstrap-regression public-bash-refusal
  valid_fd_output=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C BASH_ENV="$hostile_startup" OMEGA_HARNESS_STAGE=clean \
    /bin/bash /repo/tests/test-security-results.sh clean /repo 3</repo/tests/test-security-results.sh 2>&1)
  valid_fd_code=$?
  [ "$valid_fd_code" -eq 125 ] &&
    [[ "$valid_fd_output" == *$'ISOLATION_REJECT\tbootstrap\tunsupported-public-bash'* ]] &&
    [[ "$valid_fd_output" != *'tests passed'* ]] || isolation_error bootstrap-regression public-bash-valid-fd-refusal
  /usr/bin/rm -f -- "$hostile_startup" "$hostile_startup_sentinel" ||
    isolation_error bootstrap-regression hostile-startup-cleanup
  echo "BOOTSTRAP PASS: direct Bash invocation is refused after inherited BASH_ENV processing"

  async_stdout=/tmp/omega-async-sigint.stdout
  async_stderr=/tmp/omega-async-sigint.stderr
  async_pid_file=/tmp/omega-async-sigint.pid
  async_status_file=/tmp/omega-async-sigint.status
  /usr/bin/rm -f -- "$async_stdout" "$async_stderr" "$async_pid_file" "$async_status_file" ||
    isolation_error bootstrap-regression async-sigint-cleanup
  /usr/bin/timeout -s TERM -k 1 5 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /bin/bash --noprofile --norc -c '
      "$1" > "$2" 2> "$3" &
      child=$!
      printf "%s\n" "$child" > "$4"
      wait "$child"
      printf "%s\n" "$?" > "$5"
    ' omega-async-sigint /repo/tests/test-security-results.sh "$async_stdout" "$async_stderr" \
      "$async_pid_file" "$async_status_file" ||
    isolation_error bootstrap-regression async-sigint-timeout
  [ -s "$async_pid_file" ] && [ -s "$async_status_file" ] ||
    isolation_error bootstrap-regression async-sigint-result
  read -r async_pid < "$async_pid_file" || isolation_error bootstrap-regression async-sigint-pid
  read -r async_status < "$async_status_file" || isolation_error bootstrap-regression async-sigint-status
  [[ "$async_pid" =~ ^[0-9]+$ ]] && [ "$async_status" -eq 125 ] && [ ! -e "/proc/$async_pid" ] ||
    isolation_error bootstrap-regression "async-sigint-process:$async_pid:$async_status"
  [ ! -s "$async_stdout" ] &&
    [ "$(<"$async_stderr")" = $'ISOLATION_REJECT\tbootstrap\tsigint-ignored' ] &&
    ! /usr/bin/grep -Eq '^(Tests passed:|Isolation gate: PASS)' "$async_stdout" "$async_stderr" ||
    isolation_error bootstrap-regression async-sigint-output
  /usr/bin/rm -f -- "$async_stdout" "$async_stderr" "$async_pid_file" "$async_status_file" ||
    isolation_error bootstrap-regression async-sigint-final-cleanup
  echo "BOOTSTRAP PASS: asynchronous public launch rejects inherited ignored SIGINT without recursion"

  for public_control in --omega-clean-bootstrap-v1 --omega-isolated-supervisor-v1 --omega-isolated-tests-v1 \
    --bootstrap-probe --guard-only --prewrite-probe --internal-stage clean supervisor signals tests; do
    public_output=$(/repo/tests/test-security-results.sh "$public_control" 2>&1)
    public_code=$?
    [ "$public_code" -eq 125 ] &&
      [ "$public_output" = $'ISOLATION_REJECT\tbootstrap\tpublic-arguments' ] ||
      isolation_error bootstrap-regression "public-control:$public_control"
  done
  echo "BOOTSTRAP PASS: all public arguments are refused before internal dispatch"
  forged_sentinel=/tmp/omega-forged-stage-sentinel
  self_mnt=$(/usr/bin/readlink /proc/self/ns/mnt)
  self_net=$(/usr/bin/readlink /proc/self/ns/net)
  self_pid=$(/usr/bin/readlink /proc/self/ns/pid)
  self_user=$(/usr/bin/readlink /proc/self/ns/user)
  exec 5< /repo/tests/test-security-results.sh || isolation_error bootstrap-regression forged-descriptor
  stage_found=false
  while IFS= read -r stage_line <&5; do
    if [ "$stage_line" = '# OMEGA_BASH_STAGE_BEGIN' ]; then stage_found=true; break; fi
  done
  [ "$stage_found" = true ] || isolation_error bootstrap-regression forged-descriptor
  forged_output=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C OMEGA_INTERNAL_PROBE=prewrite \
    /bin/bash --noprofile --norc -s -- tests /repo \
    "$self_mnt" "$self_net" "$self_pid" "$self_user" <&5 2>&1)
  forged_code=$?
  exec 5<&-
  [ "$forged_code" -eq 125 ] &&
    [ "$forged_output" = $'ISOLATION_REJECT\tprewrite-invariant\tmount-namespace-not-private' ] &&
    [ ! -e "$forged_sentinel" ] && [ ! -L "$forged_sentinel" ] ||
    isolation_error bootstrap-regression "forged-token-prewrite:$forged_code:$forged_output"
  echo "BOOTSTRAP PASS: forged internal stage is rejected before its sentinel write"
  printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf || isolation_error "configuration probe creation failed"
  /usr/bin/chmod 0644 -- /etc/omega/omega.conf || isolation_error "configuration probe mode setup failed"
  [ "$(/usr/bin/stat -c '%u:%a:%F' -- /etc/omega/omega.conf)" = "0:644:regular file" ] || isolation_error "root-owned 0644 configuration cannot be modeled"
  /usr/bin/rm -f -- /etc/omega/omega.conf || isolation_error "configuration probe cleanup failed"
  EXEC_GUARD=/repo/tests/stubs/omega-test-guard
  STUB_SOURCE=/repo/tests/stubs/omega-test-command
  /bin/bash -n "$EXEC_GUARD" "$STUB_SOURCE" || isolation_error "guard or stub syntax validation failed"
  GATE_ROOT="/tmp/omega-phase3-guard-gate.$$"
  GATE_BIN="$GATE_ROOT/bin"
  /usr/bin/mkdir -p -- "$GATE_BIN" || isolation_error "guard gate workspace creation failed"
  for gate_name in awk sed jq systemctl; do
    /usr/bin/ln -s -- "$STUB_SOURCE" "$GATE_BIN/$gate_name" || isolation_error "guard gate stub creation failed"
  done

  GUARD_NEGATIVE_COUNT=0
  run_guard_negative() {
    local name="$1" expected="$2" template="$3" sentinel="$GATE_ROOT/$1.executed"
    local guard_log="$GATE_ROOT/$1.guard" stub_log="$GATE_ROOT/$1.stub" startup="$EXEC_GUARD"
    local attempt code rejection_count=0 rejection_line expected_class expected_command expected_reason guard_pid
    local probe_stdout probe_stderr probe_pid_file probe_status_file probe_wrapper_code signal_mask signal_low
    local -a hostile_environment=()
    attempt="${template//@SENTINEL@/$sentinel}"
    : > "$guard_log"
    : > "$stub_log"
    case "$name" in
      external-identity)
        /usr/bin/rm -f -- "$GATE_BIN/jq"
        /usr/bin/ln -s -- /usr/bin/true "$GATE_BIN/jq"
        ;;
      external-hash)
        startup="$GATE_ROOT/hash-env"
        printf 'hash -p /usr/bin/true jq\n. /repo/tests/stubs/omega-test-guard\n' > "$startup"
        ;;
      external-alias)
        startup="$GATE_ROOT/alias-env"
        printf "shopt -s expand_aliases\nalias jq='/usr/bin/touch %q'\n. /repo/tests/stubs/omega-test-guard\n" \
          "$sentinel" > "$startup"
        ;;
      jq-function)
        /usr/bin/rm -f -- "$GATE_BIN/jq"
        hostile_environment+=("BASH_FUNC_jq%%=() { /usr/bin/touch $sentinel; }")
        ;;
      systemctl-function)
        /usr/bin/rm -f -- "$GATE_BIN/systemctl"
        hostile_environment+=("BASH_FUNC_systemctl%%=() { /usr/bin/touch $sentinel; }")
        ;;
      builtin-function)
        hostile_environment+=("BASH_FUNC_printf%%=() { /usr/bin/touch $sentinel; }")
        ;;
      ignored-sigint-target)
        hostile_environment+=("OMEGA_TEST_PRODUCTION_SOURCE=/repo/scripts/omega-report.sh")
        hostile_environment+=("OMEGA_TEST_STARTUP_SIGNAL=INT")
        attempt='signal_mask=""; while IFS=: read -r signal_key signal_value; do [ "$signal_key" = SigIgn ] || continue; signal_mask="${signal_value#"${signal_value%%[![:space:]]*}"}"; signal_mask="${signal_mask%"${signal_mask##*[![:space:]]}"}"; break; done < "/proc/$BASHPID/status"; printf "SIGIGN=%s\n" "$signal_mask"; OMEGA_STAT=$(resolve_trusted_command stat 2>/dev/null)'
        ;;
    esac
    if [ "$name" = ignored-sigint-target ]; then
      probe_stdout="$GATE_ROOT/$name.stdout"
      probe_stderr="$GATE_ROOT/$name.stderr"
      probe_pid_file="$GATE_ROOT/$name.pid"
      probe_status_file="$GATE_ROOT/$name.status"
      /usr/bin/timeout -s TERM -k 1 5 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
        /bin/bash --noprofile --norc -c '
          [ "$#" -eq 11 ] || exit 124
          /usr/bin/env -i PATH="$1" HOME=/tmp TMPDIR=/tmp LC_ALL=C BASH_ENV="$2" \
            OMEGA_REPO_ROOT="$3" OMEGA_STUB_BIN="$1" OMEGA_STUB_SOURCE="$4" \
            OMEGA_TRUSTED_PATH="$1" OMEGA_EXEC_LOG="$5" OMEGA_STUB_LOG="$6" \
            OMEGA_REAL_AWK=/usr/bin/mawk OMEGA_REAL_CUT=/usr/bin/cut OMEGA_REAL_GREP=/usr/bin/grep \
            OMEGA_REAL_SED=/usr/bin/sed OMEGA_REAL_SORT=/usr/bin/sort OMEGA_REAL_TAIL=/usr/bin/tail \
            OMEGA_REAL_UNIQ=/usr/bin/uniq OMEGA_REAL_JQ=/usr/bin/jq OMEGA_REAL_CP=/usr/bin/cp \
            OMEGA_REAL_MKDIR=/usr/bin/mkdir OMEGA_REAL_MKTEMP=/usr/bin/mktemp OMEGA_REAL_MV=/usr/bin/mv \
            OMEGA_REAL_RM=/usr/bin/rm OMEGA_REAL_STAT=/usr/bin/stat \
            OMEGA_TEST_PRODUCTION_SOURCE="$3/scripts/omega-report.sh" OMEGA_TEST_STARTUP_SIGNAL=INT \
            /bin/bash --noprofile --norc -c "$7" > "$8" 2> "$9" &
          child=$!
          printf "%s\n" "$child" > "${10}"
          wait "$child"
          printf "%s\n" "$?" > "${11}"
        ' omega-ignored-sigint "$GATE_BIN" "$startup" /repo "$STUB_SOURCE" "$guard_log" "$stub_log" \
          "$attempt" "$probe_stdout" "$probe_stderr" "$probe_pid_file" "$probe_status_file"
      probe_wrapper_code=$?
      [ "$probe_wrapper_code" -eq 0 ] && [ -s "$probe_pid_file" ] && [ -s "$probe_status_file" ] ||
        isolation_error guard-regression "$name:wrapper:$probe_wrapper_code"
      read -r guard_pid < "$probe_pid_file" || isolation_error guard-regression "$name:pid"
      read -r code < "$probe_status_file" || isolation_error guard-regression "$name:status"
      [[ "$guard_pid" =~ ^[0-9]+$ ]] && [[ "$code" =~ ^[0-9]+$ ]] && [ ! -e "/proc/$guard_pid" ] ||
        isolation_error guard-regression "$name:process:$guard_pid:$code"
      signal_mask=$(<"$probe_stdout")
      signal_mask="${signal_mask#SIGIGN=}"
      case "$signal_mask" in ''|*[!0-9A-Fa-f]*) isolation_error guard-regression "$name:sigign-unreadable" ;; esac
      signal_low="${signal_mask: -1}"
      case "$signal_low" in
        2|3|6|7|A|B|E|F|a|b|e|f) ;;
        *) isolation_error guard-regression "$name:sigint-not-ignored:$signal_mask" ;;
      esac
      [ "$(/usr/bin/awk 'END { print NR+0 }' "$probe_stderr")" -eq 1 ] &&
        /usr/bin/grep -Fq 'ISOLATION FAILURE: signal-target-sigint-ignored:' "$probe_stderr" ||
        isolation_error guard-regression "$name:diagnostic"
    else
      /usr/bin/env -i PATH="$GATE_BIN" HOME=/tmp TMPDIR=/tmp LC_ALL=C BASH_ENV="$startup" \
        OMEGA_REPO_ROOT=/repo OMEGA_STUB_BIN="$GATE_BIN" OMEGA_STUB_SOURCE="$STUB_SOURCE" \
        OMEGA_TRUSTED_PATH="$GATE_BIN" \
        OMEGA_EXEC_LOG="$guard_log" OMEGA_STUB_LOG="$stub_log" \
        OMEGA_REAL_AWK=/usr/bin/mawk OMEGA_REAL_CUT=/usr/bin/cut OMEGA_REAL_GREP=/usr/bin/grep \
        OMEGA_REAL_SED=/usr/bin/sed OMEGA_REAL_SORT=/usr/bin/sort OMEGA_REAL_TAIL=/usr/bin/tail \
        OMEGA_REAL_UNIQ=/usr/bin/uniq OMEGA_REAL_JQ=/usr/bin/jq OMEGA_REAL_CP=/usr/bin/cp \
        OMEGA_REAL_MKDIR=/usr/bin/mkdir OMEGA_REAL_MKTEMP=/usr/bin/mktemp OMEGA_REAL_MV=/usr/bin/mv \
        OMEGA_REAL_RM=/usr/bin/rm OMEGA_REAL_STAT=/usr/bin/stat \
        "${hostile_environment[@]}" \
        /bin/bash --noprofile --norc -c "$attempt" >/dev/null 2>/dev/null
      code=$?
    fi
    case "$name" in
      external-identity|jq-function)
        /usr/bin/rm -f -- "$GATE_BIN/jq"
        /usr/bin/ln -s -- "$STUB_SOURCE" "$GATE_BIN/jq"
        ;;
      systemctl-function)
        /usr/bin/ln -s -- "$STUB_SOURCE" "$GATE_BIN/systemctl"
        ;;
    esac
    [ "$code" -eq 125 ] || isolation_error guard-regression "$name:exit:$code"
    [ ! -e "$sentinel" ] && [ ! -L "$sentinel" ] || isolation_error guard-regression "$name:sentinel"
    while IFS= read -r rejection_line; do rejection_count=$((rejection_count+1)); done < <(
      /usr/bin/grep -Eh '^(DENY|UNEXPECTED)[[:space:]]' "$guard_log" "$stub_log" || true
    )
    [ "$rejection_count" -eq 1 ] || isolation_error guard-regression "$name:rejection-count:$rejection_count"
    case "$expected" in
      guard:*)
        expected_class="${expected#guard:}"
        /usr/bin/grep -q $'^DENY\t'"$expected_class"$'\t' "$guard_log" ||
          isolation_error guard-regression "$name:class:$expected_class"
        [ ! -s "$stub_log" ] || isolation_error guard-regression "$name:unexpected-stub"
        ;;
      stub:*:*)
        expected_command="${expected#stub:}"; expected_reason="${expected_command#*:}"; expected_command="${expected_command%%:*}"
        [ "$(/usr/bin/grep -Fxc -- $'UNEXPECTED\t'"$expected_command"$'\t'"$expected_reason" "$stub_log")" -eq 1 ] ||
          isolation_error guard-regression "$name:stub-reason:$expected_command:$expected_reason"
        ! /usr/bin/grep -q '^DENY[[:space:]]' "$guard_log" || isolation_error guard-regression "$name:guard-deny"
        ;;
      *) isolation_error guard-regression "$name:invalid-expectation" ;;
    esac
    GUARD_NEGATIVE_COUNT=$((GUARD_NEGATIVE_COUNT+1))
    echo "GUARD PASS: $name rejected as $expected without sentinel execution"
  }

  run_guard_negative assignment-prefix guard:assignment-prefixed-dispatch 'FLAG=1 /usr/bin/touch @SENTINEL@'
  run_guard_negative path-mutation guard:immutable-state-mutation 'PATH=/usr/bin; /usr/bin/touch @SENTINEL@'
  run_guard_negative mapping-mutation guard:immutable-state-mutation 'OMEGA_STUB_BIN=/usr/bin; /usr/bin/touch @SENTINEL@'
  run_guard_negative functrace-mutation guard:set-mutation 'set +T; guarded_escape() { /usr/bin/touch @SENTINEL@; }; guarded_escape'
  run_guard_negative builtin-dispatch guard:shell-dispatch "builtin eval '/usr/bin/touch @SENTINEL@'"
  run_guard_negative function-dispatch guard:function-dispatch 'guarded_escape() { /usr/bin/touch @SENTINEL@; }; guarded_escape'
  run_guard_negative awk-system stub:awk:program "awk 'BEGIN { system(\"/usr/bin/touch @SENTINEL@\") }'"
  run_guard_negative sed-execute stub:sed:arguments "sed 'e /usr/bin/touch @SENTINEL@' </dev/null"
  run_guard_negative shell-reentry guard:shell-reentry "bash --noprofile --norc -c '/usr/bin/touch @SENTINEL@'"
  run_guard_negative absolute-path guard:unapproved-dispatch '/usr/bin/touch @SENTINEL@'
  run_guard_negative indirect-dispatch guard:unapproved-dispatch 'runner=/usr/bin/touch; "$runner" @SENTINEL@'
  run_guard_negative jq-function guard:external-type-mismatch 'jq'
  run_guard_negative systemctl-function guard:external-type-mismatch 'systemctl'
  run_guard_negative builtin-function guard:builtin-type-mismatch 'printf unsafe'
  run_guard_negative external-identity guard:external-identity-mismatch 'jq'
  run_guard_negative external-hash guard:external-hash-mismatch 'jq'
  run_guard_negative external-alias guard:unapproved-dispatch 'jq'
  run_guard_negative ignored-sigint-target guard:signal-target-sigint-ignored 'OMEGA_STAT=$(resolve_trusted_command stat 2>/dev/null)'
  /usr/bin/rm -rf -- "$GATE_ROOT" || isolation_error "guard gate cleanup failed"
  echo "Guard negative tests passed: $GUARD_NEGATIVE_COUNT"
  exec 6< /repo/tests/test-security-results.sh || isolation_error bootstrap signal-tests-descriptor
  stage_found=false
  while IFS= read -r stage_line <&6; do
    if [ "$stage_line" = '# OMEGA_BASH_STAGE_BEGIN' ]; then stage_found=true; break; fi
  done
  [ "$stage_found" = true ] || isolation_error bootstrap signal-tests-descriptor
  if /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /bin/bash --noprofile --norc -s -- signals /repo \
    "$FORBIDDEN_MNT_NS" "$FORBIDDEN_NET_NS" "$FORBIDDEN_PID_NS" "$FORBIDDEN_USER_NS" <&6; then
    echo "TARGETED PASS: isolated production signal assertions"
  else
    isolation_error signal-regression targeted-signal-stage
  fi
  exec 4< /repo/tests/test-security-results.sh || isolation_error bootstrap tests-descriptor
  stage_found=false
  while IFS= read -r stage_line <&4; do
    if [ "$stage_line" = '# OMEGA_BASH_STAGE_BEGIN' ]; then stage_found=true; break; fi
  done
  [ "$stage_found" = true ] || isolation_error bootstrap tests-descriptor
  if /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /bin/bash --noprofile --norc -s -- tests /repo \
    "$FORBIDDEN_MNT_NS" "$FORBIDDEN_NET_NS" "$FORBIDDEN_PID_NS" "$FORBIDDEN_USER_NS" <&4; then
    suite_status=0
  else
    suite_status=$?
  fi
  echo "Isolation gate: PASS (clean startup, immutable child state, identity-checked wrappers, structured guard audit, private /etc+/var+/tmp, read-only repository, network namespace)"
  exit "$suite_status"
fi

case "$STAGE_TOKEN" in signals|tests) ;; *) isolation_error bootstrap invalid-test-stage ;; esac
validate_isolation prewrite-invariant
if [ "${OMEGA_INTERNAL_PROBE:-}" = prewrite ]; then
  /usr/bin/touch -- /tmp/omega-forged-stage-sentinel || isolation_error prewrite-probe sentinel-write
  isolation_error prewrite-probe unexpectedly-reached
fi
unset ENV CDPATH GLOBIGNORE HOST_REPO_ROOT OMEGA_INTERNAL_PROBE

PATH=/usr/bin:/bin
export PATH
readonly PATH
unset BASH_ENV ENV CDPATH

REPO_ROOT="$BODY_REPO_ROOT"
TEST_DIR="$REPO_ROOT/tests"
FIXTURE_DIR="$TEST_DIR/fixtures"
CONFIG_FIXTURE_DIR="$FIXTURE_DIR/config"
REPO_STUB_SOURCE="$TEST_DIR/stubs/omega-test-command"
STUB_SOURCE="/usr/local/libexec/omega-test-command"
EXEC_GUARD="$TEST_DIR/stubs/omega-test-guard"
BOOTSTRAP_GUARD="/usr/local/libexec/omega-test-guard"
TEST_ROOT=$(/usr/bin/mktemp -d -- "/tmp/omega-phase1-tests.XXXXXX")
/usr/bin/chmod 0700 -- "$TEST_ROOT"
STUB_BIN="/usr/local/bin"
TRUSTED_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PASS_COUNT=0
FAIL_COUNT=0
NEXT_WITH_HOME=true
NEXT_WITH_REPORT_DIR=true
NEXT_HOME_VALUE=""
NEXT_INPUT_SETUP="default"
NEXT_MISSING_COMMAND=""
NEXT_EXPECTED_STDERR=""
NEXT_RM_ONESHOT=false
NEXT_TMPDIR_VALUE=""
NEXT_COMMAND_SETUP="default"
NEXT_BOOTSTRAP_SUPERVISOR_PID=""

cleanup() {
  /usr/bin/rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

pass() {
  echo "PASS: $1"
  PASS_COUNT=$((PASS_COUNT+1))
}

fail() {
  echo "FAIL: $1"
  FAIL_COUNT=$((FAIL_COUNT+1))
}

assert_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [ "$actual" = "$expected" ]; then
    pass "$label"
  else
    fail "$label (expected '$expected', got '$actual')"
  fi
}

assert_contains() {
  local label="$1"
  local file="$2"
  local text="$3"
  local observed
  if grep -Fq -- "$text" "$file"; then
    pass "$label"
  else
    observed=$(<"$file")
    observed="${observed//$'\n'/ | }"
    fail "$label (missing '$text'; observed: $observed)"
  fi
}

assert_not_contains() {
  local label="$1"
  local file="$2"
  local text="$3"
  if grep -Fq -- "$text" "$file"; then
    fail "$label (unexpected '$text')"
  else
    pass "$label"
  fi
}

assert_file_exists() {
  local label="$1"
  local file="$2"
  if [ -f "$file" ]; then
    pass "$label"
  else
    fail "$label (missing $file)"
  fi
}

assert_file_absent() {
  local label="$1"
  local file="$2"
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    pass "$label"
  else
    fail "$label (unexpected $file)"
  fi
}

assert_no_matching_path() {
  local label="$1"
  local pattern="$2"
  local matches

  matches=$(compgen -G "$pattern" || true)
  if [ -z "$matches" ]; then
    pass "$label"
  else
    fail "$label (unexpected path remains: $matches)"
  fi
}

assert_matching_path_exists() {
  local label="$1" pattern="$2" matches

  matches=$(compgen -G "$pattern" || true)
  if [ -n "$matches" ]; then
    pass "$label"
  else
    fail "$label (expected a matching path)"
  fi
}

assert_report_failure_evidence() {
  local label="$1"
  local completed="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt"
  local evidence="$completed.evidence"

  assert_file_absent "$label removes the completed report name" "$completed"
  assert_file_exists "$label retains the validated evidence name" "$evidence"
  assert_equal "$label retains exactly one stored result marker" "1" \
    "$(grep -Ec '^OMEGA_RESULT=(SUCCESS|WARNING|UNKNOWN|FAILURE)$' "$evidence")"
  assert_equal "$label stores the final failure marker" "OMEGA_RESULT=FAILURE" \
    "$(awk 'NF { line=$0 } END { print line }' "$evidence")"
  assert_equal "$label removes the stale success marker" "0" \
    "$(grep -Ec '^OMEGA_RESULT=SUCCESS$' "$evidence" || true)"
  assert_equal "$label retains private evidence permissions" "regular file:600" \
    "$(/usr/bin/stat -c '%F:%a' -- "$evidence")"
  assert_contains "$label reports the retained evidence name" "$CASE_STDOUT" "$evidence"
  assert_no_matching_path "$label leaves no publication stage" "$CASE_REPORT_DIR/.omega-report-stage.*"
  assert_no_matching_path "$label leaves no temporary workspace" "$CASE_REPORT_DIR/.omega-report-work.*"
  assert_no_matching_path "$label creates no colliding evidence name" "$evidence.[0-9]*"
  assert_equal "$label attempts published rollback removal once" "1" \
    "$(grep -Ec '^rm[[:space:]]+-f[[:space:]]' "$CASE_STUB_LOG")"
  assert_equal "$label cleans its temporary workspace once" "1" \
    "$(grep -Ec '^rm[[:space:]]+-rf[[:space:]]' "$CASE_STUB_LOG")"
}

assert_stderr_empty() {
  local label="$1"
  local file="$2"
  if [ -s "$file" ]; then
    fail "$label (unexpected stderr output: $(<"$file"))"
  else
    pass "$label"
  fi
}

assert_stub_log_sealed() {
  local label="$1"
  local file="$2"
  local unexpected

  unexpected=$(grep -Ev '^(awk|cut|grep|sed|sort|tail|uniq|systemctl|curl|sudo|stat|jq|docker|hostname|ip|uptime|df|free|date|mkdir|mktemp|mv|rm|clear|omega|omega-status|omega-health|omega-report|omega-alerts|omega-summary|omega-doctor|omega-bundle|omega-cleanup)([[:space:]]|$)' "$file" || true)
  if [ -z "$unexpected" ]; then
    pass "$label"
  else
    fail "$label (unexpected or rejected stub invocation: $unexpected)"
  fi
}

assert_guard_log_sealed() {
  local label="$1" file="$2" malformed denied

  malformed=$(grep -Ev '^(START|ALLOW)[[:space:]]' "$file" || true)
  denied=$(grep '^DENY[[:space:]]' "$file" || true)
  if [ ! -s "$file" ]; then
    fail "$label (guard log is empty)"
  elif ! grep -q '^START[[:space:]]' "$file"; then
    fail "$label (guard startup record is missing)"
  elif [ -n "$denied" ]; then
    fail "$label (guard recorded a denied dispatch: $denied)"
  elif [ -n "$malformed" ]; then
    fail "$label (malformed guard record: $malformed)"
  else
    pass "$label"
  fi
}

assert_signal_guard_order() {
  local label="$1"
  local file="$2"
  local result

  result=$(awk '
    /^emit_result_marker\(\) \{/ { in_emit=1 }
    in_emit && trap_line == 0 && index($0, "trap ") && index($0, "HUP INT TERM") { trap_line=NR }
    in_emit && check_line == 0 && index($0, "[ \"$RESULT_EMITTED\" = false ]") { check_line=NR }
    /^[[:space:]]*RESULT_EMITTED=true$/ { assignments++ }
    /^finish_result\(\) \{/ { in_finish=1 }
    in_finish && cleanup_line == 0 && index($0, "cleanup_workspace") { cleanup_line=NR }
    in_finish && emit_line == 0 && index($0, "emit_result_marker") { emit_line=NR }
    END {
      if (trap_line > 0 && check_line > trap_line && assignments == 1 &&
          cleanup_line > 0 && emit_line > cleanup_line) print "ok"
    }
  ' "$file")
  if [ "$result" = "ok" ]; then
    pass "$label"
  else
    fail "$label (cleanup and signal suppression must precede the single result emission)"
  fi
}

readonly REAL_JQ=/usr/bin/jq
readonly REAL_AWK=/usr/bin/mawk
readonly REAL_CUT=/usr/bin/cut
readonly REAL_GREP=/usr/bin/grep
readonly REAL_SED=/usr/bin/sed
readonly REAL_SORT=/usr/bin/sort
readonly REAL_TAIL=/usr/bin/tail
readonly REAL_UNIQ=/usr/bin/uniq
readonly REAL_CP=/usr/bin/cp
readonly REAL_MKDIR=/usr/bin/mkdir
readonly REAL_MKTEMP=/usr/bin/mktemp
readonly REAL_MV=/usr/bin/mv
readonly REAL_RM=/usr/bin/rm
readonly REAL_STAT=/usr/bin/stat
readonly REAL_LN=/usr/bin/ln
readonly REAL_CHMOD=/usr/bin/chmod

for target in "$REAL_AWK" "$REAL_CUT" "$REAL_GREP" "$REAL_SED" "$REAL_SORT" "$REAL_TAIL" "$REAL_UNIQ" \
  "$REAL_JQ" "$REAL_CP" "$REAL_MKDIR" "$REAL_MKTEMP" "$REAL_MV" "$REAL_RM" "$REAL_STAT" "$REAL_LN" "$REAL_CHMOD"; do
  if [ ! -x "$target" ]; then
    echo "Required test utility is not executable: $target" >&2
    exit 1
  fi
done

setup_private_stub_link() {
  local link_type="$1" source="$2" target="$3" link_error source_id target_id target_value

  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    case "$link_type" in
      hard) link_error=$(/usr/bin/ln -- "$source" "$target" 2>&1) && return 0 ;;
      symbolic) link_error=$(/usr/bin/ln -s -- "$source" "$target" 2>&1) && return 0 ;;
      *) return 1 ;;
    esac
  fi

  case "$link_type" in
    hard)
      [ -f "$source" ] && [ ! -L "$source" ] && [ -f "$target" ] && [ ! -L "$target" ] || return 1
      source_id=$(/usr/bin/stat -c '%d:%i' -- "$source") || return 1
      target_id=$(/usr/bin/stat -c '%d:%i' -- "$target") || return 1
      [ "$target_id" = "$source_id" ] || return 1
      ;;
    symbolic)
      [ -f "$source" ] && [ ! -L "$source" ] && [ -L "$target" ] || return 1
      target_value=$(/usr/bin/readlink -- "$target") || return 1
      [ "$target_value" = "$source" ] || return 1
      source_id=$(/usr/bin/stat -Lc '%d:%i' -- "$source") || return 1
      target_id=$(/usr/bin/stat -Lc '%d:%i' -- "$target") || return 1
      [ "$target_id" = "$source_id" ] || return 1
      ;;
    *) return 1 ;;
  esac
}

/usr/bin/cp -- "$REPO_STUB_SOURCE" "$STUB_SOURCE"
/usr/bin/chmod 0755 -- "$STUB_SOURCE"
/usr/bin/cmp -s -- "$REPO_STUB_SOURCE" "$STUB_SOURCE" || isolation_error test-setup private-stub-copy
/usr/bin/cp -- "$EXEC_GUARD" "$BOOTSTRAP_GUARD"
/usr/bin/chmod 0644 -- "$BOOTSTRAP_GUARD"
[ "$(/usr/bin/stat -c '%F:%u:%a' -- "$BOOTSTRAP_GUARD")" = 'regular file:0:644' ] ||
  isolation_error test-setup bootstrap-guard-metadata
/usr/bin/cmp -s -- "$EXEC_GUARD" "$BOOTSTRAP_GUARD" || isolation_error test-setup bootstrap-guard-copy
UNSAFE_STUB_SOURCE="/usr/local/libexec/omega-test-command-unsafe"
/usr/bin/cp -- "$REPO_STUB_SOURCE" "$UNSAFE_STUB_SOURCE"
/usr/bin/chmod 0775 -- "$UNSAFE_STUB_SOURCE"

ATTACKER_BIN="$TEST_ROOT/attacker-bin"
/usr/bin/mkdir -p -- "$ATTACKER_BIN"
for attacker_command in jq stat; do
  printf '#!/bin/sh\n/usr/bin/touch /tmp/omega-attacker-%s.executed\nexit 0\n' "$attacker_command" > "$ATTACKER_BIN/$attacker_command"
  /usr/bin/chmod 0777 -- "$ATTACKER_BIN/$attacker_command"
done

for name in awk cut grep sed sort tail uniq systemctl curl sudo stat docker hostname ip uptime df free date clear \
  mkdir mktemp mv rm; do
  setup_private_stub_link hard "$STUB_SOURCE" "$STUB_BIN/$name" ||
    isolation_error test-setup "command-stub-link:$name"
done
setup_private_stub_link hard "$STUB_SOURCE" /usr/local/libexec/jq ||
  isolation_error test-setup command-stub-link:jq-source
setup_private_stub_link symbolic /usr/local/libexec/jq "$STUB_BIN/jq" ||
  isolation_error test-setup command-stub-link:jq

for name in awk cut grep sed sort tail uniq systemctl curl sudo stat docker hostname ip uptime df free date clear \
  mkdir mktemp mv rm; do
  setup_private_stub_link hard "$STUB_SOURCE" "$STUB_BIN/$name" ||
    isolation_error test-setup "command-stub-repeat:$name"
done
setup_private_stub_link hard "$STUB_SOURCE" /usr/local/libexec/jq ||
  isolation_error test-setup command-stub-repeat:jq-source
setup_private_stub_link symbolic /usr/local/libexec/jq "$STUB_BIN/jq" ||
  isolation_error test-setup command-stub-repeat:jq

PRIVATE_LINK_MISMATCH="$TEST_ROOT/private-link-mismatch"
/usr/bin/mkdir -- "$PRIVATE_LINK_MISMATCH"
printf 'different inode\n' > "$PRIVATE_LINK_MISMATCH/regular"
/usr/bin/ln -s -- /usr/bin/true "$PRIVATE_LINK_MISMATCH/symlink"
/usr/bin/mkdir -- "$PRIVATE_LINK_MISMATCH/directory"
for mismatch in regular symlink directory; do
  if setup_private_stub_link hard "$STUB_SOURCE" "$PRIVATE_LINK_MISMATCH/$mismatch"; then
    isolation_error test-setup "hard-link-mismatch-accepted:$mismatch"
  fi
  if setup_private_stub_link symbolic "$STUB_SOURCE" "$PRIVATE_LINK_MISMATCH/$mismatch"; then
    isolation_error test-setup "symbolic-link-mismatch-accepted:$mismatch"
  fi
done
for name in omega omega-status omega-health omega-report omega-alerts omega-summary omega-doctor omega-bundle omega-cleanup; do
  /usr/bin/cp -- "$STUB_SOURCE" "$STUB_BIN/$name"
  /usr/bin/chmod 0755 -- "$STUB_BIN/$name"
  /usr/bin/cmp -s -- "$STUB_SOURCE" "$STUB_BIN/$name" || isolation_error test-setup "command-stub-copy:$name"
done

ONE_SHOT_STUB_SOURCE="/usr/local/libexec/rm"
/usr/bin/mawk '
  $0 == "  rm)" { in_rm=1 }
  in_rm && $0 == "      fail) exit 1 ;;" {
    print "      fail-once)"
    print "        one_shot_state=\"${OMEGA_STUB_RM_ONESHOT_STATE:?}\""
    print "        one_shot_count=0"
    print "        [ ! -f \"$one_shot_state\" ] || one_shot_count=$(<\"$one_shot_state\")"
    print "        one_shot_count=$((one_shot_count + 1))"
    print "        printf \"%s\\n\" \"$one_shot_count\" > \"$one_shot_state\""
    print "        if [ \"$one_shot_count\" -eq 1 ]; then"
    print "          printf \"OMEGA_TEST_RM_FAIL_ONCE\\n\" >&2"
    print "          exit 1"
    print "        fi"
    print "        ;;"
  }
  { print }
  $0 == "  clear)" { in_rm=0 }
  ' "$REPO_STUB_SOURCE" > "$ONE_SHOT_STUB_SOURCE" || isolation_error test-setup one-shot-stub-generation
/usr/bin/chmod 0755 -- "$ONE_SHOT_STUB_SOURCE" || isolation_error test-setup one-shot-stub-mode

EMPTY_EVE="$TEST_ROOT/eve-empty.jsonl"
: > "$EMPTY_EVE"

prepare_canonical_input() {
  local fixture="$1"
  local setup="$2"

  /usr/bin/rm -rf -- /etc/omega /var/log/suricata
  /usr/bin/mkdir -p -- /etc/omega /var/log/suricata
  /usr/bin/chmod 0755 -- /etc /etc/omega /var/log/suricata
  /usr/bin/cp -- "$fixture" /var/log/suricata/eve.json
  /usr/bin/chmod 0644 -- /var/log/suricata/eve.json
  CURRENT_EVE_PATH=/var/log/suricata/eve.json

  case "$setup" in
    default) ;;
    no-config-dir) /usr/bin/rm -rf -- /etc/omega ;;
    valid-default)
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    valid-alternate)
      /usr/bin/mkdir -p -- /var/log/suricata/alternate
      /usr/bin/cp -- "$fixture" /var/log/suricata/alternate/eve.json
      /usr/bin/chmod 0644 -- /var/log/suricata/alternate/eve.json
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/alternate/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      CURRENT_EVE_PATH=/var/log/suricata/alternate/eve.json
      ;;
    config-fixture-*)
      config_fixture="${setup#config-fixture-}"
      /usr/bin/cp -- "$CONFIG_FIXTURE_DIR/$config_fixture.conf" /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      if [ "$config_fixture" = result-marker ]; then
        /usr/bin/cp -- "$fixture" /var/log/suricata/OMEGA_RESULT=SUCCESS.json
        CURRENT_EVE_PATH=/var/log/suricata/OMEGA_RESULT=SUCCESS.json
      fi
      ;;
    config-missing-assignment)
      printf 'OMEGA_CONFIG_V1\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-blank-line)
      printf 'OMEGA_CONFIG_V1\n\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-comment)
      printf 'OMEGA_CONFIG_V1\n# no executable comments\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-missing-newline)
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-oversized)
      printf -v config_padding '%4100s' ''
      config_padding="${config_padding// /a}"
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/%s\n' "$config_padding" > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-long-line)
      printf -v config_padding '%2028s' ''
      config_padding="${config_padding// /a}"
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/%s\n' "$config_padding" > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-relative) printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=relative/eve.json\n' > /etc/omega/omega.conf ;;
    config-leading-space) printf 'OMEGA_CONFIG_V1\n suricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf ;;
    config-trailing-space) printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json \n' > /etc/omega/omega.conf ;;
    config-root) printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/\n' > /etc/omega/omega.conf ;;
    config-traversal) printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/../eve.json\n' > /etc/omega/omega.conf ;;
    config-double-separator) printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var//log/eve.json\n' > /etc/omega/omega.conf ;;
    config-trailing-separator) printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/\n' > /etc/omega/omega.conf ;;
    config-control-*)
      control_number="${setup#config-control-}"
      printf -v control_escape '\\%03o' "$control_number"
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve' > /etc/omega/omega.conf
      printf '%b' "$control_escape" >> /etc/omega/omega.conf
      printf '.json\n' >> /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
    config-mode-0600)
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0600 -- /etc/omega/omega.conf
      ;;
    config-mode-0664)
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0664 -- /etc/omega/omega.conf
      ;;
    config-unreadable)
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/var/log/suricata/eve.json\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0000 -- /etc/omega/omega.conf
      ;;
    config-symlink)
      /usr/bin/cp -- "$CONFIG_FIXTURE_DIR/valid-default.conf" /var/log/suricata/config-target
      /usr/bin/ln -s -- /var/log/suricata/config-target /etc/omega/omega.conf
      ;;
    config-directory) /usr/bin/mkdir -- /etc/omega/omega.conf ;;
    config-fifo) /usr/bin/mkfifo -- /etc/omega/omega.conf ;;
    parent-symlink)
      /usr/bin/rm -rf -- /etc/omega
      /usr/bin/mkdir -- /var/log/suricata/config-parent
      /usr/bin/ln -s -- /var/log/suricata/config-parent /etc/omega
      ;;
    parent-file)
      /usr/bin/rm -rf -- /etc/omega
      printf 'not a directory\n' > /etc/omega
      ;;
    parent-writable) /usr/bin/chmod 0775 -- /etc/omega ;;
    parent-unsearchable) /usr/bin/chmod 0600 -- /etc/omega ;;
    etc-writable) /usr/bin/chmod 0777 -- /etc ;;
    telemetry-missing) /usr/bin/rm -f -- /var/log/suricata/eve.json ;;
    telemetry-directory)
      /usr/bin/rm -f -- /var/log/suricata/eve.json
      /usr/bin/mkdir -- /var/log/suricata/eve.json
      ;;
    telemetry-fifo)
      /usr/bin/rm -f -- /var/log/suricata/eve.json
      /usr/bin/mkfifo -- /var/log/suricata/eve.json
      ;;
    telemetry-device)
      printf 'OMEGA_CONFIG_V1\nsuricata_eve_path=/dev/null\n' > /etc/omega/omega.conf
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      CURRENT_EVE_PATH=/dev/null
      ;;
    telemetry-symlink)
      /usr/bin/mv -- /var/log/suricata/eve.json /var/log/suricata/eve.target
      /usr/bin/ln -s -- /var/log/suricata/eve.target /var/log/suricata/eve.json
      ;;
    telemetry-unreadable) /usr/bin/chmod 0000 -- /var/log/suricata/eve.json ;;
    *) isolation_error "unknown canonical input setup: $setup" ;;
  esac
  case "$setup" in
    config-relative|config-leading-space|config-trailing-space|config-root|config-traversal|config-double-separator|config-trailing-separator)
      /usr/bin/chmod 0644 -- /etc/omega/omega.conf
      ;;
  esac
}

run_case() {
  local label="$1"
  local expected_code="$2"
  local expected_result="$3"
  local script="$4"
  local fixture="$5"
  shift 5

  local case_dir="$TEST_ROOT/cases/$label"
  local with_home="$NEXT_WITH_HOME"
  local with_report_dir="$NEXT_WITH_REPORT_DIR"
  local home_value="$NEXT_HOME_VALUE"
  local input_setup="$NEXT_INPUT_SETUP"
  local missing_command="$NEXT_MISSING_COMMAND"
  local expected_stderr="$NEXT_EXPECTED_STDERR"
  local rm_oneshot="$NEXT_RM_ONESHOT"
  local tmpdir_value="$NEXT_TMPDIR_VALUE"
  local command_setup="$NEXT_COMMAND_SETUP"
  local bootstrap_supervisor_pid="$NEXT_BOOTSTRAP_SUPERVISOR_PID"
  local rm_source="$STUB_SOURCE"
  local bootstrap_home="" body_fd body_line body_found=false
  local -a environment
  NEXT_WITH_HOME=true
  NEXT_WITH_REPORT_DIR=true
  NEXT_HOME_VALUE=""
  NEXT_INPUT_SETUP="default"
  NEXT_MISSING_COMMAND=""
  NEXT_EXPECTED_STDERR=""
  NEXT_RM_ONESHOT=false
  NEXT_TMPDIR_VALUE=""
  NEXT_COMMAND_SETUP="default"
  NEXT_BOOTSTRAP_SUPERVISOR_PID=""

  prepare_canonical_input "$fixture" "$input_setup"

  mkdir -p "$case_dir/home" "$case_dir/tmp"
  /usr/bin/chmod 0700 -- "$TEST_ROOT/cases" "$case_dir" "$case_dir/home" "$case_dir/tmp"
  if [ -n "$tmpdir_value" ]; then /usr/bin/mkdir -p -- "$tmpdir_value"; else tmpdir_value="$case_dir/tmp"; fi
  if [ "$with_report_dir" = true ]; then
    mkdir -p "$case_dir/home/omega-reports/output"
    /usr/bin/chmod 0700 -- "$case_dir/home/omega-reports" "$case_dir/home/omega-reports/output"
  fi

  CASE_STDOUT="$case_dir/stdout"
  CASE_STDERR="$case_dir/stderr"
  CASE_STUB_LOG="$case_dir/stub.log"
  CASE_EXEC_LOG="$case_dir/guard.log"
  CASE_REPORT_DIR="$case_dir/home/omega-reports/output"
  : > "$CASE_STUB_LOG"
  : > "$CASE_EXEC_LOG"
  if [ -n "$missing_command" ]; then
    for command_name in $missing_command; do
      case "$command_name" in omega-bundle|omega-cleanup) ;; *) isolation_error "unsafe missing-command test" ;; esac
      /usr/bin/rm -f -- "$STUB_BIN/$command_name"
    done
  fi
  if [ "$rm_oneshot" = true ]; then
    /usr/bin/rm -f -- "$STUB_BIN/rm"
    /usr/bin/ln -s -- "$ONE_SHOT_STUB_SOURCE" "$STUB_BIN/rm"
    rm_source="$ONE_SHOT_STUB_SOURCE"
  fi
  case "$command_setup" in
    default) ;;
    unsafe-command-directory) /usr/bin/chmod 0775 -- "$STUB_BIN" ;;
    wrong-omega-destination) /usr/bin/mv -- "$STUB_BIN/omega-bundle" /usr/local/sbin/omega-bundle ;;
    unsafe-system-symlink)
      /usr/bin/rm -f -- "$STUB_BIN/jq"
      /usr/bin/ln -s -- "$UNSAFE_STUB_SOURCE" "$STUB_BIN/jq"
      ;;
    unsafe-multihop-symlink)
      /usr/bin/mkdir -p -- "$TEST_ROOT/unsafe-command-hop"
      /usr/bin/chmod 0777 -- "$TEST_ROOT/unsafe-command-hop"
      /usr/bin/ln -s -- /usr/local/libexec/jq "$TEST_ROOT/unsafe-command-hop/jq"
      /usr/bin/rm -f -- "$STUB_BIN/jq"
      /usr/bin/ln -s -- "$TEST_ROOT/unsafe-command-hop/jq" "$STUB_BIN/jq"
      ;;
    canonical-candidate-swap) ;;
    *) isolation_error test-setup "unknown-command-setup:$command_setup" ;;
  esac

  environment=(
    "PATH=$TRUSTED_PATH"
    "TMPDIR=$tmpdir_value"
    "LC_ALL=C"
    "OMEGA_STUB_BIN=$STUB_BIN"
    "OMEGA_TRUSTED_PATH=$TRUSTED_PATH"
    "OMEGA_STUB_SOURCE=$STUB_SOURCE"
    "OMEGA_STUB_RM_SOURCE=$rm_source"
    "OMEGA_STUB_RM_ONESHOT_STATE=$case_dir/rm-attempts"
    "OMEGA_STUB_LOG=$CASE_STUB_LOG"
    "OMEGA_REPO_ROOT=$REPO_ROOT"
    "BASH_ENV=$EXEC_GUARD"
    "OMEGA_EXEC_LOG=$CASE_EXEC_LOG"
    "OMEGA_STUB_EVE_TARGET=$CURRENT_EVE_PATH"
    "OMEGA_STUB_STATE_DIR=$case_dir"
    "OMEGA_STUB_ROTATE_FILE=$FIXTURE_DIR/eve-high-alert.jsonl"
    "OMEGA_STUB_CONFIG_REPLACEMENT=$CONFIG_FIXTURE_DIR/valid-alternate.conf"
    "OMEGA_REAL_JQ=$REAL_JQ"
    "OMEGA_REAL_AWK=$REAL_AWK"
    "OMEGA_REAL_CUT=$REAL_CUT"
    "OMEGA_REAL_GREP=$REAL_GREP"
    "OMEGA_REAL_SED=$REAL_SED"
    "OMEGA_REAL_SORT=$REAL_SORT"
    "OMEGA_REAL_TAIL=$REAL_TAIL"
    "OMEGA_REAL_UNIQ=$REAL_UNIQ"
    "OMEGA_REAL_CP=$REAL_CP"
    "OMEGA_REAL_MKDIR=$REAL_MKDIR"
    "OMEGA_REAL_MKTEMP=$REAL_MKTEMP"
    "OMEGA_REAL_MV=$REAL_MV"
    "OMEGA_REAL_RM=$REAL_RM"
    "OMEGA_REAL_STAT=$REAL_STAT"
    "OMEGA_REAL_LN=$REAL_LN"
    "OMEGA_REAL_CHMOD=$REAL_CHMOD"
    "OMEGA_TEST_PRODUCTION_SOURCE=$REPO_ROOT/scripts/$script"
  )
  if [ "$with_home" = true ]; then
    if [ -n "$home_value" ]; then
      environment+=("HOME=$home_value")
      bootstrap_home="$home_value"
    else
      environment+=("HOME=$case_dir/home")
      bootstrap_home="$case_dir/home"
    fi
  fi
  environment+=("$@")

  exec {body_fd}< "$REPO_ROOT/scripts/$script" || isolation_error test-execution "body-descriptor:$script"
  while IFS= read -r body_line <&"$body_fd"; do
    if [ "$body_line" = '# OMEGA_BASH_BODY_V1' ]; then body_found=true; break; fi
  done
  if [ "$body_found" = true ]; then
    /usr/bin/env -i "${environment[@]}" \
      /bin/bash --noprofile --norc -s -- "$bootstrap_home" "$tmpdir_value" "$bootstrap_supervisor_pid" \
      <&"$body_fd" > "$CASE_STDOUT" 2> "$CASE_STDERR"
  else
    exec {body_fd}<&-
    body_fd=""
    /usr/bin/env -i "${environment[@]}" \
      /bin/bash --noprofile --norc "$REPO_ROOT/scripts/$script" > "$CASE_STDOUT" 2> "$CASE_STDERR"
  fi
  CASE_CODE=$?
  if [ -n "$body_fd" ]; then exec {body_fd}<&-; fi
  case "$command_setup" in
    unsafe-command-directory) /usr/bin/chmod 0755 -- "$STUB_BIN" ;;
    wrong-omega-destination) /usr/bin/mv -- /usr/local/sbin/omega-bundle "$STUB_BIN/omega-bundle" ;;
    unsafe-system-symlink)
      /usr/bin/rm -f -- "$STUB_BIN/jq"
      /usr/bin/ln -s -- /usr/local/libexec/jq "$STUB_BIN/jq"
      ;;
    unsafe-multihop-symlink)
      /usr/bin/rm -f -- "$STUB_BIN/jq"
      /usr/bin/ln -s -- /usr/local/libexec/jq "$STUB_BIN/jq"
      /usr/bin/rm -rf -- "$TEST_ROOT/unsafe-command-hop"
      ;;
    canonical-candidate-swap)
      /usr/bin/rm -f -- "$STUB_BIN/jq"
      /usr/bin/ln -s -- /usr/local/libexec/jq "$STUB_BIN/jq"
      ;;
  esac
  if [ "$rm_oneshot" = true ]; then
    /usr/bin/rm -f -- "$STUB_BIN/rm"
    /usr/bin/ln -- "$STUB_SOURCE" "$STUB_BIN/rm"
  fi
  if [ -n "$missing_command" ]; then
    for command_name in $missing_command; do
      /usr/bin/cp -- "$STUB_SOURCE" "$STUB_BIN/$command_name"
      /usr/bin/chmod 0755 -- "$STUB_BIN/$command_name"
    done
  fi

  assert_equal "$label exit code" "$expected_code" "$CASE_CODE"

  local result_count
  local last_nonblank
  result_count=$(grep -Ec '^OMEGA_RESULT=(SUCCESS|WARNING|UNKNOWN|FAILURE)$' "$CASE_STDOUT")
  last_nonblank=$(awk 'NF { line=$0 } END { print line }' "$CASE_STDOUT")
  assert_equal "$label emits one result" "1" "$result_count"
  assert_equal "$label result is last" "OMEGA_RESULT=$expected_result" "$last_nonblank"
  if [ -n "$expected_stderr" ]; then
    assert_equal "$label preserves expected stderr" "$expected_stderr" "$(<"$CASE_STDERR")"
  else
    assert_stderr_empty "$label stderr is empty" "$CASE_STDERR"
  fi
  assert_stub_log_sealed "$label stub boundary is sealed" "$CASE_STUB_LOG"
  assert_guard_log_sealed "$label guard execution log is sealed" "$CASE_EXEC_LOG"
}

if [ "$STAGE_TOKEN" = signals ]; then
  echo "== targeted signal assertions =="

  for script in omega-summary.sh omega-doctor.sh; do
    for signal in HUP INT TERM; do
      NEXT_BOOTSTRAP_SUPERVISOR_PID=999999
      run_case "${script%.sh}-early-failure-${signal,,}" 3 FAILURE "$script" \
        "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_TEST_STARTUP_SIGNAL="$signal"
    done
  done

  run_case "report-startup-signal-int" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_TEST_STARTUP_SIGNAL=INT
  run_case "report-signal-int" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL=INT
  assert_no_matching_path "report INT cleans temporary workspace" "$CASE_REPORT_DIR/.omega-report-work.*"
  NEXT_RM_ONESHOT=true
  NEXT_EXPECTED_STDERR="OMEGA_TEST_RM_FAIL_ONCE"
  run_case "report-int-one-shot-cleanup-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL=INT OMEGA_STUB_RM_MODE=fail-once
  assert_equal "report INT cleanup failure attempts removal once" "1" \
    "$(grep -Ec '^rm[[:space:]]' "$CASE_STUB_LOG")"
  assert_equal "report INT cleanup failure records one attempt" "1" \
    "$(<"$TEST_ROOT/cases/report-int-one-shot-cleanup-failure/rm-attempts")"
  assert_matching_path_exists "report INT cleanup failure retains evidence" \
    "$CASE_REPORT_DIR/.omega-report-work.*"

  for final_stage in descriptor display stage copy cleanup marker postpublish; do
    run_case "report-final-${final_stage}-int" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
      OMEGA_TEST_FINAL_SIGNAL_STAGE="$final_stage" OMEGA_TEST_FINAL_SIGNAL=INT
    assert_no_matching_path "report $final_stage INT leaves no report or incomplete publication" \
      "$CASE_REPORT_DIR/omega-report-*"
    assert_no_matching_path "report $final_stage INT removes its private stage" \
      "$CASE_REPORT_DIR/.omega-report-stage.*"
  done
  run_case "report-final-publication-int" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_MV_MODE=signal-after-move OMEGA_STUB_SIGNAL=INT
  assert_no_matching_path "report publication INT removes the interrupted publication" \
    "$CASE_REPORT_DIR/omega-report-*"
  assert_no_matching_path "report publication INT leaves no private stage" \
    "$CASE_REPORT_DIR/.omega-report-stage.*"
  run_case "report-final-publication-rm-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_MV_MODE=signal-after-move OMEGA_STUB_SIGNAL=TERM OMEGA_STUB_RM_MODE=fail-published
  assert_report_failure_evidence "report publication rollback failure"

  run_case "alerts-startup-signal-int" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_TEST_STARTUP_SIGNAL=INT
  run_case "alerts-signal-int" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL=INT
  assert_no_matching_path "alerts INT cleans temporary workspace" \
    "$TEST_ROOT/cases/alerts-signal-int/tmp/omega-alerts.*"
  NEXT_RM_ONESHOT=true
  NEXT_EXPECTED_STDERR="OMEGA_TEST_RM_FAIL_ONCE"
  run_case "alerts-int-one-shot-cleanup-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL=INT OMEGA_STUB_RM_MODE=fail-once
  assert_equal "alerts INT cleanup failure attempts removal once" "1" \
    "$(grep -Ec '^rm[[:space:]]' "$CASE_STUB_LOG")"
  assert_equal "alerts INT cleanup failure records one attempt" "1" \
    "$(<"$TEST_ROOT/cases/alerts-int-one-shot-cleanup-failure/rm-attempts")"
  assert_matching_path_exists "alerts INT cleanup failure retains evidence" \
    "$TEST_ROOT/cases/alerts-int-one-shot-cleanup-failure/tmp/omega-alerts.*"

  echo "Targeted signal tests passed: $PASS_COUNT"
  echo "Targeted signal tests failed: $FAIL_COUNT"
  (( FAIL_COUNT == 0 )) || exit 1
  exit 0
fi

echo "== production seam and aggregation guards =="
if grep -R -E 'OMEGA_(EVE_FILE|EVEBOX_URL|REPORT_DIR)' \
  "$REPO_ROOT/scripts/omega-summary.sh" "$REPO_ROOT/scripts/omega-alerts.sh" \
  "$REPO_ROOT/scripts/omega-doctor.sh" "$REPO_ROOT/scripts/omega-report.sh" \
  "$REPO_ROOT/scripts/omega-status.sh" "$REPO_ROOT/scripts/omega-health.sh" >/dev/null; then
  fail "production scripts contain removed test seams"
else
  pass "production scripts contain no fixture override seams"
fi
if grep -R -E '(^|[^[:alnum:]_])wc([[:space:]]|$)' \
  "$REPO_ROOT/scripts/omega-summary.sh" "$REPO_ROOT/scripts/omega-alerts.sh" \
  "$REPO_ROOT/scripts/omega-doctor.sh" "$REPO_ROOT/scripts/omega-report.sh" >/dev/null; then
  fail "telemetry scripts contain wc counting"
else
  pass "telemetry scripts contain no wc counting"
fi
if grep -R -E 'RESULT_CODE=[123]' \
  "$REPO_ROOT/scripts/omega-summary.sh" "$REPO_ROOT/scripts/omega-alerts.sh" \
  "$REPO_ROOT/scripts/omega-doctor.sh" "$REPO_ROOT/scripts/omega-report.sh" \
  "$REPO_ROOT/scripts/omega-status.sh" "$REPO_ROOT/scripts/omega-health.sh" >/dev/null; then
  fail "production scripts contain non-monotonic result assignments"
else
  pass "result changes use monotonic promotion"
fi
if grep -E '(mktemp -d|sort|tail -n [0-9]+)[[:space:]]+"\$' \
  "$REPO_ROOT/scripts/omega-alerts.sh" "$REPO_ROOT/scripts/omega-report.sh" >/dev/null; then
  fail "path operands are missing option terminators"
else
  pass "temporary and formatting path operands use option terminators"
fi
assert_signal_guard_order "alerts result emission closes the signal race" "$REPO_ROOT/scripts/omega-alerts.sh"
assert_signal_guard_order "report result emission closes the signal race" "$REPO_ROOT/scripts/omega-report.sh"

BLOCK_REFERENCE="$TEST_ROOT/runtime-input.reference"
for parser_script in omega-summary.sh omega-alerts.sh omega-report.sh omega-doctor.sh; do
  block_file="$TEST_ROOT/runtime-input.$parser_script"
  awk '/^# OMEGA_RUNTIME_INPUT_V1_BEGIN$/ { copy=1 } copy { print } /^# OMEGA_RUNTIME_INPUT_V1_END$/ { exit }' \
    "$REPO_ROOT/scripts/$parser_script" > "$block_file"
  block_lines=$(awk 'END { print NR }' "$block_file")
  if (( block_lines > 0 && block_lines <= 80 )); then
    pass "$parser_script runtime input block is readable and within 80 lines"
  else
    fail "$parser_script runtime input block has $block_lines lines"
  fi
  if [ ! -e "$BLOCK_REFERENCE" ]; then
    /usr/bin/cp -- "$block_file" "$BLOCK_REFERENCE"
  elif /usr/bin/cmp -s -- "$BLOCK_REFERENCE" "$block_file"; then
    pass "$parser_script runtime input block is byte-identical"
  else
    fail "$parser_script runtime input block diverges"
  fi
done
if grep -E 'sudo[[:space:]]+jq' "$REPO_ROOT/scripts/omega-summary.sh" "$REPO_ROOT/scripts/omega-alerts.sh" \
  "$REPO_ROOT/scripts/omega-report.sh" "$REPO_ROOT/scripts/omega-doctor.sh" >/dev/null; then
  fail "telemetry consumers retain privileged jq execution"
else
  pass "telemetry consumers use no sudo jq fallback"
fi
assert_contains "frozen installer already declares stat as a lifecycle dependency" "$REPO_ROOT/install.sh" "mktemp mv readlink rm rmdir sha256sum stat uname"
assert_contains "frozen installer already recognizes jq as a runtime integration" "$REPO_ROOT/install.sh" "curl docker jq sudo systemctl tailscale"

echo "== production shebang bootstrap boundary =="
HOSTILE_PRODUCTION_ENV="$TEST_ROOT/hostile-production-env"
HOSTILE_PRODUCTION_SENTINEL=/tmp/omega-hostile-production-env.executed
printf '/usr/bin/touch %s\nshopt -s expand_aliases\nalias echo="/usr/bin/touch %s"\njq() { /usr/bin/touch %s; }\nstat() { /usr/bin/touch %s; }\nfunction /usr/bin/stat { /usr/bin/touch %s; }\nfunction /usr/bin/readlink { /usr/bin/touch %s; }\nprintf "OMEGA_RESULT=SUCCESS\\n"\nexit 0\n' \
  "$HOSTILE_PRODUCTION_SENTINEL" "$HOSTILE_PRODUCTION_SENTINEL" "$HOSTILE_PRODUCTION_SENTINEL" \
  "$HOSTILE_PRODUCTION_SENTINEL" "$HOSTILE_PRODUCTION_SENTINEL" "$HOSTILE_PRODUCTION_SENTINEL" > "$HOSTILE_PRODUCTION_ENV"
for bootstrap_script in omega-summary.sh omega-alerts.sh omega-report.sh omega-doctor.sh; do
  /usr/bin/rm -f -- "$HOSTILE_PRODUCTION_SENTINEL"
  bootstrap_output="$TEST_ROOT/bootstrap-$bootstrap_script.out"
  bootstrap_error="$TEST_ROOT/bootstrap-$bootstrap_script.err"
  /usr/bin/env -i PATH="$ATTACKER_BIN:$TRUSTED_PATH" HOME="$TEST_ROOT" TMPDIR="$TEST_ROOT" LC_ALL=C \
    BASH_ENV="$HOSTILE_PRODUCTION_ENV" ENV="$HOSTILE_PRODUCTION_ENV" SHELLOPTS=xtrace BASHOPTS=extdebug \
    CDPATH="$ATTACKER_BIN" 'GLOBIGNORE=*' \
    'BASH_FUNC_jq%%=() { /usr/bin/touch /tmp/omega-hostile-production-env.executed; }' \
    'BASH_FUNC_stat%%=() { /usr/bin/touch /tmp/omega-hostile-production-env.executed; }' \
    'BASH_FUNC_/usr/bin/stat%%=() { /usr/bin/touch /tmp/omega-hostile-production-env.executed; }' \
    'BASH_FUNC_/usr/bin/readlink%%=() { /usr/bin/touch /tmp/omega-hostile-production-env.executed; }' \
    "$REPO_ROOT/scripts/$bootstrap_script" > "$bootstrap_output" 2> "$bootstrap_error"
  bootstrap_code=$?
  if [ "$bootstrap_code" -eq 2 ] || [ "$bootstrap_code" -eq 3 ]; then
    pass "$bootstrap_script shebang bootstrap fails closed without fixture environment"
  else
    fail "$bootstrap_script shebang bootstrap exit (expected 2 or 3, got $bootstrap_code)"
  fi
  assert_file_absent "$bootstrap_script ignores hostile inherited startup code" "$HOSTILE_PRODUCTION_SENTINEL"
  assert_equal "$bootstrap_script bootstrap emits one result" "1" \
    "$(grep -Ec '^OMEGA_RESULT=(SUCCESS|WARNING|UNKNOWN|FAILURE)$' "$bootstrap_output" || true)"
  assert_equal "$bootstrap_script bootstrap cannot forge success" "0" \
    "$(grep -Ec '^OMEGA_RESULT=SUCCESS$' "$bootstrap_output" || true)"
done

count_bootstrap_processes() {
  local process argument found count=0
  for process in /proc/[0-9]*; do
    [ -r "$process/cmdline" ] || continue
    found=false
    while IFS= read -r -d '' argument; do
      case "$argument" in *omega-bootstrap*|*omega-gate*) found=true; break ;; esac
    done < "$process/cmdline"
    [ "$found" = false ] || count=$((count + 1))
  done
  printf '%s\n' "$count"
}

for bootstrap_script in omega-summary.sh omega-alerts.sh omega-report.sh omega-doctor.sh; do
  for bootstrap_phase in startup transition ready; do
    for signal in HUP INT TERM; do
      label="$bootstrap_script $bootstrap_phase $signal bootstrap signal"
      bootstrap_output="$TEST_ROOT/${bootstrap_script%.sh}-$bootstrap_phase-${signal,,}.out"
      bootstrap_error="$TEST_ROOT/${bootstrap_script%.sh}-$bootstrap_phase-${signal,,}.err"
      /usr/bin/timeout -s KILL 5 /usr/bin/env -i PATH=/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LC_ALL=C \
        BASH_ENV="$BOOTSTRAP_GUARD" OMEGA_TEST_BOOTSTRAP_PHASE="$bootstrap_phase" \
        OMEGA_TEST_BOOTSTRAP_SIGNAL="$signal" "$REPO_ROOT/scripts/$bootstrap_script" \
        > "$bootstrap_output" 2> "$bootstrap_error"
      bootstrap_code=$?
      assert_equal "$label exits UNKNOWN" "2" "$bootstrap_code"
      assert_equal "$label emits exactly one marker" "1" \
        "$(grep -Ec '^OMEGA_RESULT=(SUCCESS|WARNING|UNKNOWN|FAILURE)$' "$bootstrap_output" || true)"
      assert_equal "$label final marker" "OMEGA_RESULT=UNKNOWN" \
        "$(awk 'NF { line=$0 } END { print line }' "$bootstrap_output")"
      assert_equal "$label leaves no bootstrap child" "0" "$(count_bootstrap_processes)"
      assert_stderr_empty "$label stderr is empty" "$bootstrap_error"
    done
  done
done

echo "== omega-summary =="
run_case "summary-success" 0 SUCCESS omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "summary accepts non-alert records without .alert" "$CASE_STDOUT" "DNS events observed: 1"
assert_contains "summary uses canonical telemetry path" "$CASE_STUB_LOG" "/var/log/suricata/eve.json"
/usr/bin/rm -f -- /tmp/omega-attacker-jq.executed /tmp/omega-attacker-stat.executed
run_case "summary-exported-security-functions" 0 SUCCESS omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  'BASH_FUNC_jq%%=() { /usr/bin/touch /tmp/omega-attacker-jq.executed; printf "0\t0\t0\t0\n"; }' \
  'BASH_FUNC_stat%%=() { /usr/bin/touch /tmp/omega-attacker-stat.executed; printf "regular file\t0\t755\n"; }'
assert_file_absent "exported jq function is never dispatched" /tmp/omega-attacker-jq.executed
assert_file_absent "exported stat function is never dispatched" /tmp/omega-attacker-stat.executed
run_case "summary-hostile-earlier-path" 0 SUCCESS omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  "PATH=$ATTACKER_BIN:$TRUSTED_PATH"
assert_file_absent "earlier PATH jq executable is never dispatched" /tmp/omega-attacker-jq.executed
assert_file_absent "earlier PATH stat executable is never dispatched" /tmp/omega-attacker-stat.executed
NEXT_COMMAND_SETUP="unsafe-command-directory"
run_case "summary-unsafe-command-directory" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_not_contains "unsafe command directory cannot create a false-safe summary" "$CASE_STDOUT" "No high-priority Suricata alerts"
NEXT_COMMAND_SETUP="unsafe-multihop-symlink"
run_case "summary-unsafe-multihop-symlink" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_not_contains "unsafe symlink hop cannot create a false-safe summary" "$CASE_STDOUT" "No high-priority Suricata alerts"
/usr/bin/rm -f -- /tmp/omega-attacker-jq.executed
NEXT_COMMAND_SETUP="canonical-candidate-swap"
run_case "summary-canonical-candidate-swap" 0 SUCCESS omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_HOSTNAME_MODE=swap-jq-candidate OMEGA_STUB_SWAP_TARGET="$ATTACKER_BIN/jq"
assert_file_absent "validated canonical jq dispatch ignores a swapped candidate link" /tmp/omega-attacker-jq.executed
run_case "summary-warning" 1 WARNING omega-summary.sh "$FIXTURE_DIR/eve-high-alert.jsonl"
assert_contains "summary reports high alert" "$CASE_STDOUT" "Higher-priority alerts detected"
run_case "summary-empty" 1 WARNING omega-summary.sh "$EMPTY_EVE"
assert_contains "summary empty telemetry is explicit" "$CASE_STDOUT" "telemetry is empty; alert safety cannot be determined"
assert_not_contains "summary empty telemetry is not false-safe" "$CASE_STDOUT" "No high-priority Suricata alerts"
run_case "summary-malformed" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-malformed.jsonl"
assert_not_contains "summary malformed input is not false-safe" "$CASE_STDOUT" "No high-priority Suricata alerts"
run_case "summary-invalid-alert" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-invalid-alert.jsonl"
run_case "summary-multiline-json" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-multiline.jsonl"
run_case "summary-two-records-one-line" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-two-records-one-line.jsonl"
run_case "summary-result-marker-data" 0 SUCCESS omega-summary.sh "$FIXTURE_DIR/eve-result-marker.jsonl"
run_case "summary-aggregation-failure" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=fail
run_case "summary-aggregation-invalid-output" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=bad-output
run_case "summary-active-output-error" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SYSTEMCTL_MODE=active-error
run_case "summary-nested-result-marker" 0 SUCCESS omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_HOSTNAME_MODE=result-injection
run_case "summary-ip-result-marker" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_IP_MODE=result-injection
assert_contains "summary rejects ambiguous Tailscale output" "$CASE_STDOUT" "Tailscale: Invalid or ambiguous output"
run_case "summary-invalid-tailscale-address" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_IP_MODE=invalid-address
run_case "summary-service-failure" 3 FAILURE omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_INACTIVE_UNIT=suricata
run_case "summary-failure-plus-unknown" 3 FAILURE omega-summary.sh "$FIXTURE_DIR/eve-malformed.jsonl" OMEGA_STUB_INACTIVE_UNIT=suricata
NEXT_INPUT_SETUP="telemetry-unreadable"
run_case "summary-unreadable-telemetry" 2 UNKNOWN omega-summary.sh "$FIXTURE_DIR/eve-clean.jsonl"

echo "== omega-status =="
run_case "status-success" 0 SUCCESS omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "status uses canonical EveBox URL" "$CASE_STUB_LOG" "https://localhost:5636"
run_case "status-warning" 1 WARNING omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_IP_MODE=no-tailscale
run_case "status-unknown" 2 UNKNOWN omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SYSTEMCTL_MODE=query-error
run_case "status-active-output-error" 2 UNKNOWN omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SYSTEMCTL_MODE=active-error
run_case "status-nested-result-marker" 0 SUCCESS omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_HOSTNAME_MODE=result-injection
run_case "status-ip-result-marker" 2 UNKNOWN omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_IP_MODE=result-injection
assert_contains "status rejects ambiguous Tailscale output" "$CASE_STDOUT" "Tailscale: Not found"
run_case "status-invalid-tailscale-address" 2 UNKNOWN omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_IP_MODE=invalid-address
run_case "status-failure" 3 FAILURE omega-status.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_INACTIVE_UNIT=suricata
assert_not_contains "status failure does not claim operational" "$CASE_STDOUT" "Status: Omega is operational."

echo "== omega-health =="
run_case "health-success" 0 SUCCESS omega-health.sh "$FIXTURE_DIR/eve-clean.jsonl"
run_case "health-warning" 1 WARNING omega-health.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_IP_MODE=fail
run_case "health-unknown" 2 UNKNOWN omega-health.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_DOCKER_MODE=fail
run_case "health-active-output-error" 2 UNKNOWN omega-health.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SYSTEMCTL_MODE=active-error
run_case "health-nested-result-marker" 0 SUCCESS omega-health.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_DOCKER_MODE=result-injection
run_case "health-failure" 3 FAILURE omega-health.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_INACTIVE_UNIT=suricata

echo "== omega-doctor =="
run_case "doctor-success" 0 SUCCESS omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "doctor simulates EveBox through curl" "$CASE_STUB_LOG" $'curl\t-k\t-s\t-I\t--max-time\t10\t--\thttps://localhost:5636'
assert_contains "doctor accepts a safe canonical system-command symlink" "$CASE_STDOUT" "[OK] Command found: jq"
assert_contains "doctor accepts the canonical Phase 2 OMEGA destination" "$CASE_STDOUT" "[OK] Command found: omega-bundle"
NEXT_COMMAND_SETUP="wrong-omega-destination"
run_case "doctor-wrong-omega-destination" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "doctor rejects an OMEGA command outside its canonical destination" "$CASE_STDOUT" "[FAIL] Missing command: omega-bundle"
NEXT_COMMAND_SETUP="unsafe-system-symlink"
run_case "doctor-unsafe-system-symlink" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "doctor rejects a system symlink with a writable target" "$CASE_STDOUT" "[FAIL] Missing command: jq"
NEXT_COMMAND_SETUP="unsafe-multihop-symlink"
run_case "doctor-unsafe-multihop-symlink" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "doctor rejects an unsafe intermediate symlink hop" "$CASE_STDOUT" "[FAIL] Missing command: jq"
NEXT_WITH_REPORT_DIR=false
run_case "doctor-warning" 1 WARNING omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
run_case "doctor-empty" 1 WARNING omega-doctor.sh "$EMPTY_EVE"
assert_contains "doctor empty telemetry is explicit" "$CASE_STDOUT" "telemetry is empty; alert safety cannot be determined"
run_case "doctor-unknown" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SYSTEMCTL_MODE=query-error
run_case "doctor-active-output-error" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SYSTEMCTL_MODE=active-error
run_case "doctor-malformed-log" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-malformed.jsonl"
run_case "doctor-invalid-alert" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-invalid-alert.jsonl"
run_case "doctor-multiline-json" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-multiline.jsonl"
run_case "doctor-two-records-one-line" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-two-records-one-line.jsonl"
run_case "doctor-result-marker-data" 0 SUCCESS omega-doctor.sh "$FIXTURE_DIR/eve-result-marker.jsonl"
run_case "doctor-aggregation-failure" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=fail
run_case "doctor-aggregation-invalid-output" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=bad-output
NEXT_WITH_HOME=false
run_case "doctor-unset-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "doctor explains unset HOME" "$CASE_STDOUT" "HOME is unset"
NEXT_HOME_VALUE="relative-home"
run_case "doctor-relative-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$TEST_ROOT/cases/doctor-traversal-home/home/../home"
run_case "doctor-traversal-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
CONTROL_HOME_ROOT="$TEST_ROOT/control-homes"
TAB_HOME="$CONTROL_HOME_ROOT/tab"$'\t'"home"
ESC_HOME="$CONTROL_HOME_ROOT/escape"$'\033'"home"
BELL_HOME="$CONTROL_HOME_ROOT/bell"$'\007'"home"
/usr/bin/mkdir -p -- "$TAB_HOME" "$ESC_HOME" "$BELL_HOME"
NEXT_HOME_VALUE="$TAB_HOME"
run_case "doctor-tab-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$ESC_HOME"
run_case "doctor-escape-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$BELL_HOME"
run_case "doctor-bell-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/mkdir -p -- "$TEST_ROOT/cases/doctor-symlink-home/real-home"
/usr/bin/ln -s -- "$TEST_ROOT/cases/doctor-symlink-home/real-home" "$TEST_ROOT/cases/doctor-symlink-home/home-link"
NEXT_HOME_VALUE="$TEST_ROOT/cases/doctor-symlink-home/home-link"
run_case "doctor-symlink-home" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/mkdir -p -- "$TEST_ROOT/cases/doctor-symlink-output/escape" "$TEST_ROOT/cases/doctor-symlink-output/home"
/usr/bin/ln -s -- "$TEST_ROOT/cases/doctor-symlink-output/escape" "$TEST_ROOT/cases/doctor-symlink-output/home/omega-reports"
NEXT_WITH_REPORT_DIR=false
run_case "doctor-symlink-output" 2 UNKNOWN omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
run_case "doctor-failure" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_INACTIVE_UNIT=suricata

echo "== omega-report =="
run_case "report-success" 0 SUCCESS omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_equal "report normalizes the opened telemetry descriptor once" "1" "$(grep -Ec '^jq[[:space:]]+-Rrc([[:space:]]|$)' "$CASE_STUB_LOG")"
assert_contains "report validates the opened descriptor" "$CASE_STUB_LOG" "/proc/self/fd/"
REPORT_FILE="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt"
assert_file_exists "report publishes completed file" "$REPORT_FILE"
assert_equal "completed report result is last" "OMEGA_RESULT=SUCCESS" "$(awk 'NF { line=$0 } END { print line }' "$REPORT_FILE")"

ORIGINAL_REPORT=$(<"$REPORT_FILE")
run_case "report-success" 0 SUCCESS omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_equal "existing valid report is unchanged" "$ORIGINAL_REPORT" "$(<"$REPORT_FILE")"
assert_file_exists "colliding report is published without replacement" "$REPORT_FILE.1"

run_case "report-empty" 1 WARNING omega-report.sh "$EMPTY_EVE"
REPORT_FILE="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt"
assert_file_exists "empty but valid report is complete" "$REPORT_FILE"
assert_contains "empty report does not claim safety" "$REPORT_FILE" "alert safety cannot be determined"

run_case "report-high-alert" 1 WARNING omega-report.sh "$FIXTURE_DIR/eve-high-alert.jsonl"
assert_contains "report records higher-priority alerts" "$CASE_STDOUT" "Higher-priority alerts: 1"

run_case "report-malformed" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-malformed.jsonl"
INCOMPLETE_FILE="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt.incomplete"
assert_file_exists "malformed report has incomplete designation" "$INCOMPLETE_FILE"
assert_equal "incomplete report result is last" "OMEGA_RESULT=UNKNOWN" "$(awk 'NF { line=$0 } END { print line }' "$INCOMPLETE_FILE")"
if [ -f "$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt" ]; then
  fail "malformed report does not publish a valid report filename"
else
  pass "malformed report does not publish a valid report filename"
fi

run_case "report-invalid-alert" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-invalid-alert.jsonl"
run_case "report-multiline-json" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-multiline.jsonl"
run_case "report-two-records-one-line" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-two-records-one-line.jsonl"
run_case "report-result-marker-data" 0 SUCCESS omega-report.sh "$FIXTURE_DIR/eve-result-marker.jsonl"
run_case "report-nested-result-marker" 0 SUCCESS omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_HOSTNAME_MODE=result-injection
run_case "report-aggregation-failure" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=fail
assert_file_exists "aggregation failure report is incomplete" "$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt.incomplete"
run_case "report-aggregation-invalid-output" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=bad-output
NEXT_WITH_HOME=false
run_case "report-unset-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_contains "report explains unset HOME" "$CASE_STDOUT" "HOME is unset"
NEXT_HOME_VALUE="relative-home"
run_case "report-relative-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$TEST_ROOT/cases/report-traversal-home/home/../home"
run_case "report-traversal-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$TAB_HOME"
run_case "report-tab-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$ESC_HOME"
run_case "report-escape-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_HOME_VALUE="$BELL_HOME"
run_case "report-bell-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/mkdir -p -- "$TEST_ROOT/cases/report-symlink-home/real-home"
/usr/bin/ln -s -- "$TEST_ROOT/cases/report-symlink-home/real-home" "$TEST_ROOT/cases/report-symlink-home/home-link"
NEXT_HOME_VALUE="$TEST_ROOT/cases/report-symlink-home/home-link"
run_case "report-symlink-home" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/mkdir -p -- "$TEST_ROOT/unsafe-home-parent/home"
/usr/bin/chmod 0777 -- "$TEST_ROOT/unsafe-home-parent"
NEXT_HOME_VALUE="$TEST_ROOT/unsafe-home-parent/home"
run_case "report-unsafe-home-parent" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/chmod 0700 -- "$TEST_ROOT/unsafe-home-parent"
run_case "report-home-wrong-owner" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=path-wrong-owner OMEGA_STUB_STAT_TARGET_KIND=home
run_case "report-home-replaced" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=replace-directory OMEGA_STUB_STAT_TARGET_KIND=home OMEGA_STUB_STAT_REPLACE_AT=2
/usr/bin/mkdir -p -- "$TEST_ROOT/cases/report-symlink-output/escape" "$TEST_ROOT/cases/report-symlink-output/home"
/usr/bin/ln -s -- "$TEST_ROOT/cases/report-symlink-output/escape" "$TEST_ROOT/cases/report-symlink-output/home/omega-reports"
NEXT_WITH_REPORT_DIR=false
run_case "report-symlink-output" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl"
run_case "report-output-writable" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=path-writable OMEGA_STUB_STAT_TARGET_KIND=output
run_case "report-output-replaced" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=replace-directory OMEGA_STUB_STAT_TARGET_KIND=output OMEGA_STUB_STAT_REPLACE_AT=2
run_case "report-workspace-wrong-mode" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=path-wrong-mode OMEGA_STUB_STAT_TARGET_KIND=workspace
run_case "report-workspace-replaced" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=replace-directory OMEGA_STUB_STAT_TARGET_KIND=workspace OMEGA_STUB_STAT_REPLACE_AT=3
run_case "report-stage-wrong-mode" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=path-wrong-mode OMEGA_STUB_STAT_TARGET_KIND=stage
run_case "report-stage-replaced" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=replace-file OMEGA_STUB_STAT_TARGET_KIND=stage OMEGA_STUB_STAT_REPLACE_AT=2
run_case "report-output-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_MKDIR_MODE=fail
run_case "report-publish-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_MV_MODE=fail
run_case "report-stable-display" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_MV_MODE=replace-target
assert_not_contains "report display is pinned to finalized content" "$CASE_STDOUT" "RACE_REPLACEMENT"
run_case "report-display-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_SED_MODE=fail-display
REPORT_FILE="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt"
assert_file_exists "display failure still publishes the completed diagnostic body" "$REPORT_FILE"
assert_equal "display failure stored marker matches final failure" "OMEGA_RESULT=FAILURE" \
  "$(awk 'NF { line=$0 } END { print line }' "$REPORT_FILE")"
NEXT_RM_ONESHOT=true
NEXT_EXPECTED_STDERR="OMEGA_TEST_RM_FAIL_ONCE"
run_case "report-normal-cleanup-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_RM_MODE=fail-once
assert_equal "report normal cleanup failure attempts removal once" "1" \
  "$(grep -Ec '^rm[[:space:]]' "$CASE_STUB_LOG")"
assert_equal "report normal cleanup failure records one attempt" "1" \
  "$(<"$TEST_ROOT/cases/report-normal-cleanup-failure/rm-attempts")"
assert_matching_path_exists "report normal cleanup failure retains evidence" \
  "$CASE_REPORT_DIR/.omega-report-work.*"
REPORT_FILE="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt"
assert_file_exists "cleanup failure publishes diagnostic report with final state" "$REPORT_FILE"
assert_equal "cleanup failure stored marker matches final failure" "OMEGA_RESULT=FAILURE" \
  "$(awk 'NF { line=$0 } END { print line }' "$REPORT_FILE")"
for signal in HUP INT TERM; do
  run_case "report-startup-signal-${signal,,}" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_TEST_STARTUP_SIGNAL="$signal"
done
for signal in HUP INT TERM; do
  run_case "report-signal-${signal,,}" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL="$signal"
  assert_no_matching_path "report $signal cleans temporary workspace" "$CASE_REPORT_DIR/.omega-report-work.*"
done
for signal in HUP INT TERM; do
  NEXT_RM_ONESHOT=true
  NEXT_EXPECTED_STDERR="OMEGA_TEST_RM_FAIL_ONCE"
  run_case "report-${signal,,}-one-shot-cleanup-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL="$signal" OMEGA_STUB_RM_MODE=fail-once
  assert_equal "report $signal cleanup failure attempts removal once" "1" \
    "$(grep -Ec '^rm[[:space:]]' "$CASE_STUB_LOG")"
  assert_equal "report $signal cleanup failure records one attempt" "1" \
    "$(<"$TEST_ROOT/cases/report-${signal,,}-one-shot-cleanup-failure/rm-attempts")"
  assert_matching_path_exists "report $signal cleanup failure retains evidence" \
    "$CASE_REPORT_DIR/.omega-report-work.*"
done
run_case "report-signal-cleanup-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL=TERM OMEGA_STUB_RM_MODE=fail
assert_contains "report signal cleanup failure is explicit" "$CASE_STDOUT" "temporary-workspace cleanup failed"
assert_matching_path_exists "report signal cleanup failure retains evidence" \
  "$CASE_REPORT_DIR/.omega-report-work.*"

for final_stage in descriptor display stage copy cleanup marker postpublish; do
  for signal in HUP INT TERM; do
    run_case "report-final-${final_stage}-${signal,,}" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
      OMEGA_TEST_FINAL_SIGNAL_STAGE="$final_stage" OMEGA_TEST_FINAL_SIGNAL="$signal"
    assert_no_matching_path "report $final_stage $signal leaves no report or incomplete publication" \
      "$CASE_REPORT_DIR/omega-report-*"
    assert_no_matching_path "report $final_stage $signal removes its private stage" \
      "$CASE_REPORT_DIR/.omega-report-stage.*"
  done
done
for signal in HUP INT TERM; do
  run_case "report-final-publication-${signal,,}" 2 UNKNOWN omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_MV_MODE=signal-after-move OMEGA_STUB_SIGNAL="$signal"
  assert_no_matching_path "report publication $signal removes the interrupted publication" \
    "$CASE_REPORT_DIR/omega-report-*"
  assert_no_matching_path "report publication $signal leaves no private stage" \
    "$CASE_REPORT_DIR/.omega-report-stage.*"
done
run_case "report-final-publication-rm-failure" 3 FAILURE omega-report.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_MV_MODE=signal-after-move OMEGA_STUB_SIGNAL=TERM OMEGA_STUB_RM_MODE=fail-published
assert_report_failure_evidence "report publication rollback failure"

echo "== omega-alerts =="
run_case "alerts-success" 0 SUCCESS omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl"
assert_equal "alerts normalizes the opened telemetry descriptor once" "1" "$(grep -Ec '^jq[[:space:]]+-Rrc([[:space:]]|$)' "$CASE_STUB_LOG")"
assert_contains "alerts validates the opened descriptor" "$CASE_STUB_LOG" "/proc/self/fd/"
NEXT_EXPECTED_STDERR="OMEGA_TEST_STDERR_AFTER_TELEMETRY"
run_case "alerts-stderr-after-telemetry-close" 0 SUCCESS omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_RM_MODE=stderr-probe
run_case "alerts-warning" 1 WARNING omega-alerts.sh "$FIXTURE_DIR/eve-high-alert.jsonl"
run_case "alerts-empty" 1 WARNING omega-alerts.sh "$EMPTY_EVE"
assert_contains "alerts empty telemetry is explicit" "$CASE_STDOUT" "telemetry is empty; alert safety cannot be determined"
assert_not_contains "alerts empty telemetry is not false-safe" "$CASE_STDOUT" "No higher-priority alerts detected"
run_case "alerts-malformed" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-malformed.jsonl"
assert_not_contains "alerts malformed input is not false-safe" "$CASE_STDOUT" "No higher-priority alerts detected"
run_case "alerts-invalid-alert" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-invalid-alert.jsonl"
run_case "alerts-multiline-json" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-multiline.jsonl"
run_case "alerts-two-records-one-line" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-two-records-one-line.jsonl"
run_case "alerts-result-marker-data" 0 SUCCESS omega-alerts.sh "$FIXTURE_DIR/eve-result-marker.jsonl"
run_case "alerts-nested-result-marker" 0 SUCCESS omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_HOSTNAME_MODE=result-injection
run_case "alerts-aggregation-failure" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=fail
run_case "alerts-aggregation-invalid-output" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_AGGREGATION_MODE=bad-output
run_case "alerts-workspace-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_MKTEMP_MODE=fail
NEXT_TMPDIR_VALUE=/tmp
run_case "alerts-root-sticky-temporary-base" 0 SUCCESS omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/mkdir -p -- "$TEST_ROOT/unsafe-tmp-parent/base"
/usr/bin/chmod 0777 -- "$TEST_ROOT/unsafe-tmp-parent"
NEXT_TMPDIR_VALUE="$TEST_ROOT/unsafe-tmp-parent/base"
run_case "alerts-unsafe-temporary-parent" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl"
/usr/bin/chmod 0700 -- "$TEST_ROOT/unsafe-tmp-parent"
run_case "alerts-temporary-base-wrong-owner" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=path-wrong-owner OMEGA_STUB_STAT_TARGET_KIND=temp-base
run_case "alerts-temporary-base-replaced" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=replace-directory OMEGA_STUB_STAT_TARGET_KIND=temp-base OMEGA_STUB_STAT_REPLACE_AT=2
run_case "alerts-workspace-wrong-mode" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=path-wrong-mode OMEGA_STUB_STAT_TARGET_KIND=workspace
run_case "alerts-workspace-replaced" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=replace-directory OMEGA_STUB_STAT_TARGET_KIND=workspace OMEGA_STUB_STAT_REPLACE_AT=3
run_case "alerts-temporary-stat-malformed" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=malformed-target OMEGA_STUB_STAT_TARGET_KIND=temp-base
run_case "alerts-temporary-stat-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_STAT_MODE=fail-target OMEGA_STUB_STAT_TARGET_KIND=temp-base
HOSTILE_TMP="$TEST_ROOT/hostile-tmp"$'\nOMEGA_RESULT=SUCCESS\npath'
NEXT_TMPDIR_VALUE="$HOSTILE_TMP"
run_case "alerts-hostile-tmpdir" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_RM_MODE=fail
assert_equal "hostile TMPDIR cannot forge a success result line" "0" \
  "$(grep -Ec '^OMEGA_RESULT=SUCCESS$' "$CASE_STDOUT" || true)"
run_case "alerts-hostile-workspace-cleanup-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_MKTEMP_MODE=hostile-path OMEGA_STUB_RM_MODE=fail
assert_contains "hostile retained workspace is rendered on one escaped line" "$CASE_STDOUT" "temporary-workspace cleanup failed; evidence was retained:"
assert_equal "hostile cleanup output has no forged success marker" "0" \
  "$(grep -Ec '^OMEGA_RESULT=SUCCESS$' "$CASE_STDOUT" || true)"
NEXT_RM_ONESHOT=true
NEXT_EXPECTED_STDERR="OMEGA_TEST_RM_FAIL_ONCE"
run_case "alerts-normal-cleanup-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" OMEGA_STUB_RM_MODE=fail-once
assert_equal "alerts normal cleanup failure attempts removal once" "1" \
  "$(grep -Ec '^rm[[:space:]]' "$CASE_STUB_LOG")"
assert_equal "alerts normal cleanup failure records one attempt" "1" \
  "$(<"$TEST_ROOT/cases/alerts-normal-cleanup-failure/rm-attempts")"
assert_matching_path_exists "alerts normal cleanup failure retains evidence" \
  "$TEST_ROOT/cases/alerts-normal-cleanup-failure/tmp/omega-alerts.*"
for signal in HUP INT TERM; do
  run_case "alerts-startup-signal-${signal,,}" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_TEST_STARTUP_SIGNAL="$signal"
done
for signal in HUP INT TERM; do
  run_case "alerts-signal-${signal,,}" 2 UNKNOWN omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL="$signal"
  assert_no_matching_path "alerts $signal cleans temporary workspace" "$TEST_ROOT/cases/alerts-signal-${signal,,}/tmp/omega-alerts.*"
done
for signal in HUP INT TERM; do
  NEXT_RM_ONESHOT=true
  NEXT_EXPECTED_STDERR="OMEGA_TEST_RM_FAIL_ONCE"
  run_case "alerts-${signal,,}-one-shot-cleanup-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
    OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL="$signal" OMEGA_STUB_RM_MODE=fail-once
  assert_equal "alerts $signal cleanup failure attempts removal once" "1" \
    "$(grep -Ec '^rm[[:space:]]' "$CASE_STUB_LOG")"
  assert_equal "alerts $signal cleanup failure records one attempt" "1" \
    "$(<"$TEST_ROOT/cases/alerts-${signal,,}-one-shot-cleanup-failure/rm-attempts")"
  assert_matching_path_exists "alerts $signal cleanup failure retains evidence" \
    "$TEST_ROOT/cases/alerts-${signal,,}-one-shot-cleanup-failure/tmp/omega-alerts.*"
done
run_case "alerts-signal-cleanup-failure" 3 FAILURE omega-alerts.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  OMEGA_STUB_JQ_MODE=signal-parent OMEGA_STUB_SIGNAL=TERM OMEGA_STUB_RM_MODE=fail
assert_contains "alerts signal cleanup failure is explicit" "$CASE_STDOUT" "temporary-workspace cleanup failed"
assert_matching_path_exists "alerts signal cleanup failure retains evidence" \
  "$TEST_ROOT/cases/alerts-signal-cleanup-failure/tmp/omega-alerts.*"

run_parser_matrix_case() {
  local label="$1" setup="$2" common_code="$3" common_result="$4" doctor_code="$5" doctor_result="$6"
  shift 6
  local parser_script parser_label expected_code expected_result incomplete_file valid_file

  for parser_script in omega-summary.sh omega-alerts.sh omega-report.sh omega-doctor.sh; do
    parser_label="${parser_script#omega-}"
    parser_label="${parser_label%.sh}"
    expected_code="$common_code"
    expected_result="$common_result"
    if [ "$parser_script" = omega-doctor.sh ]; then
      expected_code="$doctor_code"
      expected_result="$doctor_result"
    fi
    NEXT_INPUT_SETUP="$setup"
    run_case "$parser_label-$label" "$expected_code" "$expected_result" "$parser_script" "$FIXTURE_DIR/eve-clean.jsonl" "$@"
    if [ "$parser_script" = omega-report.sh ] && [ "$expected_code" = 2 ]; then
      incomplete_file="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt.incomplete"
      valid_file="$CASE_REPORT_DIR/omega-report-2026-08-24_10-00-00.txt"
      assert_file_exists "$parser_label-$label publishes one incomplete report" "$incomplete_file"
      assert_file_absent "$parser_label-$label never publishes a complete filename" "$valid_file"
      assert_equal "$parser_label-$label incomplete marker is final" "OMEGA_RESULT=UNKNOWN" \
        "$(awk 'NF { line=$0 } END { print line }' "$incomplete_file")"
    fi
  done
}

echo "== shared configuration parser matrix =="
run_parser_matrix_case "config-absent-file" default 0 SUCCESS 0 SUCCESS
run_parser_matrix_case "config-absent-directory" no-config-dir 0 SUCCESS 0 SUCCESS
run_parser_matrix_case "config-valid-default" valid-default 0 SUCCESS 0 SUCCESS
run_parser_matrix_case "config-valid-alternate" valid-alternate 0 SUCCESS 0 SUCCESS
run_parser_matrix_case "config-marker-path" config-fixture-result-marker 0 SUCCESS 0 SUCCESS

INVALID_CONFIG_SETUPS=(
  config-fixture-invalid-header config-missing-assignment config-fixture-duplicate-key
  config-fixture-unknown-key config-blank-line config-comment config-missing-newline
  config-oversized config-long-line config-mode-0600 config-mode-0664 config-symlink
  config-directory config-fifo parent-symlink parent-file parent-writable etc-writable
  config-relative config-root config-traversal config-double-separator config-trailing-separator
  config-leading-space config-trailing-space
)
for config_setup in "${INVALID_CONFIG_SETUPS[@]}"; do
  run_parser_matrix_case "$config_setup" "$config_setup" 2 UNKNOWN 3 FAILURE
done
run_parser_matrix_case "config-wrong-owner" valid-default 2 UNKNOWN 3 FAILURE OMEGA_STUB_STAT_MODE=config-wrong-owner
run_parser_matrix_case "config-parent-wrong-owner" valid-default 2 UNKNOWN 3 FAILURE OMEGA_STUB_STAT_MODE=parent-wrong-owner

for control_number in {0..31} 127; do
  printf -v control_label '%03d' "$control_number"
  run_parser_matrix_case "config-control-$control_label" "config-control-$control_number" 2 UNKNOWN 3 FAILURE
done

echo "== configuration acquisition uncertainty =="
run_parser_matrix_case "config-open-failure" config-unreadable 2 UNKNOWN 2 UNKNOWN OMEGA_STUB_STAT_MODE=config-open-fail
run_parser_matrix_case "config-descriptor-drift" valid-default 2 UNKNOWN 2 UNKNOWN OMEGA_STUB_STAT_MODE=config-drift
run_parser_matrix_case "config-parent-unsearchable" parent-unsearchable 2 UNKNOWN 2 UNKNOWN

echo "== telemetry object and snapshot matrix =="
for telemetry_setup in telemetry-missing telemetry-unreadable telemetry-directory telemetry-fifo telemetry-device telemetry-symlink; do
  run_parser_matrix_case "$telemetry_setup" "$telemetry_setup" 2 UNKNOWN 2 UNKNOWN
done
run_parser_matrix_case "telemetry-socket" default 2 UNKNOWN 2 UNKNOWN OMEGA_STUB_STAT_MODE=telemetry-socket
run_parser_matrix_case "telemetry-replaced-before-open" default 2 UNKNOWN 2 UNKNOWN OMEGA_STUB_STAT_MODE=rotate-before-open
run_parser_matrix_case "telemetry-replaced-after-read" default 2 UNKNOWN 2 UNKNOWN OMEGA_STUB_JQ_MODE=rotate-after-read
run_parser_matrix_case "telemetry-disappears-after-read" default 2 UNKNOWN 2 UNKNOWN OMEGA_STUB_JQ_MODE=disappear-after-read
run_parser_matrix_case "telemetry-same-inode-append" default 1 WARNING 0 SUCCESS \
  OMEGA_STUB_JQ_MODE=append-complete OMEGA_STUB_APPEND_FILE="$FIXTURE_DIR/eve-high-alert.jsonl"
run_parser_matrix_case "telemetry-partial-append" default 2 UNKNOWN 2 UNKNOWN \
  OMEGA_STUB_JQ_MODE=append-partial 'OMEGA_STUB_APPEND_TEXT={"event_type":"alert"'

echo "== doctor nine-command coverage =="
NEXT_MISSING_COMMAND="omega-bundle"
run_case "doctor-missing-bundle" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_MISSING_COMMAND="omega-cleanup"
run_case "doctor-missing-cleanup" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_MISSING_COMMAND="omega-bundle omega-cleanup"
run_case "doctor-missing-both" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"
NEXT_MISSING_COMMAND="omega-bundle"
run_case "doctor-exported-bundle-function" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl" \
  'BASH_FUNC_omega-bundle%%=() { printf exported-function-ran > "$OMEGA_STUB_STATE_DIR/exported-function-body"; }'
assert_file_absent "doctor never executes an exported omega-bundle function" \
  "$TEST_ROOT/cases/doctor-exported-bundle-function/exported-function-body"
assert_not_contains "doctor does not record a missing command as an approved stub" "$CASE_STUB_LOG" "omega-bundle"
NEXT_INPUT_SETUP="telemetry-missing"
NEXT_MISSING_COMMAND="omega-bundle"
run_case "doctor-failure-dominates-unknown-input" 3 FAILURE omega-doctor.sh "$FIXTURE_DIR/eve-clean.jsonl"

run_menu_case() {
  local selection="$1"
  local expected_command="$2"
  local child_code="$3"
  local label="menu-${selection}-exit-${child_code}"
  local case_dir="$TEST_ROOT/menu/$label"
  local output="$case_dir/stdout"
  local error="$case_dir/stderr"
  local input="$case_dir/input"
  local stub_log="$case_dir/stub.log"
  local exec_log="$case_dir/guard.log"
  local code

  mkdir -p "$case_dir/home" "$case_dir/tmp"
  printf '%s\n\n10\n' "$selection" > "$input"
  : > "$stub_log"
  : > "$exec_log"
  /usr/bin/env -i \
    "PATH=$TRUSTED_PATH" \
    "HOME=$case_dir/home" \
    "TMPDIR=$case_dir/tmp" \
    "LC_ALL=C" \
    "OMEGA_STUB_BIN=$STUB_BIN" \
    "OMEGA_TRUSTED_PATH=$TRUSTED_PATH" \
    "OMEGA_STUB_SOURCE=$STUB_SOURCE" \
    "OMEGA_STUB_LOG=$stub_log" \
    "OMEGA_REPO_ROOT=$REPO_ROOT" \
    "BASH_ENV=$EXEC_GUARD" \
    "OMEGA_EXEC_LOG=$exec_log" \
    "OMEGA_REAL_AWK=$REAL_AWK" \
    "OMEGA_REAL_CUT=$REAL_CUT" \
    "OMEGA_REAL_GREP=$REAL_GREP" \
    "OMEGA_REAL_SED=$REAL_SED" \
    "OMEGA_REAL_SORT=$REAL_SORT" \
    "OMEGA_REAL_TAIL=$REAL_TAIL" \
    "OMEGA_REAL_UNIQ=$REAL_UNIQ" \
    "OMEGA_REAL_JQ=$REAL_JQ" \
    "OMEGA_REAL_CP=$REAL_CP" \
    "OMEGA_REAL_MKDIR=$REAL_MKDIR" \
    "OMEGA_REAL_MKTEMP=$REAL_MKTEMP" \
    "OMEGA_REAL_MV=$REAL_MV" \
    "OMEGA_REAL_RM=$REAL_RM" \
    "OMEGA_REAL_STAT=$REAL_STAT" \
    "OMEGA_STUB_MENU_EXIT=$child_code" \
    /bin/bash "$REPO_ROOT/scripts/omega.sh" < "$input" > "$output" 2> "$error"
  code=$?

  assert_equal "$label menu exit code" "0" "$code"
  assert_contains "$label returns to menu" "$output" "Exiting Omega."
  assert_contains "$label invokes expected child" "$output" "STUB_COMMAND=$expected_command"
  assert_stderr_empty "$label stderr is empty" "$error"
  assert_stub_log_sealed "$label stub boundary is sealed" "$stub_log"
  assert_guard_log_sealed "$label guard execution log is sealed" "$exec_log"
}

echo "== omega menu caller compatibility =="
MENU_COMMANDS=(omega-status omega-health omega-report omega-alerts omega-summary omega-doctor omega-bundle omega-cleanup)
for selection in 1 2 3 4 5 6 7 8; do
  expected_command="${MENU_COMMANDS[$((selection-1))]}"
  for child_code in 1 2 3; do
    run_menu_case "$selection" "$expected_command" "$child_code"
  done
done

run_menu_ip_case() {
  local label="$1"
  local ip_mode="$2"
  local expected_text="$3"
  local case_dir="$TEST_ROOT/menu/$label"
  local output="$case_dir/stdout"
  local error="$case_dir/stderr"
  local input="$case_dir/input"
  local stub_log="$case_dir/stub.log"
  local exec_log="$case_dir/guard.log"
  local code
  local result_count

  mkdir -p "$case_dir/home" "$case_dir/tmp"
  printf '9\n\n10\n' > "$input"
  : > "$stub_log"
  : > "$exec_log"
  /usr/bin/env -i \
    "PATH=$TRUSTED_PATH" \
    "HOME=$case_dir/home" \
    "TMPDIR=$case_dir/tmp" \
    "LC_ALL=C" \
    "OMEGA_STUB_BIN=$STUB_BIN" \
    "OMEGA_TRUSTED_PATH=$TRUSTED_PATH" \
    "OMEGA_STUB_SOURCE=$STUB_SOURCE" \
    "OMEGA_STUB_LOG=$stub_log" \
    "OMEGA_REPO_ROOT=$REPO_ROOT" \
    "BASH_ENV=$EXEC_GUARD" \
    "OMEGA_EXEC_LOG=$exec_log" \
    "OMEGA_REAL_AWK=$REAL_AWK" \
    "OMEGA_REAL_CUT=$REAL_CUT" \
    "OMEGA_REAL_GREP=$REAL_GREP" \
    "OMEGA_REAL_SED=$REAL_SED" \
    "OMEGA_REAL_SORT=$REAL_SORT" \
    "OMEGA_REAL_TAIL=$REAL_TAIL" \
    "OMEGA_REAL_UNIQ=$REAL_UNIQ" \
    "OMEGA_REAL_JQ=$REAL_JQ" \
    "OMEGA_REAL_CP=$REAL_CP" \
    "OMEGA_REAL_MKDIR=$REAL_MKDIR" \
    "OMEGA_REAL_MKTEMP=$REAL_MKTEMP" \
    "OMEGA_REAL_MV=$REAL_MV" \
    "OMEGA_REAL_RM=$REAL_RM" \
    "OMEGA_REAL_STAT=$REAL_STAT" \
    "OMEGA_STUB_IP_MODE=$ip_mode" \
    /bin/bash "$REPO_ROOT/scripts/omega.sh" < "$input" > "$output" 2> "$error"
  code=$?

  result_count=$(grep -Ec '^OMEGA_RESULT=(SUCCESS|WARNING|UNKNOWN|FAILURE)$' "$output")
  assert_equal "$label menu exit code" "0" "$code"
  assert_contains "$label returns to menu" "$output" "Exiting Omega."
  assert_contains "$label displays expected result" "$output" "$expected_text"
  assert_equal "$label emits no injected result marker" "0" "$result_count"
  assert_stderr_empty "$label stderr is empty" "$error"
  assert_stub_log_sealed "$label stub boundary is sealed" "$stub_log"
  assert_guard_log_sealed "$label guard execution log is sealed" "$exec_log"
}

echo "== omega menu Tailscale validation =="
run_menu_ip_case "menu-9-valid-ip" ok "EveBox: https://100.64.0.40:5636"
run_menu_ip_case "menu-9-hostile-ip" result-injection "EveBox: unavailable (valid Tailscale IPv4 address not found)"
assert_not_contains "menu-9 hostile output is not interpolated" "$TEST_ROOT/menu/menu-9-hostile-ip/stdout" "OMEGA_RESULT=SUCCESS"

echo
echo "Tests passed: $PASS_COUNT"
echo "Tests failed: $FAIL_COUNT"

if (( FAIL_COUNT > 0 )); then
  exit 1
fi

exit 0
