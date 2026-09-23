#!/bin/sh

if [ -z "${BASH_VERSION:-}" ]; then
  CDPATH=
  case "$0" in /*) harness_path="$0" ;; *) harness_path="$(pwd -P)/$0" ;; esac
  host_repo=$(CDPATH= cd -P "${harness_path%/*}/.." 2>/dev/null && pwd -P) || exit 125
  exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C OMEGA_HARNESS_BOOT=1 \
    HOST_REPO_ROOT="$host_repo" /bin/bash --noprofile --norc "$host_repo/tests/test-install-lifecycle.sh" "$@"
  exit 125
fi

set -uo pipefail

isolation_error() {
  echo "ISOLATION FAILURE: $1" >&2
  exit 125
}

if [ "${OMEGA_HARNESS_STAGE:-}" = "" ]; then
  [ "${OMEGA_HARNESS_BOOT:-}" = 1 ] || isolation_error "unclean Bash startup"
  [[ "${HOST_REPO_ROOT:-}" == /* ]] && [ -d "$HOST_REPO_ROOT" ] || isolation_error "invalid repository root"
  for tool in /usr/bin/unshare /usr/bin/bwrap; do
    [ -f "$tool" ] && [ -x "$tool" ] && [ ! -L "$tool" ] || isolation_error "required boundary tool is unavailable: $tool"
  done
  exec /usr/bin/unshare --user --map-current-user --net \
    /usr/bin/bwrap --unshare-pid --unshare-ipc --unshare-uts --die-with-parent --new-session --cap-drop ALL \
    --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --proc /proc --dev /dev --tmpfs /tmp --dir /repo --ro-bind "$HOST_REPO_ROOT" /repo --chdir /repo \
    --clearenv --setenv PATH /usr/bin:/bin --setenv LC_ALL C --setenv OMEGA_HARNESS_STAGE supervisor \
    /bin/bash --noprofile --norc /repo/tests/test-install-lifecycle.sh "$@"
  isolation_error "namespace boundary could not be established"
fi

if [ "$OMEGA_HARNESS_STAGE" = supervisor ]; then
  [ ! -e /run ] && [ ! -e /var ] && [ ! -e /home ] && [ ! -w /repo/install.sh ] || isolation_error "restricted mount view is unsafe"
  capability=""
  while IFS=$'\t' read -r key value; do [ "$key" = CapEff: ] && capability="$value"; done < /proc/self/status
  [ "$capability" = 0000000000000000 ] || isolation_error "capabilities were not dropped"
  guard_file=/tmp/omega-lifecycle-guard.sh
  exec_log=/tmp/omega-lifecycle-exec.log
  /usr/bin/cat > "$guard_file" <<'GUARD'
_omega_lifecycle_guard() {
  local command="$BASH_COMMAND" first kind
  printf '%s\n' "$command" >> "$OMEGA_EXEC_LOG" || exit 125
  first=${command%%[[:space:]]*}
  case "$first" in
    mktemp|mkdir|cp|chmod|rm|grep|stat|wc|cmp|sha256sum|uname|readlink|mv|rmdir|sleep|ln) return ;;
    git) [[ "$command" == 'git -C '*" show "* ]] && return ;;
    env) [[ "$command" == *'/bin/bash "$script" '* ]] && return ;;
    exec) [[ "$command" == 'exec /bin/bash "$repo_root/install.sh" '* ]] && return ;;
    /bin/bash) [[ "$command" == '/bin/bash "$REPO_ROOT/scripts/install-omega-status.sh" '* ]] && return ;;
    command) [[ "$command" == 'command -v '* ]] && return ;;
    \(\(*|\[\[*|'') return ;;
  esac
  kind=$(type -t -- "$first" 2>/dev/null) || kind=""
  case "$kind" in builtin|keyword|function) return ;; esac
  [[ "$first" == *=* ]] && return
  printf 'ISOLATION FAILURE: forbidden command: %s\n' "$command" >&2
  exit 125
}
set -o functrace
trap _omega_lifecycle_guard DEBUG
GUARD
  chmod 0400 -- "$guard_file" || isolation_error "guard setup failed"
  : > "$exec_log"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C BASH_ENV="$guard_file" OMEGA_EXEC_LOG="$exec_log" \
    /bin/bash --noprofile --norc -c '/usr/bin/curl https://example.invalid/' >/dev/null 2>&1
  [ "$?" -eq 125 ] || isolation_error "absolute-command guard self-test failed"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C BASH_ENV="$guard_file" OMEGA_EXEC_LOG="$exec_log" \
    /bin/bash --noprofile --norc -c 'unsafe=/usr/bin/curl; "$unsafe" https://example.invalid/' >/dev/null 2>&1
  [ "$?" -eq 125 ] || isolation_error "indirect-command guard self-test failed"
  : > "$exec_log"
  if /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C BASH_ENV="$guard_file" OMEGA_EXEC_GUARD="$guard_file" \
    OMEGA_EXEC_LOG="$exec_log" OMEGA_HARNESS_STAGE=tests /bin/bash --noprofile --norc \
    /repo/tests/test-install-lifecycle.sh "$@"; then
    suite_status=0
  else
    suite_status=$?
  fi
  [ -s "$exec_log" ] || isolation_error "command audit was not produced"
  [ "$suite_status" -ne 125 ] || isolation_error "command guard rejected execution"
  echo "Isolation audit: PASS (clean Bash startup, user+network namespace, no capabilities, restricted mounts, DEBUG command allowlist)"
  exit "$suite_status"
fi

[ "$OMEGA_HARNESS_STAGE" = tests ] || isolation_error "invalid harness stage"
unset ENV CDPATH GLOBIGNORE HOST_REPO_ROOT OMEGA_HARNESS_BOOT OMEGA_HARNESS_STAGE
PATH=/usr/bin:/bin LC_ALL=C
export PATH LC_ALL BASH_ENV OMEGA_EXEC_GUARD OMEGA_EXEC_LOG
umask 077

WORKTREE_ROOT=/repo
TEST_ROOT=$(mktemp -d) || isolation_error "private workspace creation failed"
REPO_ROOT="$TEST_ROOT/release"
INSTALLER="$REPO_ROOT/install.sh"
MANIFEST="$REPO_ROOT/install/commands.manifest"
PASS_COUNT=0
FAIL_COUNT=0
CASE_CODE=0
CASE_OUT=""
CASE_ERR=""

mkdir -p -- "$REPO_ROOT/install" "$REPO_ROOT/scripts" || isolation_error "release workspace creation failed"
cp -- "$WORKTREE_ROOT/install.sh" "$WORKTREE_ROOT/uninstall.sh" "$REPO_ROOT/" || isolation_error "lifecycle copy failed"
cp -- "$WORKTREE_ROOT/install/commands.manifest" "$REPO_ROOT/install/commands.manifest" || isolation_error "manifest copy failed"
cp -- "$WORKTREE_ROOT/scripts/install-omega-commands.sh" \
  "$WORKTREE_ROOT/scripts/install-omega-status.sh" "$REPO_ROOT/scripts/" || isolation_error "wrapper copy failed"
while IFS=$'\t' read -r source destination rest; do
  [ "$source" != "OMEGA_COMMAND_MANIFEST_V1" ] || continue
  cp -- "$WORKTREE_ROOT/$source" "$REPO_ROOT/$source" || isolation_error "command copy failed: $source"
done < "$MANIFEST"
chmod 0755 -- "$REPO_ROOT/install.sh" "$REPO_ROOT/uninstall.sh" "$REPO_ROOT/scripts/"*.sh || isolation_error "release mode setup failed"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

pass() {
  echo "PASS: $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  echo "FAIL: $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

assert_equal() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then pass "$label"; else fail "$label (expected '$expected', got '$actual')"; fi
}

assert_contains() {
  local label="$1" file="$2" text="$3"
  if grep -Fq -- "$text" "$file"; then pass "$label"; else fail "$label (missing '$text')"; fi
}

assert_absent() {
  local label="$1" path="$2"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then pass "$label"; else fail "$label (unexpected path: $path)"; fi
}

assert_file() {
  local label="$1" path="$2"
  if [ -f "$path" ] && [ ! -L "$path" ]; then pass "$label"; else fail "$label (missing regular file: $path)"; fi
}

new_root() {
  local label="$1"
  CASE_ROOT="$TEST_ROOT/roots/$label"
  mkdir -p -- "$CASE_ROOT"
}

mark_test_root() {
  : > "$1/.omega-installer-test-root"
}

run_lifecycle() {
  local label="$1" expected="$2" root="$3" fault="$4" script="$5"
  shift 5
  local result_dir="$TEST_ROOT/results/$label"
  mkdir -p -- "$result_dir" "$root/home"
  CASE_OUT="$result_dir/stdout"
  CASE_ERR="$result_dir/stderr"
  if [ "$fault" = "-" ]; then
    if env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$root/home" BASH_ENV="$OMEGA_EXEC_GUARD" OMEGA_EXEC_LOG="$OMEGA_EXEC_LOG" \
      /bin/bash "$script" "$@" > "$CASE_OUT" 2> "$CASE_ERR"; then
      CASE_CODE=0
    else
      CASE_CODE=$?
    fi
  else
    if env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$root/home" BASH_ENV="$OMEGA_EXEC_GUARD" OMEGA_EXEC_LOG="$OMEGA_EXEC_LOG" OMEGA_INSTALL_TEST_FAULT="$fault" \
      /bin/bash "$script" "$@" > "$CASE_OUT" 2> "$CASE_ERR"; then
      CASE_CODE=0
    else
      CASE_CODE=$?
    fi
  fi
  assert_equal "$label exit code" "$expected" "$CASE_CODE"
}

start_paused_lifecycle() {
  local label="$1" root="$2" fault="$3" script="$4"
  shift 4
  local result_dir="$TEST_ROOT/results/$label"
  mkdir -p -- "$result_dir" "$root/home"
  CASE_OUT="$result_dir/stdout"; CASE_ERR="$result_dir/stderr"
  env --default-signal=HUP --default-signal=INT --default-signal=TERM -i \
    PATH=/usr/bin:/bin LC_ALL=C HOME="$root/home" BASH_ENV="$OMEGA_EXEC_GUARD" OMEGA_EXEC_LOG="$OMEGA_EXEC_LOG" OMEGA_INSTALL_TEST_FAULT="$fault" \
    /bin/bash "$script" "$@" > "$CASE_OUT" 2> "$CASE_ERR" &
  CASE_PID=$!
}

wait_for_pause() {
  local label="$1" root="$2" attempt
  for ((attempt=0; attempt<500; attempt++)); do
    [ -f "$root/.omega-command-layer.lock/test-ready" ] && return 0
    kill -0 "$CASE_PID" 2>/dev/null || break
    sleep 0.01
  done
  fail "$label reaches controlled pause"
  kill -KILL "$CASE_PID" 2>/dev/null || true
  wait "$CASE_PID" 2>/dev/null || true
  return 1
}

finish_paused_lifecycle() {
  local label="$1" expected="$2"
  kill -CONT "$CASE_PID" 2>/dev/null || true
  if wait "$CASE_PID"; then CASE_CODE=0; else CASE_CODE=$?; fi
  assert_equal "$label exit code" "$expected" "$CASE_CODE"
}

clone_release() {
  local destination="$1"
  cp -R -- "$REPO_ROOT" "$destination" || isolation_error "release clone failed"
  chmod 0755 -- "$destination/install.sh" "$destination/uninstall.sh" "$destination/scripts/"*.sh || isolation_error "release clone modes failed"
}

rewrite_file_value() {
  local path="$1" old="$2" new="$3" temporary="$1.rewrite" line
  while IFS= read -r line; do printf '%s\n' "${line//$old/$new}"; done < "$path" > "$temporary"
  chmod 0644 -- "$temporary" && mv -T -- "$temporary" "$path" || isolation_error "file rewrite failed"
}

rewrite_receipt_header() {
  local root="$1" header="$2" receipt="$1/var/lib/omega-command-layer/installed.tsv"
  local temporary="$receipt.rewrite" first=true line
  while IFS= read -r line; do
    if [ "$first" = true ]; then printf '%s\n' "$header"; first=false; else printf '%s\n' "$line"; fi
  done < "$receipt" > "$temporary"
  chmod 0600 -- "$temporary" && mv -T -- "$temporary" "$receipt" || isolation_error "receipt rewrite failed"
}

assert_transactions_present() {
  local label="$1" root="$2"
  if compgen -G "$root/usr/local/bin/.omega-transaction.*" >/dev/null ||
     compgen -G "$root/var/lib/omega-command-layer/.omega-state.*" >/dev/null; then
    pass "$label"
  else
    fail "$label"
  fi
}

assert_no_transactions() {
  local label="$1" root="$2"
  if compgen -G "$root/usr/local/bin/.omega-transaction.*" >/dev/null ||
     compgen -G "$root/var/lib/omega-command-layer/.omega-state.*" >/dev/null; then
    fail "$label"
  else
    pass "$label"
  fi
}

assert_no_lock() {
  assert_absent "$1 lifecycle lock is removed" "$2/.omega-command-layer.lock"
}

assert_installed_tree() {
  local label="$1" root="$2" header source destination mode legacy_hashes legacy_links extra
  local count=0 target source_path actual_mode
  while IFS=$'\t' read -r source destination mode legacy_hashes legacy_links extra; do
    [ "$source" != "OMEGA_COMMAND_MANIFEST_V1" ] || continue
    target="$root$destination"
    source_path="$REPO_ROOT/$source"
    if [ -f "$target" ] && [ ! -L "$target" ] && cmp -s -- "$source_path" "$target"; then
      pass "$label installs exact ${destination##*/}"
    else
      fail "$label installs exact ${destination##*/}"
    fi
    actual_mode=$(stat -c '%a' -- "$target" 2>/dev/null || true)
    assert_equal "$label mode ${destination##*/}" "755" "$actual_mode"
    count=$((count + 1))
  done < "$MANIFEST"
  assert_equal "$label command count" "9" "$count"
  assert_file "$label receipt exists" "$root/var/lib/omega-command-layer/installed.tsv"
  assert_equal "$label receipt mode" "600" "$(stat -c '%a' -- "$root/var/lib/omega-command-layer/installed.tsv")"
  assert_equal "$label receipt rows" "10" "$(wc -l < "$root/var/lib/omega-command-layer/installed.tsv")"
}

assert_uninstalled_tree() {
  local label="$1" root="$2" header source destination rest
  while IFS=$'\t' read -r source destination rest; do
    [ "$source" != "OMEGA_COMMAND_MANIFEST_V1" ] || continue
    assert_absent "$label removes ${destination##*/}" "$root$destination"
  done < "$MANIFEST"
  assert_absent "$label removes receipt" "$root/var/lib/omega-command-layer/installed.tsv"
}

echo "== manifest and production bounds =="
assert_equal "manifest has header plus nine rows" "10" "$(wc -l < "$MANIFEST")"
INSTALLER_LINES=$(wc -l < "$INSTALLER")
if ((INSTALLER_LINES <= 550)); then pass "installer stays within physical-line limit"; else fail "installer exceeds 550 physical lines"; fi
assert_contains "manifest installs doctor" "$MANIFEST" $'scripts/omega-doctor.sh\t/usr/local/bin/omega-doctor\t0755'
assert_contains "manifest uses hardened report" "$MANIFEST" $'scripts/omega-report.sh\t/usr/local/bin/omega-report\t0755'
if grep -q '^scripts/omega-report[[:space:]]' "$MANIFEST"; then fail "manifest excludes legacy report"; else pass "manifest excludes legacy report"; fi
assert_contains "command staging is on command filesystem" "$INSTALLER" 'mktemp -d -- "$BIN_DIR/.omega-transaction.XXXXXX"'
assert_contains "receipt staging is on state filesystem" "$INSTALLER" 'mktemp -d -- "$STATE_DIR/.omega-state.XXXXXX"'
MANIFEST_MODE=$(stat -c '%a' -- "$WORKTREE_ROOT/install/commands.manifest")
if [[ "$MANIFEST_MODE" =~ ^[4567][0145][0145]$ ]]; then pass "manifest permissions are safe"; else fail "manifest permissions are unsafe: $MANIFEST_MODE"; fi
assert_contains "runtime warnings include Tailscale" "$INSTALLER" 'tailscale)'
if grep -Fq -- "cat <<" "$INSTALLER"; then fail "help does not depend on cat"; else pass "help uses Bash builtins"; fi
if grep -Eq '(^|[;&|][[:space:]]*)(sudo|curl|docker|systemctl|tailscale)([[:space:]]|$)' "$INSTALLER"; then
  fail "installer does not invoke services, network, or sudo"
else
  pass "installer does not invoke services, network, or sudo"
fi

new_root checkout-mode
run_lifecycle "working checkout executable mode" 0 "$CASE_ROOT" - "$WORKTREE_ROOT/install.sh" install --dry-run --destdir "$CASE_ROOT"

new_root help
run_lifecycle "help" 0 "$CASE_ROOT" - "$INSTALLER" --help
assert_contains "help prints usage" "$CASE_OUT" "Usage:"

new_root duplicate-destdir
run_lifecycle "duplicate destdir" 2 "$CASE_ROOT" - "$INSTALLER" install --dry-run --destdir / --destdir "$CASE_ROOT"

UNSAFE_RELEASE="$TEST_ROOT/unsafe-manifest-release"
clone_release "$UNSAFE_RELEASE"
chmod 0664 -- "$UNSAFE_RELEASE/install/commands.manifest"
new_root unsafe-manifest
run_lifecycle "unsafe manifest permissions" 3 "$CASE_ROOT" - "$UNSAFE_RELEASE/install.sh" install --dry-run --destdir "$CASE_ROOT"

echo "== dry run and clean lifecycle =="
new_root dry-run
run_lifecycle "clean dry-run" 0 "$CASE_ROOT" - "$INSTALLER" install --dry-run --destdir "$CASE_ROOT"
assert_contains "dry-run is advisory" "$CASE_OUT" "advisory snapshot"
assert_absent "dry-run creates no usr tree" "$CASE_ROOT/usr"
assert_absent "dry-run creates no var tree" "$CASE_ROOT/var"
assert_no_lock "dry-run" "$CASE_ROOT"

new_root clean
run_lifecycle "clean install" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_installed_tree "clean install" "$CASE_ROOT"
assert_no_lock "clean install" "$CASE_ROOT"
run_lifecycle "repeated install" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_installed_tree "repeated install" "$CASE_ROOT"
run_lifecycle "clean uninstall" 0 "$CASE_ROOT" - "$INSTALLER" uninstall --destdir "$CASE_ROOT"
assert_uninstalled_tree "clean uninstall" "$CASE_ROOT"
assert_no_lock "clean uninstall" "$CASE_ROOT"
run_lifecycle "repeated uninstall" 0 "$CASE_ROOT" - "$INSTALLER" uninstall --destdir "$CASE_ROOT"

echo "== preservation =="
new_root preserve
mkdir -p -- "$CASE_ROOT/opt/omega/config" "$CASE_ROOT/opt/omega/reports" \
  "$CASE_ROOT/var/log/omega" "$CASE_ROOT/home/user/omega-reports" "$CASE_ROOT/home/user/omega-support-bundles"
printf 'config\n' > "$CASE_ROOT/opt/omega/config/devices.csv"
printf 'report\n' > "$CASE_ROOT/opt/omega/reports/keep.txt"
printf 'log\n' > "$CASE_ROOT/var/log/omega/keep.log"
printf 'user-report\n' > "$CASE_ROOT/home/user/omega-reports/keep.txt"
printf 'bundle\n' > "$CASE_ROOT/home/user/omega-support-bundles/keep.txt"
run_lifecycle "preservation install" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
run_lifecycle "preservation uninstall" 0 "$CASE_ROOT" - "$INSTALLER" uninstall --destdir "$CASE_ROOT"
assert_contains "configuration is preserved" "$CASE_ROOT/opt/omega/config/devices.csv" "config"
assert_contains "opt reports are preserved" "$CASE_ROOT/opt/omega/reports/keep.txt" "report"
assert_contains "logs are preserved" "$CASE_ROOT/var/log/omega/keep.log" "log"
assert_contains "user reports are preserved" "$CASE_ROOT/home/user/omega-reports/keep.txt" "user-report"
assert_contains "bundles are preserved" "$CASE_ROOT/home/user/omega-support-bundles/keep.txt" "bundle"

echo "== recognized legacy migration =="
new_root legacy-links
mkdir -p -- "$CASE_ROOT/usr/local/bin" "$CASE_ROOT/opt/omega/config"
ln -s -- /opt/omega/scripts/omega-health.sh "$CASE_ROOT/usr/local/bin/omega-health"
ln -s -- /opt/omega/scripts/omega-report "$CASE_ROOT/usr/local/bin/omega-report"
printf 'legacy-data\n' > "$CASE_ROOT/opt/omega/config/devices.csv"
run_lifecycle "legacy symlink install" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_installed_tree "legacy symlink install" "$CASE_ROOT"
assert_contains "legacy opt data survives migration" "$CASE_ROOT/opt/omega/config/devices.csv" "legacy-data"

new_root legacy-files
mkdir -p -- "$CASE_ROOT/usr/local/bin"
while IFS=$'\t' read -r source destination rest; do
  [ "$source" != "OMEGA_COMMAND_MANIFEST_V1" ] || continue
  [ "$source" != "scripts/omega-doctor.sh" ] || continue
  git -C "$WORKTREE_ROOT" show "main:$source" > "$CASE_ROOT$destination"
  chmod 0755 -- "$CASE_ROOT$destination"
done < "$MANIFEST"
run_lifecycle "legacy file install" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_installed_tree "legacy file install" "$CASE_ROOT"

echo "== collision and receipt refusal =="
new_root collision
mkdir -p -- "$CASE_ROOT/usr/local/bin"
printf 'unknown\n' > "$CASE_ROOT/usr/local/bin/omega"
chmod 0755 -- "$CASE_ROOT/usr/local/bin/omega"
UNKNOWN_HASH=$(sha256sum "$CASE_ROOT/usr/local/bin/omega")
run_lifecycle "unknown collision" 1 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_equal "unknown collision is unchanged" "$UNKNOWN_HASH" "$(sha256sum "$CASE_ROOT/usr/local/bin/omega")"
assert_absent "unknown collision publishes no doctor" "$CASE_ROOT/usr/local/bin/omega-doctor"
assert_absent "unknown collision creates no receipt" "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv"
assert_no_lock "unknown collision" "$CASE_ROOT"

new_root unsupported
mkdir -p -- "$CASE_ROOT/usr/local/bin/omega"
run_lifecycle "unsupported destination" 1 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_absent "unsupported destination creates no receipt" "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv"

new_root modified
run_lifecycle "modified baseline install" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
printf 'local-change\n' >> "$CASE_ROOT/usr/local/bin/omega"
MODIFIED_HASH=$(sha256sum "$CASE_ROOT/usr/local/bin/omega")
run_lifecycle "modified reinstall refusal" 1 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_equal "modified reinstall preserves file" "$MODIFIED_HASH" "$(sha256sum "$CASE_ROOT/usr/local/bin/omega")"
run_lifecycle "modified uninstall refusal" 1 "$CASE_ROOT" - "$INSTALLER" uninstall --destdir "$CASE_ROOT"
assert_equal "modified uninstall preserves file" "$MODIFIED_HASH" "$(sha256sum "$CASE_ROOT/usr/local/bin/omega")"
assert_file "modified uninstall preserves receipt" "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv"

new_root corrupt-receipt
run_lifecycle "corrupt receipt baseline" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
rewrite_receipt_header "$CASE_ROOT" $'OMEGA_STATE_V2\t0000000000000000000000000000000000000000000000000000000000000000'
run_lifecycle "corrupt receipt refusal" 1 "$CASE_ROOT" - "$INSTALLER" uninstall --destdir "$CASE_ROOT"
assert_file "corrupt receipt preserves omega" "$CASE_ROOT/usr/local/bin/omega"
assert_file "corrupt receipt is preserved" "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv"

VERSION_RELEASE="$TEST_ROOT/version-release"
clone_release "$VERSION_RELEASE"
new_root version-mismatch
run_lifecycle "version mismatch baseline" 0 "$CASE_ROOT" - "$VERSION_RELEASE/install.sh" install --destdir "$CASE_ROOT"
LEGACY_HASH=59e240e6dceaeb1817f5f40c5a41caf6a1787dec85d2a6d4c01fedcad17fa871
ZERO_HASH=0000000000000000000000000000000000000000000000000000000000000000
rewrite_file_value "$VERSION_RELEASE/install/commands.manifest" "$LEGACY_HASH" "$LEGACY_HASH,$ZERO_HASH"
run_lifecycle "same-release uninstall refusal" 1 "$CASE_ROOT" - "$VERSION_RELEASE/install.sh" uninstall --destdir "$CASE_ROOT"
assert_file "same-release refusal preserves omega" "$CASE_ROOT/usr/local/bin/omega"
assert_file "same-release refusal preserves receipt" "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv"

echo "== automatic rollback and incomplete-operation detection =="
new_root rollback-mid
mark_test_root "$CASE_ROOT"
run_lifecycle "mid-publication rollback" 4 "$CASE_ROOT" publish:4 "$INSTALLER" install --destdir "$CASE_ROOT"
assert_uninstalled_tree "mid-publication rollback" "$CASE_ROOT"
assert_no_lock "mid-publication rollback" "$CASE_ROOT"

new_root rollback-receipt
mark_test_root "$CASE_ROOT"
run_lifecycle "receipt-publication rollback" 4 "$CASE_ROOT" receipt "$INSTALLER" install --destdir "$CASE_ROOT"
assert_uninstalled_tree "receipt-publication rollback" "$CASE_ROOT"
assert_no_lock "receipt-publication rollback" "$CASE_ROOT"

new_root rollback-uninstall
run_lifecycle "rollback uninstall baseline" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
mark_test_root "$CASE_ROOT"
run_lifecycle "uninstall rollback" 4 "$CASE_ROOT" publish:5 "$INSTALLER" uninstall --destdir "$CASE_ROOT"
assert_installed_tree "uninstall rollback" "$CASE_ROOT"
assert_no_lock "uninstall rollback" "$CASE_ROOT"

UPGRADE_RELEASE="$TEST_ROOT/managed-upgrade-release"
clone_release "$UPGRADE_RELEASE"
new_root managed-upgrade
run_lifecycle "managed upgrade baseline" 0 "$CASE_ROOT" - "$UPGRADE_RELEASE/install.sh" install --destdir "$CASE_ROOT"
BASELINE_OMEGA_HASH=$(sha256sum "$CASE_ROOT/usr/local/bin/omega")
BASELINE_RECEIPT_HASH=$(sha256sum "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv")
printf '\n# managed upgrade fixture\n' >> "$UPGRADE_RELEASE/scripts/omega.sh"
chmod 0755 -- "$UPGRADE_RELEASE/scripts/omega.sh"
rewrite_file_value "$UPGRADE_RELEASE/install/commands.manifest" "$LEGACY_HASH" "$LEGACY_HASH,$ZERO_HASH"
mark_test_root "$CASE_ROOT"
run_lifecycle "managed upgrade rollback" 4 "$CASE_ROOT" publish:1 "$UPGRADE_RELEASE/install.sh" install --destdir "$CASE_ROOT"
assert_equal "managed upgrade restores command" "$BASELINE_OMEGA_HASH" "$(sha256sum "$CASE_ROOT/usr/local/bin/omega")"
assert_equal "managed upgrade restores receipt" "$BASELINE_RECEIPT_HASH" "$(sha256sum "$CASE_ROOT/var/lib/omega-command-layer/installed.tsv")"
assert_no_lock "managed upgrade rollback" "$CASE_ROOT"

MANIFEST_DRIFT_RELEASE="$TEST_ROOT/manifest-drift-release"
clone_release "$MANIFEST_DRIFT_RELEASE"
new_root manifest-drift
mark_test_root "$CASE_ROOT"
start_paused_lifecycle "manifest drift" "$CASE_ROOT" pause-after-stage "$MANIFEST_DRIFT_RELEASE/install.sh" install --destdir "$CASE_ROOT"
if wait_for_pause "manifest drift" "$CASE_ROOT"; then
  rewrite_file_value "$MANIFEST_DRIFT_RELEASE/install/commands.manifest" $'/usr/local/bin/omega\t0755' $'/usr/local/bin/omega-drift\t0755'
  finish_paused_lifecycle "manifest drift" 3
  assert_uninstalled_tree "manifest drift" "$CASE_ROOT"
  assert_absent "manifest drift publishes no alternate destination" "$CASE_ROOT/usr/local/bin/omega-drift"
  assert_no_lock "manifest drift" "$CASE_ROOT"
fi

SOURCE_DRIFT_RELEASE="$TEST_ROOT/source-drift-release"
clone_release "$SOURCE_DRIFT_RELEASE"
new_root source-drift
mark_test_root "$CASE_ROOT"
start_paused_lifecycle "source drift" "$CASE_ROOT" pause-after-stage "$SOURCE_DRIFT_RELEASE/install.sh" install --destdir "$CASE_ROOT"
if wait_for_pause "source drift" "$CASE_ROOT"; then
  printf '\n# source drift fixture\n' >> "$SOURCE_DRIFT_RELEASE/scripts/omega.sh"
  chmod 0755 -- "$SOURCE_DRIFT_RELEASE/scripts/omega.sh"
  finish_paused_lifecycle "source drift" 3
  assert_uninstalled_tree "source drift" "$CASE_ROOT"
  assert_no_lock "source drift" "$CASE_ROOT"
fi

new_root cleanup-transaction
mark_test_root "$CASE_ROOT"
run_lifecycle "transaction cleanup failure" 5 "$CASE_ROOT" cleanup-transaction "$INSTALLER" install --destdir "$CASE_ROOT"
assert_installed_tree "transaction cleanup failure" "$CASE_ROOT"
assert_transactions_present "transaction cleanup retains artifacts" "$CASE_ROOT"
assert_file "transaction cleanup retains lock" "$CASE_ROOT/.omega-command-layer.lock/pid"

new_root cleanup-lock
mark_test_root "$CASE_ROOT"
run_lifecycle "lock cleanup failure" 5 "$CASE_ROOT" cleanup-lock "$INSTALLER" install --destdir "$CASE_ROOT"
assert_installed_tree "lock cleanup failure" "$CASE_ROOT"
assert_no_transactions "lock cleanup removes transaction artifacts" "$CASE_ROOT"
assert_file "lock cleanup retains lock" "$CASE_ROOT/.omega-command-layer.lock/pid"

new_root rollback-incomplete
mark_test_root "$CASE_ROOT"
run_lifecycle "incomplete rollback" 5 "$CASE_ROOT" rollback-incomplete "$INSTALLER" install --destdir "$CASE_ROOT"
assert_uninstalled_tree "incomplete rollback" "$CASE_ROOT"
assert_transactions_present "incomplete rollback retains artifacts" "$CASE_ROOT"
assert_file "incomplete rollback retains lock" "$CASE_ROOT/.omega-command-layer.lock/pid"

for TEST_SIGNAL in HUP INT TERM; do
  new_root "signal-${TEST_SIGNAL,,}"
  mark_test_root "$CASE_ROOT"
  start_paused_lifecycle "signal ${TEST_SIGNAL}" "$CASE_ROOT" pause-after-publish "$INSTALLER" install --destdir "$CASE_ROOT"
  if wait_for_pause "signal ${TEST_SIGNAL}" "$CASE_ROOT"; then
    kill -s "$TEST_SIGNAL" "$CASE_PID"
    finish_paused_lifecycle "signal ${TEST_SIGNAL}" 4
    assert_uninstalled_tree "signal ${TEST_SIGNAL}" "$CASE_ROOT"
    assert_no_lock "signal ${TEST_SIGNAL}" "$CASE_ROOT"
  fi
done

new_root stale-lock
mkdir -- "$CASE_ROOT/.omega-command-layer.lock"
printf '99999999\n' > "$CASE_ROOT/.omega-command-layer.lock/pid"
run_lifecycle "stale lock refusal" 5 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_absent "stale lock publishes no command" "$CASE_ROOT/usr/local/bin/omega"

new_root live-lock
mkdir -- "$CASE_ROOT/.omega-command-layer.lock"
printf '%s\n' "$$" > "$CASE_ROOT/.omega-command-layer.lock/pid"
run_lifecycle "live lock refusal" 3 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
assert_absent "live lock publishes no command" "$CASE_ROOT/usr/local/bin/omega"

echo "== preflight, path safety, and runtime warnings =="
new_root missing-dependency
mark_test_root "$CASE_ROOT"
run_lifecycle "missing lifecycle dependency" 3 "$CASE_ROOT" missing-lifecycle:stat "$INSTALLER" install --destdir "$CASE_ROOT"
assert_absent "missing dependency creates no usr tree" "$CASE_ROOT/usr"

new_root runtime-warning
mark_test_root "$CASE_ROOT"
run_lifecycle "missing runtime warning" 0 "$CASE_ROOT" missing-runtime:docker "$INSTALLER" install --dry-run --destdir "$CASE_ROOT"
assert_contains "runtime dependency is warning only" "$CASE_ERR" "Runtime integration command not found: docker"
run_lifecycle "missing Tailscale warning" 0 "$CASE_ROOT" missing-runtime:tailscale "$INSTALLER" install --dry-run --destdir "$CASE_ROOT"
assert_contains "Tailscale dependency is warning only" "$CASE_ERR" "Runtime integration command not found: tailscale"

SOURCE_COPY="$TEST_ROOT/source-copy"
mkdir -p -- "$SOURCE_COPY/install" "$SOURCE_COPY/scripts"
cp -- "$INSTALLER" "$SOURCE_COPY/install.sh"
cp -- "$MANIFEST" "$SOURCE_COPY/install/commands.manifest"
while IFS=$'\t' read -r source destination rest; do
  [ "$source" != "OMEGA_COMMAND_MANIFEST_V1" ] || continue
  cp -- "$REPO_ROOT/$source" "$SOURCE_COPY/$source"
done < "$MANIFEST"
rm -- "$SOURCE_COPY/scripts/omega-doctor.sh"
new_root missing-source
run_lifecycle "missing source" 3 "$CASE_ROOT" - "$SOURCE_COPY/install.sh" install --dry-run --destdir "$CASE_ROOT"

new_root traversal
run_lifecycle "traversal destdir" 2 "$CASE_ROOT" - "$INSTALLER" install --dry-run --destdir "$CASE_ROOT/../traversal"

CONTROL_ROOT="$TEST_ROOT/roots/control"$'\t'"root"
mkdir -p -- "$CONTROL_ROOT"
run_lifecycle "control-character destdir" 2 "$CONTROL_ROOT" - "$INSTALLER" install --dry-run --destdir "$CONTROL_ROOT"

REAL_ROOT="$TEST_ROOT/roots/real-root"
LINK_ROOT="$TEST_ROOT/roots/link-root"
mkdir -p -- "$REAL_ROOT"
ln -s -- "$REAL_ROOT" "$LINK_ROOT"
run_lifecycle "symlink destdir" 2 "$LINK_ROOT" - "$INSTALLER" install --dry-run --destdir "$LINK_ROOT"

echo "== compatibility wrappers =="
new_root command-wrapper
run_lifecycle "command installer wrapper" 0 "$CASE_ROOT" - "$REPO_ROOT/scripts/install-omega-commands.sh" --dry-run --destdir "$CASE_ROOT"
assert_absent "command wrapper dry-run is non-mutating" "$CASE_ROOT/usr"

new_root uninstall-wrapper
run_lifecycle "uninstall wrapper baseline" 0 "$CASE_ROOT" - "$INSTALLER" install --destdir "$CASE_ROOT"
run_lifecycle "uninstall wrapper" 0 "$CASE_ROOT" - "$REPO_ROOT/uninstall.sh" --destdir "$CASE_ROOT"
assert_uninstalled_tree "uninstall wrapper" "$CASE_ROOT"

STATUS_OUT="$TEST_ROOT/results/status-deprecation.stdout"
STATUS_ERR="$TEST_ROOT/results/status-deprecation.stderr"
if /bin/bash "$REPO_ROOT/scripts/install-omega-status.sh" > "$STATUS_OUT" 2> "$STATUS_ERR"; then
  STATUS_CODE=0
else
  STATUS_CODE=$?
fi
assert_equal "status installer deprecation exit code" "2" "$STATUS_CODE"
assert_contains "status installer is explicitly non-mutating" "$STATUS_ERR" "no files were changed"
assert_contains "status installer points to canonical installer" "$STATUS_ERR" "./install.sh install"

echo
echo "Tests passed: $PASS_COUNT"
echo "Tests failed: $FAIL_COUNT"
if ((FAIL_COUNT > 0)); then exit 1; fi
exit 0
