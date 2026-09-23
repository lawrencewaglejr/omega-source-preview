#!/bin/bash -p
set -euo pipefail

IFS=$' \t\n'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
hash -r
umask 0077
export LC_ALL=C

PROGRAM=${0##*/}

die() {
  printf '%s: %s\n' "$PROGRAM" "$*" >&2
  exit 1
}

reject_unsafe_environment() {
  local variable
  local -a unsafe_variables=(
    BASH_ENV ENV CDPATH GLOBIGNORE
    GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG
    GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM
    GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM
    GIT_REPLACE_REF_BASE GIT_NAMESPACE GIT_ATTR_NOSYSTEM GIT_OPTIONAL_LOCKS
    GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND GIT_ASKPASS SSH_ASKPASS
    GIT_TERMINAL_PROMPT
  )
  for variable in "${unsafe_variables[@]}"; do
    [[ -v "$variable" ]] && die "UNSAFE_ENVIRONMENT=$variable"
  done
  return 0
}

reject_unsafe_environment
unset BASH_ENV ENV CDPATH GLOBIGNORE

readonly MKTEMP_TOOL=/usr/bin/mktemp
readonly RM_TOOL=/usr/bin/rm
readonly RMDIR_TOOL=/usr/bin/rmdir
readonly CP_TOOL=/usr/bin/cp
readonly MKDIR_TOOL=/usr/bin/mkdir
readonly SED_TOOL=/usr/bin/sed
readonly GIT_TOOL=/usr/bin/git
readonly ENV_TOOL=/usr/bin/env
readonly CAT_TOOL=/usr/bin/cat
readonly STAT_TOOL=/usr/bin/stat
readonly ID_TOOL=/usr/bin/id
readonly READLINK_TOOL=/usr/bin/readlink
readonly DIRNAME_TOOL=/usr/bin/dirname
readonly PYTHON_TOOL=/usr/bin/python3
readonly CHMOD_TOOL=/usr/bin/chmod
readonly LN_TOOL=/usr/bin/ln
readonly MKFIFO_TOOL=/usr/bin/mkfifo
readonly MV_TOOL=/usr/bin/mv
readonly HEAD_TOOL=/usr/bin/head
readonly SLEEP_TOOL=/usr/bin/sleep
readonly UNSHARE_TOOL=/usr/bin/unshare

SCRIPT_DIR=$($READLINK_TOOL -f -- "$($DIRNAME_TOOL -- "${BASH_SOURCE[0]}")")
REPOSITORY_ROOT=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../..")
VERIFY="$REPOSITORY_ROOT/image/scripts/verify.sh"
BUILD="$REPOSITORY_ROOT/image/scripts/build.sh"
NETWORK_NAMESPACE_EXEC="$REPOSITORY_ROOT/image/scripts/network-namespace-exec.py"
SELF="$SCRIPT_DIR/test-builder-foundation.sh"

TEST_ROOT=
TEST_ROOT_IDENTITY=
CLEANUP_ENABLED=false
CLEANUP_DONE=false
PASS_COUNT=0
FAIL_COUNT=0

validate_private_temp_root() {
  local root=$1 owner mode identity canonical
  canonical=$($READLINK_TOOL -f -- "$root") || return 1
  [ "$canonical" = "$root" ] || return 1
  [[ "$root" =~ ^/tmp/omega-phase4-builder-foundation\.[A-Za-z0-9]{8}$ ]] || return 1
  [ -d "$root" ] && [ ! -L "$root" ] || return 1
  owner=$($STAT_TOOL -c %u -- "$root") || return 1
  [ "$owner" = "$($ID_TOOL -u)" ] || return 1
  mode=$($STAT_TOOL -c %a -- "$root") || return 1
  [ "$mode" = 700 ] || return 1
  identity=$($STAT_TOOL -c '%d:%i' -- "$root") || return 1
  if [ -n "$TEST_ROOT_IDENTITY" ]; then
    [ "$identity" = "$TEST_ROOT_IDENTITY" ] || return 1
  fi
}

create_test_root() {
  local mktemp_path=$1 candidate
  if ! candidate=$($mktemp_path -d --tmpdir=/tmp 'omega-phase4-builder-foundation.XXXXXXXX' 2>/dev/null); then
    die 'TEST_TEMP_ROOT_CREATE_FAILED=YES'
  fi
  TEST_ROOT=$($READLINK_TOOL -f -- "$candidate") || die 'TEST_TEMP_ROOT_CANONICALIZATION_FAILED=YES'
  validate_private_temp_root "$TEST_ROOT" || die 'TEST_TEMP_ROOT_VALIDATION_FAILED=YES'
  TEST_ROOT_IDENTITY=$($STAT_TOOL -c '%d:%i' -- "$TEST_ROOT") ||
    die 'TEST_TEMP_ROOT_IDENTITY_FAILED=YES'
  CLEANUP_ENABLED=true
}

cleanup() {
  [ "$CLEANUP_ENABLED" = true ] || return 0
  [ "$CLEANUP_DONE" = false ] || return 0
  CLEANUP_DONE=true
  validate_private_temp_root "$TEST_ROOT" || {
    printf '%s: TEST_TEMP_ROOT_CLEANUP_REFUSED=YES\n' "$PROGRAM" >&2
    return 1
  }
  $RM_TOOL -rf --one-file-system -- "$TEST_ROOT"
  CLEANUP_ENABLED=false
}

handle_signal() {
  local status=$1 cleanup_status=0
  trap - EXIT HUP INT TERM
  cleanup || cleanup_status=$?
  exit "$status"
}

install_cleanup_traps() {
  trap cleanup EXIT
  trap 'handle_signal 129' HUP
  trap 'handle_signal 130' INT
  trap 'handle_signal 143' TERM
}

if [ "${1:-}" = --self-test-mktemp-failure ]; then
  [ "$#" -eq 1 ] || die 'SELF_TEST_ARGUMENTS_INVALID=YES'
  create_test_root /usr/bin/false
  die 'SELF_TEST_MKTEMP_FAILURE_NOT_DETECTED=YES'
fi

create_test_root "$MKTEMP_TOOL"
install_cleanup_traps

if [ "${1:-}" = --self-test-temp-root ]; then
  [ "$#" -eq 1 ] || die 'SELF_TEST_ARGUMENTS_INVALID=YES'
  printf 'TEST_TEMP_ROOT_VALID=YES\n'
  exit 0
fi

if [ "${1:-}" = --signal-fixture ]; then
  [ "$#" -eq 1 ] || die 'SELF_TEST_ARGUMENTS_INVALID=YES'
  printf 'SIGNAL_FIXTURE_ROOT=%s\n' "$TEST_ROOT"
  while :; do
    $SLEEP_TOOL 1
  done
fi

[ "$#" -eq 0 ] || die 'UNKNOWN_TEST_ARGUMENT=YES'

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS: %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf 'FAIL: %s\n' "$1" >&2
}

run_case_exact() {
  local label=$1 expected_status=$2 expected_output=$3
  shift 3
  local output status output_file="$TEST_ROOT/output"
  : > "$output_file"
  if "$@" > "$output_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  output=$($CAT_TOOL -- "$output_file")
  if [ "$status" -ne "$expected_status" ]; then
    fail "$label status expected=$expected_status actual=$status output=$output"
    return
  fi
  if [ "$output" != "$expected_output" ]; then
    fail "$label output expected=$expected_output actual=$output"
    return
  fi
  pass "$label"
}

run_case_contains() {
  local label=$1 expected_status=$2 expected_text=$3
  shift 3
  local output status output_file="$TEST_ROOT/output"
  : > "$output_file"
  if "$@" > "$output_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  output=$($CAT_TOOL -- "$output_file")
  if [ "$status" -ne "$expected_status" ]; then
    fail "$label status expected=$expected_status actual=$status output=$output"
    return
  fi
  if [[ "$output" != *"$expected_text"* ]]; then
    fail "$label missing text=$expected_text output=$output"
    return
  fi
  pass "$label"
}

copy_foundation() {
  local destination=$1
  $MKDIR_TOOL -p -- "$destination"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/config" "$destination/config"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/locks" "$destination/locks"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/bdebstrap" "$destination/bdebstrap"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/host-tools" "$destination/host-tools"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/layer" "$destination/layer"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/rootfs-overlay" "$destination/rootfs-overlay"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/scripts" "$destination/scripts"
  $CP_TOOL -a -- "$REPOSITORY_ROOT/image/post-build.sh" "$destination/post-build.sh"
}

fresh_foundation() {
  local name=$1 destination="$TEST_ROOT/$1"
  copy_foundation "$destination"
  printf '%s' "$destination"
}

git_fixture() {
  $ENV_TOOL -i \
    PATH="$PATH" HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    $GIT_TOOL -c core.fsmonitor=false -c core.untrackedCache=false "$@"
}

make_additive_descendant() {
  local name=$1 destination="$TEST_ROOT/source-$1"
  git_fixture -c protocol.file.allow=always clone -q --no-hardlinks -- "$REPOSITORY_ROOT" "$destination"
  git_fixture -C "$destination" config user.name omega-test
  git_fixture -C "$destination" config user.email omega-test.invalid
  printf 'phase 4 fixture\n' > "$destination/phase4-fixture.txt"
  git_fixture -C "$destination" add phase4-fixture.txt
  git_fixture -C "$destination" -c commit.gpgsign=false commit -q -m phase4-fixture
  printf '%s' "$destination"
}

unset_proxy_env=(
  -u http_proxy -u https_proxy -u ftp_proxy -u all_proxy
  -u HTTP_PROXY -u HTTPS_PROXY -u FTP_PROXY -u ALL_PROXY
)

FOUNDATION_OUTPUT=$'IMAGE_PAYLOAD_VALID=YES\nBUILDER_FOUNDATION_VALID=YES\nSTATIC_GEOMETRY_VALID=YES\nBUILDER_RELEASE_AUTHENTICATION=OPERATIONALLY-APPROVED-BY-HUMAN-RISK-ACCEPTANCE\nRASPBERRYPI_REPOSITORY_TRUST=OPERATIONALLY-APPROVED-BY-HUMAN-RISK-ACCEPTANCE\nBUILDER_CONFIG_COMPATIBILITY=VERIFIED-LOCAL-PLAN\nNETWORK_ISOLATION=ENFORCED-BY-BUILD-WRAPPER-USER-AND-NETWORK-NAMESPACE\nSERVICE_PACKAGE_LOCK=RESOLVED\nOCI_IMAGE_LOCK=RESOLVED\nBUILD_READINESS=READY'
SERVICE_LOCK_OUTPUT="$FOUNDATION_OUTPUT"$'\nSERVICE_LOCKS=RESOLVED'
READINESS_OUTPUT="$FOUNDATION_OUTPUT"$'\nBUILD_READINESS_CHECK=PASS'

run_case_exact 'canonical foundation validates with ready status' 0 "$FOUNDATION_OUTPUT" "$VERIFY"
run_case_exact 'resolved service locks pass' 0 "$SERVICE_LOCK_OUTPUT" \
  "$VERIFY" --require-service-locks
run_case_exact 'resolved build readiness passes' 0 "$READINESS_OUTPUT" \
  "$VERIFY" --require-build-readiness
run_case_exact 'arm64 architecture accepted' 0 'ARCHITECTURE_VALID=arm64' \
  "$VERIFY" --check-architecture arm64
run_case_exact 'non-arm64 architecture rejected' 1 \
  'verify.sh: unsupported build architecture: x86_64; expected native arm64' \
  "$VERIFY" --check-architecture x86_64
run_case_contains 'absolute required tools validate and report provenance' 0 \
  'BUILD_TOOLS_VALID=YES' "$BUILD" --check-tools
run_case_contains 'missing absolute required tool rejected' 1 \
  'required absolute build tool is unavailable: /usr/bin/omega-intentionally-missing' \
  $ENV_TOOL OMEGA_REQUIRED_TOOLS_EXTRA=omega-intentionally-missing "$BUILD" --check-tools
run_case_contains 'offline declaration creates verified construction isolation' 0 \
  'CONSTRUCTION_NETWORK_ISOLATION=VERIFIED' \
  $ENV_TOOL "${unset_proxy_env[@]}" OMEGA_NETWORK_MODE=offline "$BUILD" --check-network
run_case_exact 'undeclared offline environment rejected' 1 \
  'build.sh: OFFLINE_ENVIRONMENT_DECLARATION=MISSING' \
  $ENV_TOOL "${unset_proxy_env[@]}" OMEGA_NETWORK_MODE=online "$BUILD" --check-network
run_case_exact 'proxy input rejected' 1 'build.sh: UNDECLARED_PROXY_INPUT=HTTPS_PROXY' \
  $ENV_TOOL "${unset_proxy_env[@]}" OMEGA_NETWORK_MODE=offline HTTPS_PROXY=http://127.0.0.1:9 \
  "$BUILD" --check-network

host_network_namespace=$($READLINK_TOOL /proc/self/ns/net)
run_case_exact 'construction wrapper rejects the host network namespace' 1 \
  'NETWORK_NAMESPACE_ERROR=NOT_ISOLATED' \
  "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace"
run_case_contains 'construction wrapper accepts a loopback-only network namespace' 0 \
  'CONSTRUCTION_NETWORK_ISOLATION=VERIFIED' \
  "$UNSHARE_TOOL" -Urn -- "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace"
host_mount_namespace=$($READLINK_TOOL /proc/self/ns/mnt)
run_case_exact 'construction wrapper rejects shared host mounts' 1 \
  'NETWORK_NAMESPACE_ERROR=MOUNT_NAMESPACE_NOT_ISOLATED' \
  "$UNSHARE_TOOL" -Urn -- "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace" \
    --host-mount-namespace "$host_mount_namespace"
run_case_contains 'construction wrapper accepts private mounts' 0 \
  'CONSTRUCTION_MOUNT_ISOLATION=VERIFIED' \
  "$UNSHARE_TOOL" -Urnm -- "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace" \
    --host-mount-namespace "$host_mount_namespace"
run_case_exact 'construction wrapper rejects a single mapped user' 1 \
  'NETWORK_NAMESPACE_ERROR=UID_MAPPING_INSUFFICIENT' \
  "$UNSHARE_TOOL" -Urn -- "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace" \
    --require-subordinate-mapping
run_case_contains 'construction wrapper executes an absolute command after verification' 0 \
  'ISOLATED_COMMAND_EXECUTED=YES' \
  "$UNSHARE_TOOL" -Urn -- "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace" -- \
    /usr/bin/printf 'ISOLATED_COMMAND_EXECUTED=YES\n'
run_case_exact 'construction wrapper rejects a relative command' 1 \
  'NETWORK_NAMESPACE_ERROR=COMMAND_NOT_ABSOLUTE' \
  "$UNSHARE_TOOL" -Urn -- "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
    --host-network-namespace "$host_network_namespace" -- printf rejected

hostile_env="$TEST_ROOT/hostile-bash-env"
hostile_marker="$TEST_ROOT/bash-env-executed"
printf '/usr/bin/printf executed > %q\n' "$hostile_marker" > "$hostile_env"
run_case_exact 'verify ignores hostile BASH_ENV startup content' 1 \
  'verify.sh: UNSAFE_ENVIRONMENT=BASH_ENV' \
  $ENV_TOOL BASH_ENV="$hostile_env" "$VERIFY" --check-architecture arm64
run_case_exact 'build ignores hostile BASH_ENV startup content' 1 \
  'build.sh: UNSAFE_ENVIRONMENT=BASH_ENV' \
  $ENV_TOOL BASH_ENV="$hostile_env" "$BUILD" --check-tools
run_case_exact 'focused test ignores hostile BASH_ENV startup content' 1 \
  'test-builder-foundation.sh: UNSAFE_ENVIRONMENT=BASH_ENV' \
  $ENV_TOOL BASH_ENV="$hostile_env" "$SELF" --self-test-temp-root
if [ -e "$hostile_marker" ]; then
  fail 'hostile BASH_ENV marker was executed'
else
  pass 'hostile BASH_ENV marker was never executed'
fi

shim_dir="$TEST_ROOT/path-shims"
shim_marker="$TEST_ROOT/path-shim-executed"
$MKDIR_TOOL -p -- "$shim_dir"
for shim in git grep mktemp rm; do
  printf '#!/bin/sh\n/usr/bin/printf executed >> %q\nexit 99\n' "$shim_marker" > "$shim_dir/$shim"
  $CHMOD_TOOL 0700 "$shim_dir/$shim"
done
run_case_contains 'build ignores hostile PATH shims' 0 'BUILD_TOOLS_VALID=YES' \
  $ENV_TOOL PATH="$shim_dir:/usr/bin:/bin" "$BUILD" --check-tools
run_case_exact 'verify ignores hostile PATH shims' 0 'ARCHITECTURE_VALID=arm64' \
  $ENV_TOOL PATH="$shim_dir:/usr/bin:/bin" "$VERIFY" --check-architecture arm64
run_case_exact 'focused test ignores hostile mktemp and rm shims' 0 'TEST_TEMP_ROOT_VALID=YES' \
  $ENV_TOOL PATH="$shim_dir:/usr/bin:/bin" "$SELF" --self-test-temp-root
if [ -e "$shim_marker" ]; then
  fail 'hostile PATH shim was executed'
else
  pass 'hostile PATH shims were never executed'
fi
run_case_exact 'unsafe Git environment rejected deterministically' 1 \
  'build.sh: UNSAFE_ENVIRONMENT=GIT_DIR' \
  $ENV_TOOL GIT_DIR=/tmp "$BUILD" --check-source "$REPOSITORY_ROOT"
run_case_exact 'mktemp failure is detected before cleanup is enabled' 1 \
  'test-builder-foundation.sh: TEST_TEMP_ROOT_CREATE_FAILED=YES' \
  "$SELF" --self-test-mktemp-failure

source_clean=$(make_additive_descendant clean)
source_clean_head=$(git_fixture -C "$source_clean" rev-parse HEAD)
SOURCE_VALID_OUTPUT=$(printf 'PROTECTED_CONTENT_ANCHOR=%s\nAUTHORIZED_README_COMMIT=%s\nPHASE4_SOURCE_COMMIT=%s\nPROTECTED_PATHS_VERIFIED=42\nSOURCE_TREE_CLEAN=YES\nSOURCE_VALID=YES' \
  4eeafcf1caffc4223055e32b33bc83067d72e20e \
  5179f3595f0b9e1c61417ee76d660fb05c7f102b "$source_clean_head")
run_case_exact 'clean additive Phase 4 descendant source accepted' 0 "$SOURCE_VALID_OUTPUT" \
  "$BUILD" --check-source "$source_clean"

source_modified=$(make_additive_descendant modified)
printf 'protected mutation\n' >> "$source_modified/install.sh"
git_fixture -C "$source_modified" add install.sh
git_fixture -C "$source_modified" -c commit.gpgsign=false commit -q -m modify-protected
run_case_exact 'modified protected path rejected' 1 \
  'build.sh: PROTECTED_PATH_IDENTITY_MISMATCH=install.sh' \
  "$BUILD" --check-source "$source_modified"

source_deleted=$(make_additive_descendant deleted)
$RM_TOOL -- "$source_deleted/install.sh"
git_fixture -C "$source_deleted" add -A
git_fixture -C "$source_deleted" -c commit.gpgsign=false commit -q -m delete-protected
run_case_exact 'deleted protected path rejected' 1 \
  'build.sh: PROTECTED_PATH_MISSING=install.sh' \
  "$BUILD" --check-source "$source_deleted"

source_mode=$(make_additive_descendant mode)
$CHMOD_TOOL 0644 "$source_mode/install.sh"
git_fixture -C "$source_mode" add install.sh
git_fixture -C "$source_mode" -c commit.gpgsign=false commit -q -m mode-protected
run_case_exact 'mode-changed protected path rejected' 1 \
  'build.sh: PROTECTED_PATH_IDENTITY_MISMATCH=install.sh' \
  "$BUILD" --check-source "$source_mode"

source_unrelated="$TEST_ROOT/source-unrelated"
$MKDIR_TOOL -p -- "$source_unrelated"
git_fixture -C "$source_unrelated" init -q
git_fixture -C "$source_unrelated" config user.name omega-test
git_fixture -C "$source_unrelated" config user.email omega-test.invalid
printf 'unrelated\n' > "$source_unrelated/source.txt"
git_fixture -C "$source_unrelated" add source.txt
git_fixture -C "$source_unrelated" -c commit.gpgsign=false commit -q -m unrelated
run_case_exact 'unrelated commit history rejected' 1 \
  'build.sh: PROTECTED_CONTENT_ANCHOR_NOT_FOUND=4eeafcf1caffc4223055e32b33bc83067d72e20e' \
  "$BUILD" --check-source "$source_unrelated"

source_dirty=$(make_additive_descendant dirty)
printf 'dirty\n' > "$source_dirty/untracked-phase4.txt"
run_case_exact 'dirty Phase 4 source tree rejected' 1 'build.sh: SOURCE_TREE_DIRTY=YES' \
  "$BUILD" --check-source "$source_dirty"

run_case_exact 'preflight requires explicit input cache' 1 \
  'build.sh: INPUT_CACHE_ROOT_REQUIRED=YES' \
  $ENV_TOOL "${unset_proxy_env[@]}" OMEGA_NETWORK_MODE=offline "$BUILD" --preflight \
  --source-root "$source_clean"
run_case_exact 'real build requires explicit input cache' 1 \
  'build.sh: INPUT_CACHE_ROOT_REQUIRED=YES' \
  $ENV_TOOL "${unset_proxy_env[@]}" OMEGA_NETWORK_MODE=offline "$BUILD" --build \
  --source-root "$source_clean"

root=$(fresh_foundation duplicate)
printf 'status: unresolved\n' >> "$root/locks/builder.lock"
run_case_exact 'duplicate lock key rejected' 1 \
  'verify.sh: builder lock contains duplicate key: status' "$VERIFY" --image-root "$root"

root=$(fresh_foundation unknown)
printf 'rogue: value\n' >> "$root/locks/builder.lock"
run_case_exact 'unknown lock key rejected' 1 \
  'verify.sh: builder lock contains unknown key: rogue' "$VERIFY" --image-root "$root"

root=$(fresh_foundation missing)
$SED_TOOL -i '/^upstream_commit:/d' "$root/locks/builder.lock"
run_case_exact 'missing lock key rejected' 1 \
  'verify.sh: builder lock is missing required key: upstream_commit' "$VERIFY" --image-root "$root"

root=$(fresh_foundation empty)
$SED_TOOL -i 's/^release_authentication: operationally-approved-by-human-risk-acceptance$/release_authentication: /' "$root/locks/builder.lock"
run_case_exact 'empty lock value rejected' 1 \
  'verify.sh: builder lock has a malformed line at 28' "$VERIFY" --image-root "$root"

root=$(fresh_foundation malformed)
printf 'not-a-valid-lock-line\n' >> "$root/locks/apt-sources.lock"
run_case_exact 'malformed lock line rejected' 1 \
  'verify.sh: APT sources lock has a malformed line at 65' "$VERIFY" --image-root "$root"

while IFS='|' read -r name relative needle marker; do
  root=$(fresh_foundation "nul-$name")
  $PYTHON_TOOL -c 'from pathlib import Path; import sys; p=Path(sys.argv[1]); needle=sys.argv[2].encode(); data=p.read_bytes(); assert needle in data; p.write_bytes(data.replace(needle, needle[:1] + b"\x00" + needle[1:], 1))' \
    "$root/$relative" "$needle"
  run_case_exact "NUL byte rejected in $name" 1 "verify.sh: INPUT_BYTES_INVALID=$marker" \
    "$VERIFY" --image-root "$root"
done <<'EOF'
image-config|config/omega-rpi5-trixie-arm64.yaml|rpi5|image-config
builder-lock|locks/builder.lock|release_authentication|builder-lock
apt-sources-lock|locks/apt-sources.lock|snapshot_cutoff_utc|apt-sources-lock
packages-lock|locks/packages.lock|service_scope|packages-lock
oci-images-lock|locks/oci-images.lock|reference_policy|oci-images-lock
EOF

root=$(fresh_foundation crlf)
$PYTHON_TOOL -c 'from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))' \
  "$root/locks/builder.lock"
run_case_exact 'CRLF rejected before lock parsing' 1 'verify.sh: INPUT_BYTES_INVALID=builder-lock' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation unterminated)
$PYTHON_TOOL -c 'from pathlib import Path; import sys; p=Path(sys.argv[1]); data=p.read_bytes(); assert data.endswith(b"\n"); p.write_bytes(data[:-1])' \
  "$root/locks/builder.lock"
run_case_exact 'unterminated final lock line rejected' 1 \
  'verify.sh: builder lock is missing its final newline' "$VERIFY" --image-root "$root"

root=$(fresh_foundation comment)
printf '#comment\n' >> "$root/locks/builder.lock"
run_case_exact 'lock comments rejected' 1 'verify.sh: builder lock has a malformed line at 72' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation whitespace)
$SED_TOOL -i 's/^status: unresolved$/status:  unresolved/' "$root/locks/builder.lock"
run_case_exact 'lock whitespace ambiguity rejected' 1 'verify.sh: builder lock has a malformed line at 2' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation delimiter)
$SED_TOOL -i 's/^status: unresolved$/status: unresolved:injected/' "$root/locks/builder.lock"
run_case_exact 'lock delimiter injection rejected' 1 \
  'verify.sh: builder lock has invalid status: unresolved:injected' "$VERIFY" --image-root "$root"

root=$(fresh_foundation nonascii)
$PYTHON_TOOL -c 'from pathlib import Path; import sys; p=Path(sys.argv[1]); data=p.read_bytes(); p.write_bytes(data.replace(b"rpi-image-gen", b"rpi-image-gen\xc3\xa9", 1))' \
  "$root/locks/builder.lock"
run_case_exact 'non-ASCII lock bytes rejected' 1 'verify.sh: INPUT_BYTES_INVALID=builder-lock' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation floating-release)
$SED_TOOL -i 's/^upstream_release: v2\.8\.0$/upstream_release: latest/' "$root/locks/builder.lock"
run_case_exact 'floating builder release rejected' 1 \
  'verify.sh: builder lock key upstream_release contains a floating value: latest' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation floating-url)
$SED_TOOL -i 's#/commit/262d4df5a9f9d4133370465399a7958a7c22cdc7#/refs/heads/master#' \
  "$root/locks/builder.lock"
run_case_exact 'floating builder URL rejected' 1 \
  'verify.sh: builder lock key immutable_source_url contains a floating reference: https://github.com/raspberrypi/rpi-image-gen/refs/heads/master' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation floating-suite)
$SED_TOOL -i 's/^debian_suites: trixie,trixie-updates$/debian_suites: stable/' \
  "$root/locks/apt-sources.lock"
run_case_exact 'floating repository suite rejected' 1 \
  'verify.sh: APT sources lock key debian_suites contains a floating value: stable' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation main-wrong-field)
$SED_TOOL -i 's/^upstream_release: v2\.8\.0$/upstream_release: main/' "$root/locks/builder.lock"
run_case_exact 'main rejected outside component fields' 1 \
  'verify.sh: builder lock key upstream_release contains a floating value: main' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation main-unknown-components)
printf 'rogue_components: main\n' >> "$root/locks/apt-sources.lock"
run_case_exact 'main component exception cannot bypass allowed keys' 1 \
  'verify.sh: APT sources lock contains unknown key: rogue_components' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation wrong-protected-commit)
$SED_TOOL -i 's/^protected_omega_source_commit: .*/protected_omega_source_commit: 0000000000000000000000000000000000000000/' \
  "$root/locks/builder.lock"
run_case_exact 'protected anchor lock mismatch rejected' 1 \
  'verify.sh: builder lock has invalid protected_omega_source_commit: 0000000000000000000000000000000000000000' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation abbreviated-commit)
$SED_TOOL -i 's/^upstream_commit: .*/upstream_commit: 262d4df5a9f9/' "$root/locks/builder.lock"
run_case_exact 'abbreviated builder commit rejected' 1 \
  'verify.sh: builder lock has invalid upstream_commit: 262d4df5a9f9' "$VERIFY" --image-root "$root"

root=$(fresh_foundation malformed-sha256)
$SED_TOOL -i 's/^raspberrypi_inrelease_sha256: .*/raspberrypi_inrelease_sha256: 688c/' \
  "$root/locks/apt-sources.lock"
run_case_exact 'malformed repository SHA-256 rejected' 1 \
  'verify.sh: APT sources lock has invalid raspberrypi_inrelease_sha256: 688c' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation repository-digest-mismatch)
$SED_TOOL -i 's/^raspberrypi_inrelease_sha256: .*/raspberrypi_inrelease_sha256: 0000000000000000000000000000000000000000000000000000000000000000/' "$root/locks/apt-sources.lock"
run_case_exact 'repository digest mismatch rejected' 1 'verify.sh: APT sources lock has invalid raspberrypi_inrelease_sha256: 0000000000000000000000000000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"
root=$(fresh_foundation repository-fingerprint-mismatch)
$SED_TOOL -i 's/^raspberrypi_approved_signer_fingerprint: .*/raspberrypi_approved_signer_fingerprint: 0000000000000000000000000000000000000000/' "$root/locks/apt-sources.lock"
run_case_exact 'repository fingerprint mismatch rejected' 1 'verify.sh: APT sources lock has invalid raspberrypi_approved_signer_fingerprint: 0000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"
root=$(fresh_foundation repository-keyring-mismatch)
$SED_TOOL -i 's/^raspberrypi_keyring_sha256: .*/raspberrypi_keyring_sha256: 0000000000000000000000000000000000000000000000000000000000000000/' "$root/locks/apt-sources.lock"
run_case_exact 'repository keyring mismatch rejected' 1 'verify.sh: APT sources lock has invalid raspberrypi_keyring_sha256: 0000000000000000000000000000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"

root=$(fresh_foundation builder-tree-mismatch)
$SED_TOOL -i 's/^upstream_tree: .*/upstream_tree: 0000000000000000000000000000000000000000/' "$root/locks/builder.lock"
run_case_exact 'builder tree mismatch rejected' 1 'verify.sh: builder lock has invalid upstream_tree: 0000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"
root=$(fresh_foundation builder-archive-digest-mismatch)
$SED_TOOL -i 's/^source_archive_sha256: .*/source_archive_sha256: 0000000000000000000000000000000000000000000000000000000000000000/' "$root/locks/builder.lock"
run_case_exact 'builder archive digest mismatch rejected' 1 'verify.sh: builder lock has invalid source_archive_sha256: 0000000000000000000000000000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"
root=$(fresh_foundation builder-signer-mismatch)
$SED_TOOL -i 's/^commit_signer_fingerprint: .*/commit_signer_fingerprint: 0000000000000000000000000000000000000000/' "$root/locks/builder.lock"
run_case_exact 'builder signer fingerprint mismatch rejected' 1 'verify.sh: builder lock has invalid commit_signer_fingerprint: 0000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"
root=$(fresh_foundation builder-evidence-mismatch)
$SED_TOOL -i 's/^builder_key_validation_sha256: .*/builder_key_validation_sha256: 0000000000000000000000000000000000000000000000000000000000000000/' "$root/locks/builder.lock"
run_case_exact 'builder evidence mismatch rejected' 1 'verify.sh: builder lock has invalid builder_key_validation_sha256: 0000000000000000000000000000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"
root=$(fresh_foundation builder-config-plan-mismatch)
$SED_TOOL -i 's/^builder_config_plan_sha256: .*/builder_config_plan_sha256: 0000000000000000000000000000000000000000000000000000000000000000/' "$root/locks/builder.lock"
run_case_exact 'builder config plan digest mismatch rejected' 1 'verify.sh: builder lock has invalid builder_config_plan_sha256: 0000000000000000000000000000000000000000000000000000000000000000' "$VERIFY" --image-root "$root"


root=$(fresh_foundation architecture-mismatch)
$SED_TOOL -i 's/^architecture: arm64$/architecture: amd64/' "$root/locks/apt-sources.lock"
run_case_exact 'repository architecture mismatch rejected' 1 \
  'verify.sh: APT sources lock has invalid architecture: amd64' "$VERIFY" --image-root "$root"

root=$(fresh_foundation unresolved-packages)
$SED_TOOL -i 's/^status: resolved$/status: unresolved/' "$root/locks/packages.lock"
run_case_exact 'unresolved package lock rejected' 1 \
  'verify.sh: packages lock has invalid status: unresolved' "$VERIFY" --image-root "$root"

root=$(fresh_foundation payload-tamper)
printf 'tamper\n' >> "$root/rootfs-overlay/etc/omega/README"
run_case_exact 'payload content mismatch rejected' 1 \
  'verify.sh: PAYLOAD_SHA256_MISMATCH=rootfs-overlay/etc/omega/README' \
  "$VERIFY" --image-root "$root"

for private_path in var/lib/omega-dashboard/live/telemetry.sqlite3 var/lib/omega-ai/id_ed25519 root/.ssh/id_ed25519; do
  root=$(fresh_foundation "overlay-private-${private_path//\//-}")
  $MKDIR_TOOL -p -- "$root/rootfs-overlay/${private_path%/*}"
  printf 'private device state must never enter a master image\n' > "$root/rootfs-overlay/$private_path"
  run_case_exact "unlisted private overlay file rejected: $private_path" 1 \
    "verify.sh: OVERLAY_UNLISTED_ENTRY=rootfs-overlay/$private_path" \
    "$VERIFY" --image-root "$root"
done

root=$(fresh_foundation overlay-dotfile)
printf 'private\n' > "$root/rootfs-overlay/.private"
run_case_exact 'unlisted hidden overlay file rejected' 1 \
  'verify.sh: OVERLAY_UNLISTED_ENTRY=rootfs-overlay/.private' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation overlay-linked-directory)
$MKDIR_TOOL -- "$root/private-device-state"
printf 'private\n' > "$root/private-device-state/telemetry.sqlite3"
$LN_TOOL -s -- ../private-device-state "$root/rootfs-overlay/private"
run_case_exact 'unlisted overlay directory symlink rejected without traversal' 1 \
  'verify.sh: OVERLAY_SYMLINK_REJECTED=rootfs-overlay/private' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation overlay-dangling-link)
$LN_TOOL -s -- missing-private-target "$root/rootfs-overlay/private"
run_case_exact 'unlisted dangling overlay link rejected' 1 \
  'verify.sh: OVERLAY_SYMLINK_REJECTED=rootfs-overlay/private' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation overlay-fifo)
$MKFIFO_TOOL -- "$root/rootfs-overlay/private"
run_case_exact 'unlisted overlay FIFO rejected without opening it' 1 \
  'verify.sh: OVERLAY_NONREGULAR_ENTRY=rootfs-overlay/private' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation overlay-root-symlink)
$MV_TOOL -- "$root/rootfs-overlay" "$root/overlay.real"
$LN_TOOL -s -- overlay.real "$root/rootfs-overlay"
run_case_exact 'symlinked overlay root rejected' 1 \
  "verify.sh: payload entry path contains a symbolic link: $root/rootfs-overlay" \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation overlay-root-file)
$MV_TOOL -- "$root/rootfs-overlay" "$root/overlay.real"
printf 'not a directory\n' > "$root/rootfs-overlay"
run_case_exact 'non-directory overlay root rejected' 1 \
  "verify.sh: payload entry parent directory is invalid: $root/rootfs-overlay" \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation canonical-placement)
run_case_exact 'canonical input placement remains valid' 0 "$FOUNDATION_OUTPUT" \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation symlink-config-directory)
$MV_TOOL -- "$root/config" "$root/config.real"
$LN_TOOL -s -- config.real "$root/config"
run_case_exact 'symlinked intermediate config directory rejected without foundation marker' 1 \
  "verify.sh: image config path contains a symbolic link: $root/config" \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation symlink-locks-directory)
$MV_TOOL -- "$root/locks" "$root/locks.real"
$LN_TOOL -s -- locks.real "$root/locks"
run_case_exact 'symlinked intermediate locks directory rejected without foundation marker' 1 \
  "verify.sh: builder lock path contains a symbolic link: $root/locks" \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation symlink-config)
$MV_TOOL -- "$root/config/omega-rpi5-trixie-arm64.yaml" "$root/config/config.real"
$LN_TOOL -s -- config.real "$root/config/omega-rpi5-trixie-arm64.yaml"
run_case_contains 'symbolic input rejected' 1 'image config must not be a symbolic link' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation fifo-lock)
$RM_TOOL -- "$root/locks/builder.lock"
$MKFIFO_TOOL -- "$root/locks/builder.lock"
run_case_contains 'FIFO lock rejected without opening it' 1 'builder lock is missing or is not a regular file' \
  "$VERIFY" --image-root "$root"

root=$(fresh_foundation directory-lock)
$RM_TOOL -- "$root/locks/builder.lock"
$MKDIR_TOOL -- "$root/locks/builder.lock"
run_case_contains 'directory lock rejected' 1 'builder lock is missing or is not a regular file' \
  "$VERIFY" --image-root "$root"

run_signal_case() {
  local signal=$1 expected_status=$2 ready="$TEST_ROOT/signal-$1" pid status output child_root ready_seen=false
  $PYTHON_TOOL -c 'import os, signal, sys; signal.signal(signal.SIGHUP, signal.SIG_DFL); signal.signal(signal.SIGINT, signal.SIG_DFL); signal.signal(signal.SIGTERM, signal.SIG_DFL); os.execv(sys.argv[1], sys.argv[1:])' \
    "$SELF" --signal-fixture > "$ready" 2>&1 &
  pid=$!
  for _ in {1..100}; do
    if [ -s "$ready" ]; then
      ready_seen=true
      break
    fi
    $SLEEP_TOOL 0.05
  done
  if [ "$ready_seen" != true ]; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    fail "$signal signal fixture did not become ready"
    return
  fi
  output=$($HEAD_TOOL -n 1 -- "$ready")
  child_root=${output#SIGNAL_FIXTURE_ROOT=}
  kill -"$signal" "$pid"
  if wait "$pid"; then
    status=0
  else
    status=$?
  fi
  if [ "$status" -ne "$expected_status" ]; then
    fail "$signal signal status expected=$expected_status actual=$status output=$output"
    return
  fi
  if [[ ! "$child_root" =~ ^/tmp/omega-phase4-builder-foundation\.[A-Za-z0-9]{8}$ ]]; then
    fail "$signal signal returned unsafe child root: $child_root"
    return
  fi
  if [ -e "$child_root" ] || [ -L "$child_root" ]; then
    fail "$signal signal did not clean child root: $child_root"
    return
  fi
  pass "$signal signal cleans once and exits $expected_status"
}

run_signal_case HUP 129
run_signal_case INT 130
run_signal_case TERM 143

run_signal_inode_replacement_case() {
  local signal=$1 expected_status=$2 ready="$TEST_ROOT/signal-replacement-$1"
  local pid status output child_root saved_root original_identity replacement_identity
  local ready_seen=false failure=
  $PYTHON_TOOL -c 'import os, signal, sys; signal.signal(signal.SIGHUP, signal.SIG_DFL); signal.signal(signal.SIGINT, signal.SIG_DFL); signal.signal(signal.SIGTERM, signal.SIG_DFL); os.execv(sys.argv[1], sys.argv[1:])' \
    "$SELF" --signal-fixture > "$ready" 2>&1 &
  pid=$!
  for _ in {1..100}; do
    if [ -s "$ready" ]; then
      ready_seen=true
      break
    fi
    $SLEEP_TOOL 0.05
  done
  if [ "$ready_seen" != true ]; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    fail "$signal inode-replacement signal fixture did not become ready"
    return
  fi

  output=$($HEAD_TOOL -n 1 -- "$ready")
  child_root=${output#SIGNAL_FIXTURE_ROOT=}
  if [[ ! "$child_root" =~ ^/tmp/omega-phase4-builder-foundation\.[A-Za-z0-9]{8}$ ]]; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    fail "$signal inode-replacement returned unsafe child root: $child_root"
    return
  fi
  original_identity=$($STAT_TOOL -c '%d:%i' -- "$child_root")
  saved_root="$TEST_ROOT/signal-replacement-$signal-original"
  $MV_TOOL -- "$child_root" "$saved_root"
  $MKDIR_TOOL -m 0700 -- "$child_root"
  replacement_identity=$($STAT_TOOL -c '%d:%i' -- "$child_root")

  kill -"$signal" "$pid"
  if wait "$pid"; then
    status=0
  else
    status=$?
  fi
  output=$($CAT_TOOL -- "$ready")
  [ "$status" -eq "$expected_status" ] ||
    failure="status expected=$expected_status actual=$status"
  [[ "$output" == *'TEST_TEMP_ROOT_CLEANUP_REFUSED=YES'* ]] ||
    failure="${failure:+$failure; }cleanup refusal evidence missing"
  if [ ! -d "$saved_root" ] || [ -L "$saved_root" ] ||
     [ "$($STAT_TOOL -c '%d:%i' -- "$saved_root" 2>/dev/null || true)" != "$original_identity" ]; then
    failure="${failure:+$failure; }moved original directory was not preserved"
  fi
  if [ ! -d "$child_root" ] || [ -L "$child_root" ] ||
     [ "$($STAT_TOOL -c '%d:%i' -- "$child_root" 2>/dev/null || true)" != "$replacement_identity" ]; then
    failure="${failure:+$failure; }inode-replacement directory was not preserved"
  fi

  $RMDIR_TOOL -- "$child_root" ||
    failure="${failure:+$failure; }inode-replacement directory restoration failed"
  $RMDIR_TOOL -- "$saved_root" ||
    failure="${failure:+$failure; }moved original directory restoration failed"
  if [ -e "$child_root" ] || [ -L "$child_root" ] ||
     [ -e "$saved_root" ] || [ -L "$saved_root" ]; then
    failure="${failure:+$failure; }signal fixture restoration incomplete"
  fi

  if [ -n "$failure" ]; then
    fail "$signal inode-replacement $failure output=$output"
    return
  fi
  pass "$signal inode-replacement refuses cleanup, preserves both directories, exits $expected_status, and restores fixtures"
}

run_signal_inode_replacement_case HUP 129
run_signal_inode_replacement_case INT 130
run_signal_inode_replacement_case TERM 143

printf 'RESULT: %s passed, %s failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ]
