#!/bin/bash -p
set -euo pipefail

IFS=$' \t\n'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
hash -r
umask 0022
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export SOURCE_DATE_EPOCH=1787801458

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

readonly BASH_TOOL=/bin/bash
readonly ENV_TOOL=/usr/bin/env
readonly GIT_TOOL=/usr/bin/git
readonly SHA256SUM_TOOL=/usr/bin/sha256sum
readonly AWK_TOOL=/usr/bin/awk
readonly GREP_TOOL=/usr/bin/grep
readonly SED_TOOL=/usr/bin/sed
readonly STAT_TOOL=/usr/bin/stat
readonly ID_TOOL=/usr/bin/id
readonly UNAME_TOOL=/usr/bin/uname
readonly TAR_TOOL=/usr/bin/tar
readonly XZ_TOOL=/usr/bin/xz
readonly TAIL_TOOL=/usr/bin/tail
readonly DIRNAME_TOOL=/usr/bin/dirname
readonly READLINK_TOOL=/usr/bin/readlink
readonly PYTHON_TOOL=/usr/bin/python3
readonly MKTEMP_TOOL=/usr/bin/mktemp
readonly MKDIR_TOOL=/usr/bin/mkdir
readonly RM_TOOL=/usr/bin/rm
readonly CHMOD_TOOL=/usr/bin/chmod
readonly UNSHARE_TOOL=/usr/bin/unshare
readonly NEWUIDMAP_TOOL=/usr/bin/newuidmap
readonly NEWGIDMAP_TOOL=/usr/bin/newgidmap
readonly CP_TOOL=/bin/cp

SCRIPT_DIR=$($READLINK_TOOL -f -- "$($DIRNAME_TOOL -- "${BASH_SOURCE[0]}")")
REPOSITORY_ROOT=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../..")
VERIFY_SCRIPT="$SCRIPT_DIR/verify.sh"
BUILDER_ARCHIVE_VERIFIER=$($READLINK_TOOL -f -- "$SCRIPT_DIR/verify-builder-archive.py")
BUILDER_CONFIG_VERIFIER=$($READLINK_TOOL -f -- "$SCRIPT_DIR/verify-builder-config.py")
NETWORK_NAMESPACE_EXEC=$($READLINK_TOOL -f -- "$SCRIPT_DIR/network-namespace-exec.py")
PACKAGE_CACHE_VERIFIER=$($READLINK_TOOL -f -- "$SCRIPT_DIR/verify-package-cache.py")
OCI_CACHE_VERIFIER=$($READLINK_TOOL -f -- "$SCRIPT_DIR/verify-oci-cache.py")
BUILDER_TOOLS_VERIFIER=$($READLINK_TOOL -f -- "$SCRIPT_DIR/verify-builder-tools.py")
CONSTRUCT_SCRIPT=$($READLINK_TOOL -f -- "$SCRIPT_DIR/construct-image.sh")
DASHBOARD_STAGER="$SCRIPT_DIR/stage-dashboard.py"
DASHBOARD_MANIFEST="$REPOSITORY_ROOT/image/locks/dashboard.manifest"
ONBOARDING_STAGER="$SCRIPT_DIR/stage-onboarding.py"
ONBOARDING_MANIFEST="$REPOSITORY_ROOT/image/locks/onboarding.manifest"
AI_STAGER="$SCRIPT_DIR/stage-ai.py"
AI_MANIFEST="$REPOSITORY_ROOT/image/locks/ai.manifest.json"
BUILDER_LOCK=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/builder.lock")
BUILDER_TREE_MANIFEST=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/builder-tree.manifest")
PACKAGE_LOCK=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/packages.lock")
PACKAGE_MANIFEST=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/packages.manifest")
OCI_LOCK=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/oci-images.lock")
OCI_MANIFEST=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/oci-images.manifest")
BUILDER_TOOLS_MANIFEST=$($READLINK_TOOL -f -- "$SCRIPT_DIR/../locks/builder-tools.manifest")
PROTECTED_CONTENT_ANCHOR=4eeafcf1caffc4223055e32b33bc83067d72e20e
AUTHORIZED_README_COMMIT=5179f3595f0b9e1c61417ee76d660fb05c7f102b
AUTHORIZED_README_PARENT=4eeafcf1caffc4223055e32b33bc83067d72e20e
AUTHORIZED_README_BLOB=485c72eec8ef40c158d5fb259e4ae68dd04efdff
BUILDER_TEMP_ROOT=
BUILDER_TEMP_IDENTITY=
CURRENT_SOURCE_COMMIT=
CONSTRUCTION_SOURCE=
CONSTRUCTION_WORK=
CONSTRUCTION_RELEASE=

usage() {
  cat <<'EOF'
Usage: build.sh --preflight --input-cache-root ABSOLUTE_PATH [--source-root ABSOLUTE_PATH]
       build.sh --build --input-cache-root ABSOLUTE_PATH --output-dir ABSOLUTE_PATH
                      [--source-root ABSOLUTE_PATH]
       build.sh --check-builder-archive ABSOLUTE_INPUT_CACHE_ROOT
       build.sh --check-builder-config ABSOLUTE_INPUT_CACHE_ROOT
       build.sh --check-service-cache ABSOLUTE_INPUT_CACHE_ROOT
       build.sh --check-source ABSOLUTE_PATH
       build.sh --check-tools
       build.sh --check-network
       build.sh --check-architecture ARCHITECTURE

Phase 4 supplies fail-closed validation for its exact offline inputs.
EOF
}

git_safe() {
  $ENV_TOOL -i \
    PATH="$PATH" HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    $GIT_TOOL -c core.fsmonitor=false -c core.untrackedCache=false "$@"
}

tool_version() {
  local name=$1 path=$2 version
  case "$name" in
    bash) version=$($path --version 2>&1) || die "cannot report tool version: $name" ;;
    awk) version=$($path -W version 2>&1) || die "cannot report tool version: $name" ;;
    *) version=$($path --version 2>&1) || die "cannot report tool version: $name" ;;
  esac
  version=${version%%$'\n'*}
  version=${version//$'\r'/}
  printf 'BUILD_TOOL=%s|path=%s|version=%s|authentication=not-established\n' \
    "$name" "$path" "$version"
}

require_tool() {
  local name=$1 path=$2 canonical
  [ -f "$path" ] && [ -x "$path" ] || die "required absolute build tool is unavailable: $path"
  canonical=$($READLINK_TOOL -f -- "$path") || die "cannot resolve build tool: $path"
  case "$canonical" in
    /bin/*|/usr/bin/*|/usr/sbin/*|/sbin/*) ;;
    *) die "build tool resolves outside trusted system paths: $path -> $canonical" ;;
  esac
  tool_version "$name" "$path"
}

check_tools() {
  require_tool bash "$BASH_TOOL"
  require_tool env "$ENV_TOOL"
  require_tool git "$GIT_TOOL"
  require_tool sha256sum "$SHA256SUM_TOOL"
  require_tool awk "$AWK_TOOL"
  require_tool grep "$GREP_TOOL"
  require_tool sed "$SED_TOOL"
  require_tool stat "$STAT_TOOL"
  require_tool id "$ID_TOOL"
  require_tool uname "$UNAME_TOOL"
  require_tool tar "$TAR_TOOL"
  require_tool xz "$XZ_TOOL"
  require_tool zstd /usr/bin/zstd
  require_tool tail "$TAIL_TOOL"
  require_tool dirname "$DIRNAME_TOOL"
  require_tool readlink "$READLINK_TOOL"
  require_tool python3 "$PYTHON_TOOL"
  require_tool mktemp "$MKTEMP_TOOL"
  require_tool mkdir "$MKDIR_TOOL"
  require_tool rm "$RM_TOOL"
  require_tool chmod "$CHMOD_TOOL"
  require_tool unshare "$UNSHARE_TOOL"
  require_tool cp "$CP_TOOL"
  if [ -n "${OMEGA_REQUIRED_TOOLS_EXTRA:-}" ]; then
    [[ "$OMEGA_REQUIRED_TOOLS_EXTRA" =~ ^[A-Za-z0-9._+-]+$ ]] ||
      die 'OMEGA_REQUIRED_TOOLS_EXTRA contains an invalid tool name'
    require_tool "$OMEGA_REQUIRED_TOOLS_EXTRA" "/usr/bin/$OMEGA_REQUIRED_TOOLS_EXTRA"
  fi
  printf 'BUILD_TOOLS_VALID=YES\n'
}

check_network_declaration() {
  local variable
  [ "${OMEGA_NETWORK_MODE:-}" = offline ] ||
    die 'OFFLINE_ENVIRONMENT_DECLARATION=MISSING'
  for variable in http_proxy https_proxy ftp_proxy all_proxy HTTP_PROXY HTTPS_PROXY FTP_PROXY ALL_PROXY; do
    [ -z "${!variable:-}" ] || die "UNDECLARED_PROXY_INPUT=$variable"
  done
  printf 'OFFLINE_ENVIRONMENT_DECLARATION=YES\n'
}

run_network_probe_isolated() {
  local host_network_namespace
  host_network_namespace=$($READLINK_TOOL /proc/self/ns/net) ||
    die 'HOST_NETWORK_NAMESPACE_UNREADABLE=YES'
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    "$UNSHARE_TOOL" -Urn -- \
    "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
      --host-network-namespace "$host_network_namespace" "$@"
}

check_construction_network_isolation() {
  run_network_probe_isolated
}

require_native_helper() {
  local name=$1 path=$2 canonical
  [ -f "$path" ] && [ -x "$path" ] || die "required native-build helper is unavailable: $path"
  canonical=$($READLINK_TOOL -f -- "$path") || die "cannot resolve native-build helper: $path"
  case "$canonical" in
    /bin/*|/usr/bin/*|/usr/sbin/*|/sbin/*) ;;
    *) die "native-build helper resolves outside trusted system paths: $path -> $canonical" ;;
  esac
  printf 'NATIVE_BUILD_HELPER=%s|path=%s\n' "$name" "$path"
}

run_construction_isolated() {
  local host_network_namespace host_mount_namespace
  host_network_namespace=$($READLINK_TOOL /proc/self/ns/net) ||
    die 'HOST_NETWORK_NAMESPACE_UNREADABLE=YES'
  host_mount_namespace=$($READLINK_TOOL /proc/self/ns/mnt) ||
    die 'HOST_MOUNT_NAMESPACE_UNREADABLE=YES'
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    "$UNSHARE_TOOL" --map-auto --map-root-user --mount --net -- \
    "$PYTHON_TOOL" -B "$NETWORK_NAMESPACE_EXEC" \
      --host-network-namespace "$host_network_namespace" \
      --host-mount-namespace "$host_mount_namespace" \
      --require-subordinate-mapping "$@"
}

check_native_construction_host() {
  require_native_helper newuidmap "$NEWUIDMAP_TOOL"
  require_native_helper newgidmap "$NEWGIDMAP_TOOL"
  $ENV_TOOL -i PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B -c 'import ruamel.yaml' 2>/dev/null ||
      die 'required native-build Python module is unavailable: ruamel.yaml (install python3-ruamel.yaml)'
  run_construction_isolated
  printf 'NATIVE_BUILD_HOST=READY\n'
}

check_source() {
  local requested_root=$1 source_root top head dirty anchor_entry anchor_metadata
  local protected_path current_entry current_metadata protected_count=0 readme_parent readme_changes
  case "$requested_root" in
    /*) ;;
    *) die 'SOURCE_ROOT_NOT_ABSOLUTE=YES' ;;
  esac
  [ -d "$requested_root" ] || die 'SOURCE_ROOT_DIRECTORY_INVALID=YES'
  [ ! -L "$requested_root" ] || die 'SOURCE_ROOT_SYMLINK_REJECTED=YES'
  source_root=$($READLINK_TOOL -f -- "$requested_root") || die 'SOURCE_ROOT_RESOLUTION_FAILED=YES'
  [ "$source_root" = "$requested_root" ] || die 'SOURCE_ROOT_NOT_CANONICAL=YES'
  git_safe -C "$source_root" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die 'SOURCE_GIT_WORKTREE_INVALID=YES'
  top=$(git_safe -C "$source_root" rev-parse --show-toplevel) ||
    die 'SOURCE_GIT_TOPLEVEL_UNREADABLE=YES'
  [ "$top" = "$source_root" ] || die 'SOURCE_ROOT_IS_NOT_GIT_TOPLEVEL=YES'
  head=$(git_safe -C "$source_root" rev-parse --verify 'HEAD^{commit}') ||
    die 'PHASE4_SOURCE_COMMIT_UNREADABLE=YES'
  [[ "$head" =~ ^[0-9a-f]{40}$ ]] || die 'PHASE4_SOURCE_COMMIT_NOT_FULL_SHA1=YES'
  git_safe -C "$source_root" cat-file -e "${PROTECTED_CONTENT_ANCHOR}^{commit}" 2>/dev/null ||
    die "PROTECTED_CONTENT_ANCHOR_NOT_FOUND=$PROTECTED_CONTENT_ANCHOR"
  git_safe -C "$source_root" merge-base --is-ancestor "$PROTECTED_CONTENT_ANCHOR" "$head" ||
    die "PROTECTED_CONTENT_ANCHOR_NOT_ANCESTOR=$PROTECTED_CONTENT_ANCHOR"
  git_safe -C "$source_root" cat-file -e "${AUTHORIZED_README_COMMIT}^{commit}" 2>/dev/null ||
    die "AUTHORIZED_README_COMMIT_NOT_FOUND=$AUTHORIZED_README_COMMIT"
  git_safe -C "$source_root" merge-base --is-ancestor "$AUTHORIZED_README_COMMIT" "$head" ||
    die "AUTHORIZED_README_COMMIT_NOT_ANCESTOR=$AUTHORIZED_README_COMMIT"
  readme_parent=$(git_safe -C "$source_root" rev-parse "$AUTHORIZED_README_COMMIT^") ||
    die 'AUTHORIZED_README_PARENT_UNREADABLE=YES'
  [ "$readme_parent" = "$AUTHORIZED_README_PARENT" ] ||
    die "AUTHORIZED_README_PARENT_MISMATCH=$readme_parent"
  readme_changes=$(git_safe -C "$source_root" diff-tree --no-commit-id --name-only -r "$AUTHORIZED_README_COMMIT") ||
    die 'AUTHORIZED_README_DIFF_UNREADABLE=YES'
  [ "$readme_changes" = README.md ] || die 'AUTHORIZED_README_DIFF_INVALID=YES'
  dirty=$(git_safe -C "$source_root" status --porcelain=v1 --untracked-files=all --ignored=matching) ||
    die 'SOURCE_TREE_STATE_UNREADABLE=YES'
  [ -z "$dirty" ] || die 'SOURCE_TREE_DIRTY=YES'

  while IFS= read -r -d '' anchor_entry; do
    anchor_metadata=${anchor_entry%%$'\t'*}
    protected_path=${anchor_entry#*$'\t'}
    if [ "$protected_path" = README.md ]; then
      anchor_metadata="100644 blob $AUTHORIZED_README_BLOB"
    fi
    current_entry=
    if ! IFS= read -r -d '' current_entry < <(
      git_safe -C "$source_root" ls-tree -z "$head" -- "$protected_path"
    ); then
      die "PROTECTED_PATH_MISSING=$protected_path"
    fi
    current_metadata=${current_entry%%$'\t'*}
    [ "$current_metadata" = "$anchor_metadata" ] ||
      die "PROTECTED_PATH_IDENTITY_MISMATCH=$protected_path"
    protected_count=$((protected_count + 1))
  done < <(git_safe -C "$source_root" ls-tree -r -z "$PROTECTED_CONTENT_ANCHOR")
  [ "$protected_count" -gt 0 ] || die 'PROTECTED_CONTENT_ANCHOR_EMPTY=YES'

  printf 'PROTECTED_CONTENT_ANCHOR=%s\n' "$PROTECTED_CONTENT_ANCHOR"
  printf 'AUTHORIZED_README_COMMIT=%s\n' "$AUTHORIZED_README_COMMIT"
  printf 'PHASE4_SOURCE_COMMIT=%s\n' "$head"
  printf 'PROTECTED_PATHS_VERIFIED=%s\n' "$protected_count"
  printf 'SOURCE_TREE_CLEAN=YES\n'
  printf 'SOURCE_VALID=YES\n'
  CURRENT_SOURCE_COMMIT=$head
}

check_builder_archive() {
  local input_cache_root=$1
  [ -n "$input_cache_root" ] || die 'INPUT_CACHE_ROOT_REQUIRED=YES'
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$BUILDER_ARCHIVE_VERIFIER" \
      --mode verify-only --input-cache-root "$input_cache_root" \
      --lock "$BUILDER_LOCK" --manifest "$BUILDER_TREE_MANIFEST"
}

check_service_cache() {
  local input_cache_root=$1
  [ -n "$input_cache_root" ] || die 'INPUT_CACHE_ROOT_REQUIRED=YES'
  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$DASHBOARD_STAGER" \
      --source-root "$REPOSITORY_ROOT" --manifest "$DASHBOARD_MANIFEST"
  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$ONBOARDING_STAGER" \
      --source-root "$REPOSITORY_ROOT" --manifest "$ONBOARDING_MANIFEST"
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$PACKAGE_CACHE_VERIFIER" \
      --input-cache-root "$input_cache_root" --lock "$PACKAGE_LOCK" \
      --manifest "$PACKAGE_MANIFEST"
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$OCI_CACHE_VERIFIER" \
      --input-cache-root "$input_cache_root" --lock "$OCI_LOCK" \
      --manifest "$OCI_MANIFEST"
  "$ENV_TOOL" -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$BUILDER_TOOLS_VERIFIER" \
      --input-cache-root "$input_cache_root" --manifest "$BUILDER_TOOLS_MANIFEST"
  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$AI_STAGER" \
      --input-cache-root "$input_cache_root" --manifest "$AI_MANIFEST"
  printf 'SERVICE_INPUT_CACHE=VERIFIED\n'
}

validate_output_destination() {
  local requested=$1 parent canonical
  case "$requested" in
    /*) ;;
    *) die 'OUTPUT_DIRECTORY_NOT_ABSOLUTE=YES' ;;
  esac
  [ ! -e "$requested" ] && [ ! -L "$requested" ] || die 'OUTPUT_DIRECTORY_EXISTS=YES'
  parent=${requested%/*}
  [ -n "$parent" ] || parent=/
  [ -d "$parent" ] && [ ! -L "$parent" ] || die 'OUTPUT_PARENT_INVALID=YES'
  canonical=$($READLINK_TOOL -f -- "$parent") || die 'OUTPUT_PARENT_RESOLUTION_FAILED=YES'
  [ "$canonical" = "$parent" ] || die 'OUTPUT_PARENT_NOT_CANONICAL=YES'
}

prepare_construction_inputs() {
  local source_root=$1 input_cache_root=$2 oci_directory
  validate_builder_temp_root || die 'BUILDER_TEMP_VALIDATION_FAILED=YES'
  CONSTRUCTION_SOURCE="$BUILDER_TEMP_ROOT/omega-source"
  CONSTRUCTION_WORK="$BUILDER_TEMP_ROOT/build"
  CONSTRUCTION_RELEASE="$BUILDER_TEMP_ROOT/release"
  $MKDIR_TOOL -m 0700 -- "$CONSTRUCTION_SOURCE" "$CONSTRUCTION_WORK"
  $CP_TOOL -a -- "$source_root/image/." "$CONSTRUCTION_SOURCE/"

  "$BASH_TOOL" -p "$source_root/install.sh" install \
    --destdir "$CONSTRUCTION_SOURCE/rootfs-overlay"

  "$MKDIR_TOOL" -m 0755 -p -- "$CONSTRUCTION_SOURCE/rootfs-overlay/opt"
  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    "$PYTHON_TOOL" -B "$DASHBOARD_STAGER" \
      --source-root "$source_root" --manifest "$DASHBOARD_MANIFEST" \
      --destination "$CONSTRUCTION_SOURCE/rootfs-overlay/opt/omega-dashboard"

  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    "$PYTHON_TOOL" -B "$ONBOARDING_STAGER" \
      --source-root "$source_root" --manifest "$ONBOARDING_MANIFEST" \
      --destination "$CONSTRUCTION_SOURCE/rootfs-overlay/opt/omega-setup"

  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    "$PYTHON_TOOL" -B "$AI_STAGER" \
      --input-cache-root "$input_cache_root" --manifest "$AI_MANIFEST" \
      --stage-root "$CONSTRUCTION_SOURCE/ai-payload"
  "$CP_TOOL" -a -- "$CONSTRUCTION_SOURCE/ai-payload/." "$CONSTRUCTION_SOURCE/rootfs-overlay/"

  "$ENV_TOOL" -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$PACKAGE_CACHE_VERIFIER" \
      --input-cache-root "$input_cache_root" --lock "$PACKAGE_LOCK" \
      --manifest "$PACKAGE_MANIFEST" \
      --prepare-repository "$CONSTRUCTION_SOURCE/apt-repository"

  oci_directory="$CONSTRUCTION_SOURCE/rootfs-overlay/usr/share/omega/oci"
  $MKDIR_TOOL -m 0755 -p -- "$oci_directory"
  "$ENV_TOOL" -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$OCI_CACHE_VERIFIER" \
      --input-cache-root "$input_cache_root" --lock "$OCI_LOCK" \
      --manifest "$OCI_MANIFEST" \
      --prepare-archive "$oci_directory/omega-services.tar"
  (
    cd -- "$oci_directory"
    $SHA256SUM_TOOL -- omega-services.tar > omega-services.tar.sha256
  )
  $CHMOD_TOOL 0644 -- "$oci_directory/omega-services.tar" "$oci_directory/omega-services.tar.sha256"

  # rsync preserves overlay directory modes and times in the target root.
  # Drop checkout-dependent group/other write access without widening private dirs.
  "$ENV_TOOL" -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B -c '
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
epoch = int(sys.argv[2])
for path in [root, *root.rglob("*")]:
    metadata = path.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        path.chmod(stat.S_IMODE(metadata.st_mode) & ~0o022)
    os.utime(path, (epoch, epoch), follow_symlinks=False)
' "$CONSTRUCTION_SOURCE/rootfs-overlay" "$SOURCE_DATE_EPOCH"

  "$ENV_TOOL" -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$BUILDER_TOOLS_VERIFIER" \
      --input-cache-root "$input_cache_root" --manifest "$BUILDER_TOOLS_MANIFEST" \
      --stage-directory "$CONSTRUCTION_WORK/cache"
  printf 'CONSTRUCTION_INPUTS=PREPARED\n'
}

construct_image() {
  local source_root=$1 input_cache_root=$2 output_dir=$3
  [ -n "$CURRENT_SOURCE_COMMIT" ] || die 'SOURCE_COMMIT_NOT_CAPTURED=YES'
  validate_output_destination "$output_dir"
  prepare_construction_inputs "$source_root" "$input_cache_root"
  run_construction_isolated \
    "$BASH_TOOL" -p "$CONSTRUCT_SCRIPT" \
      "$BUILDER_TEMP_ROOT/source" "$CONSTRUCTION_SOURCE" \
      "$CONSTRUCTION_WORK" "$CONSTRUCTION_RELEASE" "$CURRENT_SOURCE_COMMIT"
  [ -d "$CONSTRUCTION_RELEASE" ] && [ ! -L "$CONSTRUCTION_RELEASE" ] ||
    die 'CONSTRUCTION_RELEASE_INVALID=YES'
  $MKDIR_TOOL -m 0700 -- "$output_dir" || die 'OUTPUT_DIRECTORY_CREATE_FAILED=YES'
  $CP_TOOL -a -- "$CONSTRUCTION_RELEASE/." "$output_dir/"
  printf 'IMAGE_OUTPUT_DIRECTORY=%s\n' "$output_dir"
  printf 'IMAGE_BUILD=PASS\n'
}

validate_builder_temp_root() {
  local canonical identity mode owner
  [ -n "$BUILDER_TEMP_ROOT" ] || return 1
  [[ "$BUILDER_TEMP_ROOT" =~ ^/tmp/omega-phase4-builder\.[A-Za-z0-9]{8}$ ]] || return 1
  [ -d "$BUILDER_TEMP_ROOT" ] && [ ! -L "$BUILDER_TEMP_ROOT" ] || return 1
  canonical=$($READLINK_TOOL -f -- "$BUILDER_TEMP_ROOT") || return 1
  [ "$canonical" = "$BUILDER_TEMP_ROOT" ] || return 1
  identity=$($STAT_TOOL -c '%d:%i' -- "$BUILDER_TEMP_ROOT") || return 1
  [ "$identity" = "$BUILDER_TEMP_IDENTITY" ] || return 1
  mode=$($STAT_TOOL -c %a -- "$BUILDER_TEMP_ROOT") || return 1
  [ "$mode" = 700 ] || return 1
  owner=$($STAT_TOOL -c %u -- "$BUILDER_TEMP_ROOT") || return 1
  [ "$owner" = "$($ID_TOOL -u)" ] || return 1
}

cleanup_builder_temp() {
  [ -n "$BUILDER_TEMP_ROOT" ] || return 0
  validate_builder_temp_root || die 'BUILDER_TEMP_CLEANUP_REFUSED=YES'
  $RM_TOOL -rf --one-file-system -- "$BUILDER_TEMP_ROOT"
  [ ! -e "$BUILDER_TEMP_ROOT" ] && [ ! -L "$BUILDER_TEMP_ROOT" ] ||
    die 'BUILDER_TEMP_CLEANUP_FAILED=YES'
  BUILDER_TEMP_ROOT=
  BUILDER_TEMP_IDENTITY=
}

prepare_verified_builder() {
  local input_cache_root=$1 candidate
  candidate=$($MKTEMP_TOOL -d --tmpdir=/tmp 'omega-phase4-builder.XXXXXXXX') ||
    die 'BUILDER_TEMP_CREATE_FAILED=YES'
  BUILDER_TEMP_ROOT=$($READLINK_TOOL -f -- "$candidate") || die 'BUILDER_TEMP_RESOLUTION_FAILED=YES'
  $CHMOD_TOOL 0700 -- "$BUILDER_TEMP_ROOT"
  BUILDER_TEMP_IDENTITY=$($STAT_TOOL -c '%d:%i' -- "$BUILDER_TEMP_ROOT") ||
    die 'BUILDER_TEMP_IDENTITY_FAILED=YES'
  validate_builder_temp_root || die 'BUILDER_TEMP_VALIDATION_FAILED=YES'
  trap cleanup_builder_temp EXIT
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON_TOOL" -B "$BUILDER_ARCHIVE_VERIFIER" \
      --mode extract --input-cache-root "$input_cache_root" \
      --lock "$BUILDER_LOCK" --manifest "$BUILDER_TREE_MANIFEST" \
      --destination "$BUILDER_TEMP_ROOT/source"
  printf 'VERIFIED_BUILDER_DIRECTORY=%s\n' "$BUILDER_TEMP_ROOT/source"
  printf 'BUILDER_CODE_EXECUTED=NO\n'
}

check_builder_config() {
  local source_root=$1 host_network_namespace config_workspace
  [ -n "$BUILDER_TEMP_ROOT" ] || die 'VERIFIED_BUILDER_REQUIRED=YES'
  validate_builder_temp_root || die 'BUILDER_TEMP_VALIDATION_FAILED=YES'
  config_workspace="$BUILDER_TEMP_ROOT/config-check"
  $MKDIR_TOOL -m 0700 -- "$config_workspace" || die 'CONFIG_WORKSPACE_CREATE_FAILED=YES'
  host_network_namespace=$($READLINK_TOOL /proc/self/ns/net) ||
    die 'HOST_NETWORK_NAMESPACE_UNREADABLE=YES'
  $ENV_TOOL -i \
    PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent \
    LANG=C LC_ALL=C TZ=UTC \
    "$UNSHARE_TOOL" -Urn -- \
    "$PYTHON_TOOL" -B "$BUILDER_CONFIG_VERIFIER" \
      --builder-root "$BUILDER_TEMP_ROOT/source" \
      --omega-image-root "$source_root/image" \
      --workspace "$config_workspace" \
      --lock "$BUILDER_LOCK" \
      --host-network-namespace "$host_network_namespace"
}

run_preflight() {
  local source_root=$1 input_cache_root=$2 architecture
  [ "$source_root" = "$REPOSITORY_ROOT" ] || die 'SOURCE_ROOT_MUST_MATCH_BUILD_CHECKOUT=YES'
  check_tools
  check_source "$source_root"
  check_network_declaration
  check_construction_network_isolation
  "$VERIFY_SCRIPT" --require-service-locks
  check_builder_archive "$input_cache_root"
  check_service_cache "$input_cache_root"
  prepare_verified_builder "$input_cache_root"
  check_builder_config "$source_root"
  "$VERIFY_SCRIPT" --require-build-readiness
  architecture=$($UNAME_TOOL -m) || die 'BUILD_ARCHITECTURE_UNREADABLE=YES'
  "$VERIFY_SCRIPT" --check-architecture "$architecture" >/dev/null
  check_native_construction_host
}

MODE=
SOURCE_ROOT=$REPOSITORY_ROOT
INPUT_CACHE_ROOT=
OUTPUT_DIR=

[ "$#" -gt 0 ] || { usage >&2; exit 2; }
MODE=$1
shift

case "$MODE" in
  --check-tools)
    [ "$#" -eq 0 ] || die 'CHECK_TOOLS_ARGUMENTS_INVALID=YES'
    check_tools
    exit 0
    ;;
  --check-network)
    [ "$#" -eq 0 ] || die 'CHECK_NETWORK_ARGUMENTS_INVALID=YES'
    check_network_declaration
    check_construction_network_isolation
    exit 0
    ;;
  --check-architecture)
    [ "$#" -eq 1 ] || die 'CHECK_ARCHITECTURE_ARGUMENTS_INVALID=YES'
    "$VERIFY_SCRIPT" --check-architecture "$1"
    exit 0
    ;;
  --check-source)
    [ "$#" -eq 1 ] || die 'CHECK_SOURCE_ARGUMENTS_INVALID=YES'
    check_source "$1"
    exit 0
    ;;
  --check-builder-archive)
    [ "$#" -eq 1 ] || die 'CHECK_BUILDER_ARCHIVE_ARGUMENTS_INVALID=YES'
    check_builder_archive "$1"
    exit 0
    ;;
  --check-builder-config)
    [ "$#" -eq 1 ] || die 'CHECK_BUILDER_CONFIG_ARGUMENTS_INVALID=YES'
    check_tools
    "$VERIFY_SCRIPT"
    prepare_verified_builder "$1"
    check_builder_config "$REPOSITORY_ROOT"
    exit 0
    ;;
  --check-service-cache)
    [ "$#" -eq 1 ] || die 'CHECK_SERVICE_CACHE_ARGUMENTS_INVALID=YES'
    "$VERIFY_SCRIPT" --require-service-locks
    check_service_cache "$1"
    exit 0
    ;;
  --preflight|--build) ;;
  --help|-h)
    usage
    exit 0
    ;;
  *) die "UNKNOWN_MODE=$MODE" ;;
esac

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-root)
      [ "$#" -ge 2 ] || die 'SOURCE_ROOT_ARGUMENT_MISSING=YES'
      SOURCE_ROOT=$2
      shift 2
      ;;
    --input-cache-root)
      [ "$#" -ge 2 ] || die 'INPUT_CACHE_ROOT_ARGUMENT_MISSING=YES'
      [ -z "$INPUT_CACHE_ROOT" ] || die 'INPUT_CACHE_ROOT_DUPLICATE=YES'
      INPUT_CACHE_ROOT=$2
      shift 2
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || die 'OUTPUT_DIRECTORY_ARGUMENT_MISSING=YES'
      [ -z "$OUTPUT_DIR" ] || die 'OUTPUT_DIRECTORY_DUPLICATE=YES'
      OUTPUT_DIR=$2
      shift 2
      ;;
    *) die "UNKNOWN_ARGUMENT=$1" ;;
  esac
done

[ -n "$INPUT_CACHE_ROOT" ] || die 'INPUT_CACHE_ROOT_REQUIRED=YES'
[ "$MODE" = --build ] || [ -z "$OUTPUT_DIR" ] || die 'OUTPUT_DIRECTORY_WITHOUT_BUILD=YES'
[ "$MODE" != --build ] || [ -n "$OUTPUT_DIR" ] || die 'OUTPUT_DIRECTORY_REQUIRED=YES'
run_preflight "$SOURCE_ROOT" "$INPUT_CACHE_ROOT"

if [ "$MODE" = --build ]; then
  construct_image "$SOURCE_ROOT" "$INPUT_CACHE_ROOT" "$OUTPUT_DIR"
  exit 0
fi

printf 'BUILD_PREFLIGHT=PASS\n'
