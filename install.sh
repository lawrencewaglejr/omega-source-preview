#!/bin/bash
set -uo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH GLOBIGNORE
umask 077
readonly EXIT_SUCCESS=0 EXIT_REFUSED=1 EXIT_INVALID=2
readonly EXIT_PREFLIGHT=3 EXIT_ROLLED_BACK=4 EXIT_ROLLBACK_INCOMPLETE=5
declare ACTION="install" ACTION_SET=false DRY_RUN=false DESTDIR_SET=false
declare DESTDIR="/" ROOT_PREFIX="" LOCK_DIR="" LOCK_HELD=false
declare BIN_DIR="" STATE_DIR="" RECEIPT="" MANIFEST="" REPO_ROOT=""
declare MANIFEST_HASH="" SNAPSHOT_MANIFEST_HASH="" CURRENT_RECEIPT_HASH=""
declare PRE_CODE=$EXIT_INVALID PRE_MESSAGE="" RECEIPT_PRESENT=false
declare BIN_TXN="" STATE_TXN="" MUTATION_STARTED=false NEW_RECEIPT_HASH=""
declare TEST_FAULT="${OMEGA_INSTALL_TEST_FAULT:-}"
unset OMEGA_INSTALL_TEST_FAULT
declare -a DESTINATIONS=() LEGACY_HASHES=() LEGACY_LINKS=()
declare -a SOURCE_PATHS=() SOURCE_HASHES=() CLASSES=() RECEIPT_HASHES=()
declare -a STAGED_HASHES=() CREATED_DIRS=()
declare -a SNAPSHOT_DESTINATIONS=() SNAPSHOT_SOURCE_PATHS=() SNAPSHOT_SOURCE_HASHES=()
usage() {
  printf '%s\n' 'Usage:' \
    '  ./install.sh install [--dry-run] [--destdir ABSOLUTE_PATH]' \
    '  ./install.sh uninstall [--dry-run] [--destdir ABSOLUTE_PATH]' \
    '  ./install.sh --help' \
    'With no action, install is used. The installer never invokes sudo.'
}
set_error() { PRE_CODE="$1"; PRE_MESSAGE="$2"; return 1; }
valid_absolute_syntax() {
  local value="$1" component
  local -a components
  [ -n "$value" ] || return 1
  [[ "$value" == /* ]] || return 1
  [[ "$value" != *[[:cntrl:]]* ]] || return 1
  if [ "$value" != "/" ]; then
    [[ "$value" != */ ]] || return 1
    [[ "$value" != *//* ]] || return 1
  fi
  IFS=/ read -r -a components <<< "${value#/}"
  for component in "${components[@]}"; do
    [ "$component" != "." ] && [ "$component" != ".." ] || return 1
  done
}
safe_directory_chain() {
  local value="$1" current="" component
  local -a components
  valid_absolute_syntax "$value" || return 1
  [ "$value" = "/" ] && return 0
  IFS=/ read -r -a components <<< "${value#/}"
  for component in "${components[@]}"; do
    current="$current/$component"
    [ ! -L "$current" ] || return 1
    if [ -e "$current" ] && [ ! -d "$current" ]; then return 1; fi
  done
}
safe_destination_parent() { local parent="${1%/*}"; safe_directory_chain "${parent:-/}"; }
file_mode() { stat -c '%a' -- "$1" 2>/dev/null; }
file_hash() {
  local output
  output=$(sha256sum -- "$1" 2>/dev/null) || return 1
  printf '%s' "${output%% *}"
}
is_hex_hash() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
value_in_list() {
  local needle="$1" list="$2" item
  local -a items
  [ "$list" != "-" ] || return 1
  IFS=, read -r -a items <<< "$list"
  for item in "${items[@]}"; do [ "$needle" = "$item" ] && return 0; done
  return 1
}
check_lifecycle_dependencies() {
  local dependency
  local -a required=(chmod cp mkdir mktemp mv readlink rm rmdir sha256sum stat uname)
  for dependency in "${required[@]}"; do
    [ "$TEST_FAULT" != "missing-lifecycle:$dependency" ] && command -v "$dependency" >/dev/null 2>&1 || {
      set_error "$EXIT_PREFLIGHT" "Required lifecycle dependency not found: $dependency"; return;
    }
  done
  [ "$(uname -s 2>/dev/null)" = "Linux" ] || {
    set_error "$EXIT_PREFLIGHT" "OMEGA installation is supported only on Linux."; return;
  }
  (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )) || {
    set_error "$EXIT_PREFLIGHT" "Bash 4.3 or newer is required."; return;
  }
}
load_manifest() {
  local source destination mode legacy_hashes legacy_links extra
  local source_path source_mode source_hash manifest_mode index
  local seen_report=false seen_doctor=false
  local -a rows
  local -A seen_destinations
  DESTINATIONS=(); LEGACY_HASHES=(); LEGACY_LINKS=(); SOURCE_PATHS=(); SOURCE_HASHES=()
  manifest_mode=$(file_mode "$MANIFEST") || manifest_mode=""
  [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] && [[ "$manifest_mode" =~ ^[4567][0145][0145]$ ]] || {
    set_error "$EXIT_PREFLIGHT" "Command manifest is missing or unsafe: $MANIFEST"; return;
  }
  MANIFEST_HASH=$(file_hash "$MANIFEST") || { set_error "$EXIT_PREFLIGHT" "Cannot checksum command manifest."; return; }
  mapfile -t rows < "$MANIFEST" || { set_error "$EXIT_PREFLIGHT" "Cannot read command manifest."; return; }
  [ "${#rows[@]}" -eq 10 ] && [ "${rows[0]}" = "OMEGA_COMMAND_MANIFEST_V1" ] || {
    set_error "$EXIT_INVALID" "Manifest must contain one supported header and nine rows."; return;
  }
  for ((index=0; index<9; index++)); do
    IFS=$'\t' read -r source destination mode legacy_hashes legacy_links extra <<< "${rows[index + 1]}"
    if [ -n "$extra" ] ||
       [[ ! "$source" =~ ^scripts/[A-Za-z0-9._-]+\.sh$ ]] ||
       [[ ! "$destination" =~ ^/usr/local/bin/[A-Za-z0-9._-]+$ ]] ||
       [ "$mode" != "0755" ] ||
       [[ ! "$legacy_hashes" =~ ^(-|[0-9a-f]{64}(,[0-9a-f]{64})*)$ ]] ||
       [[ ! "$legacy_links" =~ ^(-|/[^,[:cntrl:]]+(,/[^,[:cntrl:]]+)*)$ ]]; then
      set_error "$EXIT_INVALID" "Malformed command manifest row $((index + 2))."; return
    fi
    [ -z "${seen_destinations[$destination]+present}" ] || {
      set_error "$EXIT_INVALID" "Duplicate manifest destination: $destination"; return;
    }
    seen_destinations[$destination]=true
    source_path="$REPO_ROOT/$source"
    safe_directory_chain "${source_path%/*}" && [ -f "$source_path" ] && [ ! -L "$source_path" ] || {
      set_error "$EXIT_PREFLIGHT" "Required command source is missing or unsafe: $source"; return;
    }
    source_mode=$(file_mode "$source_path") && { [ "$source_mode" = 755 ] || [ "$source_mode" = 775 ]; } || {
      set_error "$EXIT_PREFLIGHT" "Command source mode must be 0755 or 0775: $source"; return;
    }
    source_hash=$(file_hash "$source_path") || { set_error "$EXIT_PREFLIGHT" "Cannot checksum source: $source"; return; }
    DESTINATIONS[index]="$destination"
    LEGACY_HASHES[index]="$legacy_hashes"; LEGACY_LINKS[index]="$legacy_links"
    SOURCE_PATHS[index]="$source_path"; SOURCE_HASHES[index]="$source_hash"
    [ "$source:$destination" = "scripts/omega-report.sh:/usr/local/bin/omega-report" ] && seen_report=true
    [ "$source:$destination" = "scripts/omega-doctor.sh:/usr/local/bin/omega-doctor" ] && seen_doctor=true
  done
  [ "$seen_report" = true ] && [ "$seen_doctor" = true ] || {
    set_error "$EXIT_INVALID" "Manifest must contain nine commands, hardened omega-report, and omega-doctor."; return;
  }
}
read_receipt() {
  local tag manifest_hash destination checksum mode extra index
  local -a rows
  RECEIPT_PRESENT=false; CURRENT_RECEIPT_HASH=""; RECEIPT_HASHES=()
  if [ ! -e "$RECEIPT" ] && [ ! -L "$RECEIPT" ]; then return 0; fi
  [ -f "$RECEIPT" ] && [ ! -L "$RECEIPT" ] && [ "$(file_mode "$RECEIPT")" = 600 ] || {
    set_error "$EXIT_REFUSED" "Installed-state receipt is missing, modified, or unsafe."; return;
  }
  mapfile -t rows < "$RECEIPT" || { set_error "$EXIT_REFUSED" "Installed-state receipt cannot be read."; return; }
  [ "${#rows[@]}" -eq 10 ] || { set_error "$EXIT_REFUSED" "Installed-state receipt must contain ten rows."; return; }
  IFS=$'\t' read -r tag manifest_hash extra <<< "${rows[0]}"
  if [ "$tag" != "OMEGA_STATE_V1" ] || ! is_hex_hash "$manifest_hash" || [ -n "$extra" ] ||
     { [ "$ACTION" = uninstall ] && [ "$manifest_hash" != "$MANIFEST_HASH" ]; }; then
    set_error "$EXIT_REFUSED" "Installed-state receipt header is invalid."; return
  fi
  for ((index=0; index<9; index++)); do
    IFS=$'\t' read -r destination checksum mode extra <<< "${rows[index + 1]}"
    if [ "$destination" != "${DESTINATIONS[index]}" ] || ! is_hex_hash "$checksum" ||
       [ "$mode" != "0755" ] || [ -n "$extra" ]; then
      set_error "$EXIT_REFUSED" "Installed-state receipt row $((index + 2)) is invalid."; return
    fi
    RECEIPT_HASHES[index]="$checksum"
  done
  CURRENT_RECEIPT_HASH=$(file_hash "$RECEIPT") || { set_error "$EXIT_REFUSED" "Receipt cannot be checksummed."; return; }
  RECEIPT_PRESENT=true
}
classify_destinations() {
  local index destination actual hash target any_present=false
  CLASSES=()
  read_receipt || return 1
  for ((index=0; index<9; index++)); do
    destination="$ROOT_PREFIX${DESTINATIONS[index]}"
    safe_destination_parent "$destination" || {
      set_error "$EXIT_INVALID" "Unsafe destination parent: $destination"; return 1;
    }
    if [ "$RECEIPT_PRESENT" = true ]; then
      if [ ! -f "$destination" ] || [ -L "$destination" ]; then
        set_error "$EXIT_REFUSED" "Managed destination is missing or not a regular file: $destination"; return 1
      fi
      actual=$(file_mode "$destination") || actual=""
      hash=$(file_hash "$destination") || hash=""
      if [ "$actual" != "755" ] || [ "$hash" != "${RECEIPT_HASHES[index]}" ]; then
        set_error "$EXIT_REFUSED" "Managed destination differs from its receipt: $destination"; return 1
      fi
      CLASSES[index]="managed"
    elif [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
      CLASSES[index]="absent"
    elif [ -L "$destination" ]; then
      any_present=true
      target=$(readlink -- "$destination" 2>/dev/null) || target=""
      if value_in_list "$target" "${LEGACY_LINKS[index]}"; then
        CLASSES[index]="legacy-symlink"
      else
        set_error "$EXIT_REFUSED" "Unrecognized destination symlink: $destination"; return 1
      fi
    elif [ -f "$destination" ]; then
      any_present=true
      hash=$(file_hash "$destination") || hash=""
      actual=$(file_mode "$destination") || actual=""
      if [ "$actual" != "755" ]; then
        set_error "$EXIT_REFUSED" "Recognized destination does not have mode 0755: $destination"; return 1
      elif [ "$hash" = "${SOURCE_HASHES[index]}" ]; then
        CLASSES[index]="identical"
      elif value_in_list "$hash" "${LEGACY_HASHES[index]}"; then
        CLASSES[index]="legacy-file"
      else
        set_error "$EXIT_REFUSED" "Unknown or modified destination file: $destination"; return 1
      fi
    else
      set_error "$EXIT_REFUSED" "Unsupported destination type: $destination"; return 1
    fi
  done
  if [ "$ACTION" = "uninstall" ] && [ "$RECEIPT_PRESENT" != true ] && [ "$any_present" = true ]; then
    set_error "$EXIT_REFUSED" "Uninstall requires a valid current installed-state receipt."; return 1
  fi
}
report_runtime_warnings() {
  local dependency
  local -a integrations=(curl docker jq sudo systemctl tailscale)
  echo "WARNING: Runtime services and integrations are not contacted or provisioned by this installer." >&2
  for dependency in "${integrations[@]}"; do
    if [ "$TEST_FAULT" = "missing-runtime:$dependency" ] || ! command -v "$dependency" >/dev/null 2>&1; then
      echo "WARNING: Runtime integration command not found: $dependency" >&2
    fi
  done
}
preflight() {
  safe_directory_chain "$DESTDIR" || {
    set_error "$EXIT_INVALID" "Destination root became unsafe: $DESTDIR"; return 1;
  }
  safe_destination_parent "$LOCK_DIR" || {
    set_error "$EXIT_INVALID" "Lifecycle lock parent is unsafe."; return 1;
  }
  load_manifest && classify_destinations
}
freeze_snapshot() {
  SNAPSHOT_MANIFEST_HASH="$MANIFEST_HASH"
  SNAPSHOT_DESTINATIONS=("${DESTINATIONS[@]}")
  SNAPSHOT_SOURCE_PATHS=("${SOURCE_PATHS[@]}")
  SNAPSHOT_SOURCE_HASHES=("${SOURCE_HASHES[@]}")
}
snapshot_unchanged() {
  local index
  [ "$MANIFEST_HASH" = "$SNAPSHOT_MANIFEST_HASH" ] || { set_error "$EXIT_PREFLIGHT" "Command manifest changed after locked preflight."; return; }
  for ((index=0; index<9; index++)); do
    [ "${DESTINATIONS[index]}" = "${SNAPSHOT_DESTINATIONS[index]}" ] &&
      [ "${SOURCE_PATHS[index]}" = "${SNAPSHOT_SOURCE_PATHS[index]}" ] &&
      [ "${SOURCE_HASHES[index]}" = "${SNAPSHOT_SOURCE_HASHES[index]}" ] || {
        set_error "$EXIT_PREFLIGHT" "Command manifest or source changed after locked preflight."; return;
      }
  done
}
acquire_lock() {
  local owner=""
  if [ -L "$LOCK_DIR" ] || { [ -e "$LOCK_DIR" ] && [ ! -d "$LOCK_DIR" ]; }; then
    set_error "$EXIT_REFUSED" "Lifecycle lock path has an unsafe type."
    return 1
  fi
  if mkdir -- "$LOCK_DIR" 2>/dev/null; then
    LOCK_HELD=true
    printf '%s\n' "$$" > "$LOCK_DIR/pid" || { set_error "$EXIT_PREFLIGHT" "Cannot initialize lifecycle lock."; release_lock || PRE_CODE=$EXIT_ROLLBACK_INCOMPLETE; return 1; }
    return 0
  fi
  if [ -r "$LOCK_DIR/pid" ]; then IFS= read -r owner < "$LOCK_DIR/pid" || owner=""; fi
  if [[ "$owner" =~ ^[0-9]+$ ]] && kill -0 "$owner" 2>/dev/null; then
    set_error "$EXIT_PREFLIGHT" "Another OMEGA lifecycle operation holds the lock."
  else
    set_error "$EXIT_ROLLBACK_INCOMPLETE" "A stale lock or interrupted lifecycle operation requires review: $LOCK_DIR"
  fi
  return 1
}
release_lock() {
  if [ "$LOCK_HELD" = true ]; then
    [ "$TEST_FAULT" != cleanup-lock ] && rm -rf -- "$LOCK_DIR" || return 1
    [ ! -e "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ] || return 1
    LOCK_HELD=false
  fi
}
ensure_directory() {
  local directory="$1" mode="$2"
  if [ -d "$directory" ]; then return 0; fi
  mkdir -m "$mode" -- "$directory" || return 1
  CREATED_DIRS+=("$directory")
}
create_target_directories() {
  local directory
  local -a paths=("$ROOT_PREFIX/usr" "$ROOT_PREFIX/usr/local" "$BIN_DIR" "$ROOT_PREFIX/var" "$ROOT_PREFIX/var/lib" "$STATE_DIR")
  [ -n "$ROOT_PREFIX" ] || paths=("/usr" "/usr/local" "$BIN_DIR" "/var" "/var/lib" "$STATE_DIR")
  for directory in "${paths[@]}"; do
    safe_directory_chain "$directory" || return 1
    ensure_directory "$directory" 0755 || return 1
  done
}
cleanup_created_directories() {
  local index
  for ((index=${#CREATED_DIRS[@]}-1; index>=0; index--)); do
    rmdir -- "${CREATED_DIRS[index]}" 2>/dev/null || true
  done
  CREATED_DIRS=()
}
safe_remove_transactions() {
  [ "$TEST_FAULT" != cleanup-transaction ] || return 1
  if [ -n "$BIN_TXN" ]; then
    case "$BIN_TXN" in "$BIN_DIR"/.omega-transaction.*) rm -rf -- "$BIN_TXN" || return 1 ;; *) return 1 ;; esac
    [ ! -e "$BIN_TXN" ] && [ ! -L "$BIN_TXN" ] || return 1
    BIN_TXN=""
  fi
  if [ -n "$STATE_TXN" ]; then
    case "$STATE_TXN" in "$STATE_DIR"/.omega-state.*) rm -rf -- "$STATE_TXN" || return 1 ;; *) return 1 ;; esac
    [ ! -e "$STATE_TXN" ] && [ ! -L "$STATE_TXN" ] || return 1
    STATE_TXN=""
  fi
}
cleanup_before_mutation() {
  safe_remove_transactions || return 1
  cleanup_created_directories; release_lock
}
abort_before_mutation() {
  local code="$1"; echo "ERROR: $PRE_MESSAGE" >&2
  cleanup_before_mutation || { echo "ERROR: Pre-publication cleanup is incomplete." >&2; exit "$EXIT_ROLLBACK_INCOMPLETE"; }
  exit "$code"
}
file_matches() {
  local path="$1" checksum="$2" mode="$3"
  [ -f "$path" ] && [ ! -L "$path" ] &&
    [ "$(file_mode "$path")" = "$mode" ] && [ "$(file_hash "$path")" = "$checksum" ]
}
original_matches() {
  local index="$1" path="$2" target
  case "${CLASSES[index]}" in
    absent) [ ! -e "$path" ] && [ ! -L "$path" ] ;;
    legacy-symlink)
      [ -L "$path" ] || return 1
      target=$(readlink -- "$path" 2>/dev/null) || return 1
      value_in_list "$target" "${LEGACY_LINKS[index]}"
      ;;
    managed) file_matches "$path" "${RECEIPT_HASHES[index]}" 755 ;;
    identical) file_matches "$path" "${SNAPSHOT_SOURCE_HASHES[index]}" 755 ;;
    legacy-file)
      [ -f "$path" ] && [ ! -L "$path" ] && [ "$(file_mode "$path")" = 755 ] &&
        value_in_list "$(file_hash "$path")" "${LEGACY_HASHES[index]}"
      ;;
  esac
}
rollback_current_operation() {
  local index destination old staged complete=true
  trap '' HUP INT TERM
  for ((index=8; index>=0; index--)); do
    destination="$ROOT_PREFIX${SNAPSHOT_DESTINATIONS[index]}"
    old="$BIN_TXN/old/$index"; staged="$BIN_TXN/stage/$index"
    if [ -e "$old" ] || [ -L "$old" ]; then
      if [ -e "$destination" ] || [ -L "$destination" ]; then
        file_matches "$destination" "${STAGED_HASHES[index]}" 755 && rm -f -- "$destination" || complete=false
      fi
      if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
        mv -T -- "$old" "$destination" || complete=false
      else
        complete=false
      fi
    elif [ "${CLASSES[index]}" = absent ]; then
      if file_matches "$destination" "${STAGED_HASHES[index]}" 755; then
        rm -f -- "$destination" || complete=false
      elif ! file_matches "$staged" "${STAGED_HASHES[index]}" 755 || [ -e "$destination" ] || [ -L "$destination" ]; then
        complete=false
      fi
    elif ! original_matches "$index" "$destination"; then
      complete=false
    fi
  done
  if [ -f "$STATE_TXN/receipt.old" ]; then
    if file_matches "$RECEIPT" "$NEW_RECEIPT_HASH" 600; then
      rm -f -- "$RECEIPT" || complete=false
    elif [ -e "$RECEIPT" ] || [ -L "$RECEIPT" ]; then
      complete=false
    fi
    if [ ! -e "$RECEIPT" ] && [ ! -L "$RECEIPT" ]; then
      mv -T -- "$STATE_TXN/receipt.old" "$RECEIPT" || complete=false
    else
      complete=false
    fi
  elif [ "$RECEIPT_PRESENT" = true ]; then
    file_matches "$RECEIPT" "$CURRENT_RECEIPT_HASH" 600 || complete=false
  elif file_matches "$RECEIPT" "$NEW_RECEIPT_HASH" 600; then
    rm -f -- "$RECEIPT" || complete=false
  elif ! file_matches "$STATE_TXN/receipt.new" "$NEW_RECEIPT_HASH" 600 || [ -e "$RECEIPT" ] || [ -L "$RECEIPT" ]; then
    complete=false
  fi
  test_fault_at rollback-incomplete && complete=false
  if [ "$complete" = true ] && safe_remove_transactions; then
    MUTATION_STARTED=false
    cleanup_created_directories
    release_lock && return 0
  fi
  return 1
}
operation_failed() {
  local message="$1"
  echo "ERROR: $message" >&2
  if rollback_current_operation; then
    echo "The current operation was rolled back completely." >&2
    exit "$EXIT_ROLLED_BACK"
  fi
  echo "Rollback is incomplete; transaction artifacts and lock were retained." >&2
  exit "$EXIT_ROLLBACK_INCOMPLETE"
}
handle_signal() {
  trap '' HUP INT TERM
  if [ "$MUTATION_STARTED" = true ]; then operation_failed "Lifecycle operation interrupted."; fi
  cleanup_before_mutation || exit "$EXIT_ROLLBACK_INCOMPLETE"
  exit "$EXIT_PREFLIGHT"
}
test_fault_at() { [ "$TEST_FAULT" = "$1" ]; }
prepare_transactions() {
  local index staged receipt_new
  BIN_TXN=$(mktemp -d -- "$BIN_DIR/.omega-transaction.XXXXXX") || return 1
  STATE_TXN=$(mktemp -d -- "$STATE_DIR/.omega-state.XXXXXX") || return 1
  mkdir -- "$BIN_TXN/stage" "$BIN_TXN/old" || return 1
  printf '%s\n%s\n' "$BIN_TXN" "$STATE_TXN" > "$LOCK_DIR/transaction" || return 1
  STAGED_HASHES=()
  for ((index=0; index<9; index++)); do
    staged="$BIN_TXN/stage/$index"
    cp -- "${SNAPSHOT_SOURCE_PATHS[index]}" "$staged" || return 1
    chmod 0755 -- "$staged" || return 1
    STAGED_HASHES[index]=$(file_hash "$staged") || return 1
    [ "${STAGED_HASHES[index]}" = "${SNAPSHOT_SOURCE_HASHES[index]}" ] || return 1
  done
  receipt_new="$STATE_TXN/receipt.new"
  {
    printf 'OMEGA_STATE_V1\t%s\n' "$SNAPSHOT_MANIFEST_HASH"
    for ((index=0; index<9; index++)); do
      printf '%s\t%s\t0755\n' "${SNAPSHOT_DESTINATIONS[index]}" "${STAGED_HASHES[index]}"
    done
  } > "$receipt_new" || return 1
  chmod 0600 -- "$receipt_new" || return 1
  NEW_RECEIPT_HASH=$(file_hash "$receipt_new") || return 1
}
publish_install() {
  local index destination staged old replace
  MUTATION_STARTED=true
  for ((index=0; index<9; index++)); do
    destination="$ROOT_PREFIX${SNAPSHOT_DESTINATIONS[index]}"
    staged="$BIN_TXN/stage/$index"; old="$BIN_TXN/old/$index"; replace=true
    if [ "${CLASSES[index]}" = "identical" ] ||
       { [ "${CLASSES[index]}" = "managed" ] && [ "${RECEIPT_HASHES[index]}" = "${SNAPSHOT_SOURCE_HASHES[index]}" ]; }; then
      replace=false
    fi
    if [ "$replace" = true ]; then
      if [ -e "$destination" ] || [ -L "$destination" ]; then
        mv -T -- "$destination" "$old" || operation_failed "Cannot quarantine $destination"
      fi
      mv -T -- "$staged" "$destination" || operation_failed "Cannot publish $destination"
      if ((index == 0)) && test_fault_at pause-after-publish; then : > "$LOCK_DIR/test-ready" || operation_failed "Cannot pause test publication."; kill -STOP "$$"; fi
      test_fault_at "publish:$((index + 1))" && operation_failed "Injected publication failure."
      test_fault_at rollback-incomplete && operation_failed "Injected incomplete rollback."
    fi
  done
  if [ "$RECEIPT_PRESENT" = true ]; then
    mv -T -- "$RECEIPT" "$STATE_TXN/receipt.old" || operation_failed "Cannot quarantine the current receipt."
  fi
  test_fault_at "receipt" && operation_failed "Injected receipt failure."
  mv -T -- "$STATE_TXN/receipt.new" "$RECEIPT" || operation_failed "Cannot publish installed-state receipt."
}
publish_uninstall() {
  local index destination old
  MUTATION_STARTED=true
  for ((index=0; index<9; index++)); do
    destination="$ROOT_PREFIX${SNAPSHOT_DESTINATIONS[index]}"; old="$BIN_TXN/old/$index"
    mv -T -- "$destination" "$old" || operation_failed "Cannot quarantine $destination"
    test_fault_at "publish:$((index + 1))" && operation_failed "Injected removal failure."
  done
  mv -T -- "$RECEIPT" "$STATE_TXN/receipt.old" || operation_failed "Cannot remove installed-state receipt."
}
show_plan() {
  local index
  echo "OMEGA command lifecycle: $ACTION"
  echo "Destination root: $DESTDIR"
  echo "Dry run: $DRY_RUN"
  if [ "$DRY_RUN" = true ]; then echo "NOTE: dry-run is an advisory snapshot and does not acquire the lifecycle lock."; fi
  for ((index=0; index<9; index++)); do printf '%-18s %s\n' "${CLASSES[index]}" "$ROOT_PREFIX${DESTINATIONS[index]}"; done
}
while (($#)); do
  case "$1" in
    install|uninstall)
      [ "$ACTION_SET" = false ] || { echo "ERROR: Multiple lifecycle actions supplied." >&2; exit "$EXIT_INVALID"; }
      ACTION="$1"; ACTION_SET=true; shift ;;
    --dry-run)
      [ "$DRY_RUN" = false ] || { echo "ERROR: Duplicate --dry-run." >&2; exit "$EXIT_INVALID"; }
      DRY_RUN=true; shift ;;
    --destdir)
      [ "$#" -ge 2 ] || { echo "ERROR: --destdir requires a path." >&2; exit "$EXIT_INVALID"; }
      [ "$DESTDIR_SET" = false ] || { echo "ERROR: Duplicate --destdir." >&2; exit "$EXIT_INVALID"; }
      DESTDIR="$2"; DESTDIR_SET=true; shift 2 ;;
    --help) usage || exit "$EXIT_PREFLIGHT"; exit "$EXIT_SUCCESS" ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage >&2; exit "$EXIT_INVALID" ;;
  esac
done
valid_absolute_syntax "$DESTDIR" && safe_directory_chain "$DESTDIR" && [ -d "$DESTDIR" ] || {
  echo "ERROR: --destdir must be an existing, safe absolute directory." >&2; exit "$EXIT_INVALID";
}
[ "$DESTDIR" = "/" ] || ROOT_PREFIX="$DESTDIR"
if [ -n "$TEST_FAULT" ]; then
  case "$TEST_FAULT" in missing-lifecycle:*|missing-runtime:*|publish:[1-9]|receipt|pause-after-stage|pause-after-publish|cleanup-transaction|cleanup-lock|rollback-incomplete) ;; *) echo "ERROR: Invalid test fault." >&2; exit "$EXIT_INVALID" ;; esac
  [ "$DESTDIR" != "/" ] && [ -f "$DESTDIR/.omega-installer-test-root" ] || {
    echo "ERROR: Test faults are restricted to marked non-root destination roots." >&2; exit "$EXIT_INVALID";
  }
fi
script_path="${BASH_SOURCE[0]}"
[[ "$script_path" == /* ]] || script_path="$PWD/$script_path"
script_directory="${script_path%/*}"
REPO_ROOT=$(cd -P -- "$script_directory" 2>/dev/null && pwd) || {
  echo "ERROR: Cannot resolve repository root." >&2; exit "$EXIT_PREFLIGHT";
}
MANIFEST="$REPO_ROOT/install/commands.manifest"
BIN_DIR="$ROOT_PREFIX/usr/local/bin"
STATE_DIR="$ROOT_PREFIX/var/lib/omega-command-layer"
RECEIPT="$STATE_DIR/installed.tsv"
LOCK_DIR="$ROOT_PREFIX/.omega-command-layer.lock"
if ! check_lifecycle_dependencies; then echo "ERROR: $PRE_MESSAGE" >&2; exit "$PRE_CODE"; fi
if [ "$DRY_RUN" = true ]; then
  if ! preflight; then echo "ERROR: $PRE_MESSAGE" >&2; exit "$PRE_CODE"; fi
  report_runtime_warnings
  show_plan
  exit "$EXIT_SUCCESS"
fi
if [ "$DESTDIR" = "/" ] && [ "$EUID" -ne 0 ]; then
  echo "ERROR: Root privileges are required without --destdir." >&2
  exit "$EXIT_PREFLIGHT"
fi
trap handle_signal HUP INT TERM
if ! acquire_lock; then echo "ERROR: $PRE_MESSAGE" >&2; exit "$PRE_CODE"; fi
if ! preflight; then abort_before_mutation "$PRE_CODE"; fi
freeze_snapshot
report_runtime_warnings
if [ "$ACTION" = "uninstall" ] && [ "$RECEIPT_PRESENT" != true ]; then
  show_plan
  release_lock || { echo "ERROR: Lifecycle lock removal failed." >&2; exit "$EXIT_ROLLBACK_INCOMPLETE"; }
  echo "OMEGA command layer is already absent."
  exit "$EXIT_SUCCESS"
fi
if ! create_target_directories; then set_error "$EXIT_PREFLIGHT" "Cannot create safe lifecycle target directories."; abort_before_mutation "$PRE_CODE"; fi
if ! preflight || ! snapshot_unchanged; then abort_before_mutation "$PRE_CODE"; fi
if ! prepare_transactions; then set_error "$EXIT_PREFLIGHT" "Cannot prepare private transaction staging."; abort_before_mutation "$PRE_CODE"; fi
if test_fault_at pause-after-stage; then : > "$LOCK_DIR/test-ready" || { set_error "$EXIT_PREFLIGHT" "Cannot pause manifest test."; abort_before_mutation "$PRE_CODE"; }; kill -STOP "$$"; fi
if ! preflight || ! snapshot_unchanged; then abort_before_mutation "$PRE_CODE"; fi
show_plan
if [ "$ACTION" = "install" ]; then publish_install; else publish_uninstall; fi
MUTATION_STARTED=false
if ! safe_remove_transactions || ! release_lock; then
  echo "ERROR: Installation state is complete, but transaction cleanup is incomplete." >&2
  exit "$EXIT_ROLLBACK_INCOMPLETE"
fi
if [ "$ACTION" = "uninstall" ]; then rmdir -- "$STATE_DIR" 2>/dev/null || true; fi
echo "OMEGA command lifecycle $ACTION completed successfully."
exit "$EXIT_SUCCESS"
