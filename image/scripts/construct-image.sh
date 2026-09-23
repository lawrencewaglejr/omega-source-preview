#!/bin/bash -p
set -euo pipefail

IFS=$' \t\n'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
export HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent
export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH=1787801458
export E2FSPROGS_FAKE_TIME=1787801458
export IG_OFFLINE=y PIP_NO_DEPS=1 PIP_DISABLE_PIP_VERSION_CHECK=1
umask 0022

builder_root=$1
source_root=$2
build_root=$3
release_root=$4
source_commit=$5
export PATH="$source_root/host-tools:$PATH"

# The target contains private directories owned by subordinate UIDs. Remove it
# before leaving this namespace, while those owners are still mapped.
[[ "$build_root" =~ ^/tmp/omega-phase4-builder\.[A-Za-z0-9]{8}/build$ ]]
[ -d "$build_root" ] && [ ! -L "$build_root" ]
[ "$(/usr/bin/readlink -f -- "$build_root")" = "$build_root" ]
[ "$(/usr/bin/stat -c %u -- "$build_root")" = "$(/usr/bin/id -u)" ]
[ "$(/usr/bin/stat -c %a -- "${build_root%/*}")" = 700 ]
build_identity=$(/usr/bin/stat -c '%d:%i' -- "$build_root")
parent_identity=$(/usr/bin/stat -c '%d:%i' -- "${build_root%/*}")

cleanup_construction_work() {
  [ -d "$build_root" ] && [ ! -L "$build_root" ] || return 1
  [ "$(/usr/bin/readlink -f -- "$build_root")" = "$build_root" ] || return 1
  [ "$(/usr/bin/stat -c '%d:%i' -- "$build_root")" = "$build_identity" ] || return 1
  [ "$(/usr/bin/stat -c '%d:%i' -- "${build_root%/*}")" = "$parent_identity" ] || return 1
  [ "$(/usr/bin/stat -c %a -- "${build_root%/*}")" = 700 ] || return 1
  /usr/bin/rm -rf --one-file-system -- "$build_root" || return 1
  [ ! -e "$build_root" ] && [ ! -L "$build_root" ]
}

finish_construction() {
  local status=$?
  trap - EXIT
  if ! cleanup_construction_work; then
    printf 'CONSTRUCTION_WORK_CLEANUP=FAILED\n' >&2
    [ "$status" -ne 0 ] || status=1
  fi
  exit "$status"
}
trap finish_construction EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ -x "$builder_root/rpi-image-gen" ]
[ -f "$source_root/config/omega-rpi5-trixie-arm64.yaml" ]
[ -d "$build_root/cache" ]
[ ! -e "$release_root" ]

"$builder_root/rpi-image-gen" build \
  -c "$source_root/config/omega-rpi5-trixie-arm64.yaml" \
  -S "$source_root" \
  -B "$build_root"

/usr/bin/python3 -B "$source_root/scripts/assemble-release.py" \
  --build-root "$build_root" \
  --omega-source "$source_root" \
  --output-directory "$release_root" \
  --source-commit "$source_commit"

cleanup_construction_work
trap - EXIT HUP INT TERM
printf 'FULL_IMAGE_CONSTRUCTION=PASS\n'
