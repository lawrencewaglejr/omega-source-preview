#!/bin/bash -p
set -euo pipefail

IFS=$' \t\n'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
hash -r
umask 0022
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

readonly GREP_TOOL=/usr/bin/grep
readonly TAIL_TOOL=/usr/bin/tail
readonly DIRNAME_TOOL=/usr/bin/dirname
readonly READLINK_TOOL=/usr/bin/readlink
readonly SHA256SUM_TOOL=/usr/bin/sha256sum
readonly STAT_TOOL=/usr/bin/stat

for required_tool in "$GREP_TOOL" "$TAIL_TOOL" "$DIRNAME_TOOL" "$READLINK_TOOL" "$SHA256SUM_TOOL" "$STAT_TOOL"; do
  [ -f "$required_tool" ] && [ -x "$required_tool" ] ||
    die "VALIDATOR_TOOL_UNAVAILABLE=$required_tool"
done

SCRIPT_DIR=$($READLINK_TOOL -f -- "$($DIRNAME_TOOL -- "${BASH_SOURCE[0]}")")
DEFAULT_IMAGE_ROOT=$($READLINK_TOOL -f -- "$SCRIPT_DIR/..")

usage() {
  cat <<'EOF'
Usage: verify.sh [--image-root ABSOLUTE_PATH] [--require-service-locks]
                 [--require-build-readiness]
       verify.sh --check-architecture ARCHITECTURE

Validates the Phase 4 builder foundation without network or build activity.
EOF
}

reject_floating_value() {
  local label=$1 key=$2 value=$3 lower
  lower=${value,,}
  case "$lower" in
    latest|master|stable|testing|unstable|rolling|edge|head|tip|trunk|'*')
      die "$label contains a floating value: $value"
      ;;
    main)
      case "$key" in
        *_component|*_components) ;;
        *) die "$label contains a floating value: $value" ;;
      esac
      ;;
  esac
  case "$lower" in
    */latest/*|*/master/*|*/refs/heads/*|*:latest|*:latest@*|*'?ref=master'*|*'?ref=main'*)
      die "$label contains a floating reference: $value"
      ;;
  esac
}

require_regular_file() {
  local label=$1 path=$2 expected_relative=$3 expected_path component remainder part canonical
  expected_path="$CANONICAL_IMAGE_ROOT/$expected_relative"
  [ "$path" = "$expected_path" ] || die "$label is not at its expected path: $path"

  component=$CANONICAL_IMAGE_ROOT
  remainder=$expected_relative
  while :; do
    part=${remainder%%/*}
    [ -n "$part" ] && [ "$part" != . ] && [ "$part" != .. ] ||
      die "$label has an invalid expected path: $expected_relative"
    component="$component/$part"
    if [ -L "$component" ]; then
      if [ "$remainder" = "$part" ]; then
        die "$label must not be a symbolic link: $component"
      fi
      die "$label path contains a symbolic link: $component"
    fi
    [ "$remainder" = "$part" ] && break
    [ -d "$component" ] || die "$label parent directory is invalid: $component"
    remainder=${remainder#*/}
  done

  [ -f "$path" ] || die "$label is missing or is not a regular file: $path"
  canonical=$($READLINK_TOOL -f -- "$path") || die "$label path cannot be canonicalized: $path"
  [ "$canonical" = "$expected_path" ] ||
    die "$label canonical path mismatch: $path -> $canonical"
}

reject_unsupported_raw_bytes() {
  local marker=$1 path=$2
  if $GREP_TOOL -a -q '[^ -~]' "$path"; then
    die "INPUT_BYTES_INVALID=$marker"
  fi
}

declare -A LOCK_VALUES=()
CONFIG_BOOT_PART_SIZE=
CONFIG_ROOT_PART_SIZE=
BUILDER_RELEASE_AUTHENTICATION=
BUILDER_CONFIG_COMPATIBILITY=
NETWORK_ISOLATION=
RASPBERRYPI_REPOSITORY_TRUST=
PACKAGE_LOCK_STATUS=
OCI_LOCK_STATUS=

load_flat_lock() {
  local label=$1 marker=$2 path=$3 expected_relative=$4 line key value read_status line_number=0
  require_regular_file "$label" "$path" "$expected_relative"
  reject_unsupported_raw_bytes "$marker" "$path"
  LOCK_VALUES=()

  while true; do
    line=
    if IFS= read -r line; then
      read_status=0
    else
      read_status=$?
    fi
    if [ "$read_status" -ne 0 ]; then
      [ -z "$line" ] || die "$label is missing its final newline"
      break
    fi

    line_number=$((line_number + 1))
    [[ "$line" =~ ^([a-z][a-z0-9_]*)\:\ ([!-~]+)$ ]] ||
      die "$label has a malformed line at $line_number"
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    [ -z "${LOCK_VALUES[$key]+present}" ] ||
      die "$label contains duplicate key: $key"
    reject_floating_value "$label key $key" "$key" "$value"
    LOCK_VALUES[$key]=$value
  done < "$path"

  [ "$line_number" -gt 0 ] || die "$label is empty"
}

require_lock_schema() {
  local label=$1
  shift
  local required_key key
  declare -A allowed=()
  for required_key in "$@"; do
    allowed[$required_key]=1
    [ -n "${LOCK_VALUES[$required_key]+present}" ] ||
      die "$label is missing required key: $required_key"
  done
  for key in "${!LOCK_VALUES[@]}"; do
    [ -n "${allowed[$key]+present}" ] || die "$label contains unknown key: $key"
  done
}

expect_lock_value() {
  local label=$1 key=$2 expected=$3
  [ "${LOCK_VALUES[$key]}" = "$expected" ] ||
    die "$label has invalid $key: ${LOCK_VALUES[$key]}"
}

validate_config() {
  local path=$1 last_byte index
  local -a expected actual
  expected=(
    'env:'
    '  ARCH: arm64'
    '  SOURCE_DATE_EPOCH: 1787801458'
    ''
    'sys:'
    '  workroot: /build/omega'
    ''
    'device:'
    '  layer: rpi5'
    '  storage_type: sd'
    '  hostname: omega'
    '  user1sudo: passwd'
    ''
    'image:'
    '  layer: image-rpios'
    '  boot_part_size: 512M'
    '  root_part_size: 31G'
    '  name: omega-rpi5-trixie-arm64'
    '  rootfs_type: ext4'
    '  pmap: clear'
    '  disksig: "0xbd67750e"'
    ''
    'deploy:'
    '  compression: none'
    ''
    'sbom:'
    '  enable: n'
    ''
    'locale:'
    '  default: C.UTF-8'
    '  timezone: UTC'
    ''
    'artefact:'
    '  version: omega-v1'
    ''
    'layer:'
    '  base: omega-trixie-minbase'
    ''
    'fs:'
    '  ext4_mkfs_args: "-F -b 16384 -E hash_seed=bd67750e-9777-5c69-b79e-ee0d454fbe92"'
  )
  require_regular_file 'image config' "$path" 'config/omega-rpi5-trixie-arm64.yaml'
  reject_unsupported_raw_bytes image-config "$path"
  [ -s "$path" ] || die "image config is empty: $path"
  last_byte=$($TAIL_TOOL -c 1 -- "$path")
  [ -z "$last_byte" ] || die 'image config is missing its final newline'
  mapfile -t actual < "$path"
  [ "${#actual[@]}" -eq "${#expected[@]}" ] || die 'image config has an unexpected line count'
  for index in "${!expected[@]}"; do
    [ "${actual[$index]}" = "${expected[$index]}" ] ||
      die "image config mismatch at line $((index + 1))"
  done
  CONFIG_BOOT_PART_SIZE=${actual[15]#*boot_part_size: }
  CONFIG_ROOT_PART_SIZE=${actual[16]#*root_part_size: }
}

size_to_bytes() {
  local value=$1 number unit
  [[ "$value" =~ ^([0-9]+)([MG])$ ]] || die "STATIC_GEOMETRY_SIZE_INVALID=$value"
  number=${BASH_REMATCH[1]}
  unit=${BASH_REMATCH[2]}
  case "$unit" in
    M) SIZE_BYTES=$((number * 1024 * 1024)) ;;
    G) SIZE_BYTES=$((number * 1024 * 1024 * 1024)) ;;
  esac
}

validate_builder_lock() {
  local path=$1 label='builder lock' boot_bytes root_bytes geometry slack
  load_flat_lock "$label" builder-lock "$path" 'locks/builder.lock'
  require_lock_schema "$label" \
    schema status name upstream_repository_url upstream_release builder_release_tag_role \
    upstream_commit upstream_commit_role upstream_tree immutable_source_url source_archive_url \
    source_archive_sha256 source_archive_sha256_role builder_archive_cache_relative_path \
    builder_tree_manifest_path builder_tree_manifest_sha256 builder_archive_owner_policy \
    builder_archive_permissions_policy builder_archive_link_policy \
    builder_archive_validation_policy builder_evidence_runtime_role release_tag_type \
    release_tag_signature_status commit_signature_status commit_signer_fingerprint \
    commit_signer_key_ownership_status release_to_commit_binding release_authentication \
    release_authentication_basis release_authentication_residual_risk \
    source_archive_acquisition_report_sha256 builder_key_acquisition_report_sha256 \
    builder_key_request_log_sha256 builder_key_response_digests_sha256 \
    builder_key_response_headers_sha256 builder_key_artifacts_sha256 \
    builder_key_validation_sha256 future_mismatch_policy protected_omega_source_commit \
    protected_content_policy authorized_readme_commit authorized_readme_parent_commit \
    authorized_readme_blob current_source_commit_policy config_compatibility \
    builder_config_engine builder_config_execution_scope builder_config_network_isolation \
    builder_config_plan_entry_count builder_config_plan_sha256 \
    target_hardware target_os target_suite target_debian_major \
    target_architecture storage_target image_geometry_bytes geometry_slack_bytes \
    partition_layout output_format filesystem_expansion secure_boot_otp \
    device_bound_encryption timezone locale umask source_date_epoch network_policy \
    network_isolation network_isolation_entrypoint network_isolation_runtime_check
  expect_lock_value "$label" schema omega-builder-lock-v2
  expect_lock_value "$label" status unresolved
  expect_lock_value "$label" name rpi-image-gen
  expect_lock_value "$label" upstream_repository_url https://github.com/raspberrypi/rpi-image-gen.git
  expect_lock_value "$label" upstream_release v2.8.0
  expect_lock_value "$label" builder_release_tag_role informational-only-not-a-trust-anchor
  expect_lock_value "$label" upstream_commit 262d4df5a9f9d4133370465399a7958a7c22cdc7
  expect_lock_value "$label" upstream_commit_role operationally-authenticated-source-identity
  expect_lock_value "$label" upstream_tree b4d841718ae5436dd17ed7712cec47d010853ccd
  expect_lock_value "$label" immutable_source_url https://github.com/raspberrypi/rpi-image-gen/commit/262d4df5a9f9d4133370465399a7958a7c22cdc7
  expect_lock_value "$label" source_archive_url https://codeload.github.com/raspberrypi/rpi-image-gen/tar.gz/262d4df5a9f9d4133370465399a7958a7c22cdc7
  expect_lock_value "$label" source_archive_sha256 5fb1d564d9cbe0064310e1a2123bfaa0782d7010c2545c38383020cf353321ca
  expect_lock_value "$label" source_archive_sha256_role retained-transport-content-identifier
  expect_lock_value "$label" builder_archive_cache_relative_path cache/objects/sha256/5fb1d564d9cbe0064310e1a2123bfaa0782d7010c2545c38383020cf353321ca
  expect_lock_value "$label" builder_tree_manifest_path locks/builder-tree.manifest
  expect_lock_value "$label" builder_tree_manifest_sha256 8a481d1bc3e2dc5fcc47ae0783f61d6c9a9ec67f52d57e262885bfa810065114
  expect_lock_value "$label" builder_archive_owner_policy invoking-uid-or-root
  expect_lock_value "$label" builder_archive_permissions_policy not-group-or-world-writable
  expect_lock_value "$label" builder_archive_link_policy exactly-one
  expect_lock_value "$label" builder_archive_validation_policy complete-before-extraction
  expect_lock_value "$label" builder_evidence_runtime_role audit-traceability-not-runtime-input
  expect_lock_value "$label" release_tag_type lightweight
  expect_lock_value "$label" release_tag_signature_status unsigned
  expect_lock_value "$label" commit_signature_status valid-under-unapproved-github-service-key
  expect_lock_value "$label" commit_signer_fingerprint 968479A1AFF927E37D1A566BB5690EEEBB952194
  expect_lock_value "$label" commit_signer_key_ownership_status github-service-key-not-independently-approved
  expect_lock_value "$label" release_to_commit_binding same-channel-lightweight-tag-direct-target-plus-valid-github-service-key-signed-commit
  expect_lock_value "$label" release_authentication operationally-approved-by-human-risk-acceptance
  expect_lock_value "$label" release_authentication_basis pinned-commit-and-tree-plus-verified-github-web-flow-signature-plus-release-tag-corroboration
  expect_lock_value "$label" release_authentication_residual_risk github-service-key-and-unsigned-mutable-lightweight-tag-without-independent-release-signature
  expect_lock_value "$label" source_archive_acquisition_report_sha256 65d77e7370079c723be82dbf6c803e5ea91fd1a0a4367f30c773e3a099e27c6b
  expect_lock_value "$label" builder_key_acquisition_report_sha256 35e41aaa650566c485d9e5edf45707ceec7c7ec14ca257d35763b02ffc169151
  expect_lock_value "$label" builder_key_request_log_sha256 512ce4a5de10b087a3f2f367905b5fa98cfd11908c149465bf77c6b36aeb16d9
  expect_lock_value "$label" builder_key_response_digests_sha256 815335d08fd5f115a283e94ac1c74cf56b29b1cb1a5fd4d9a92de9eb1605f597
  expect_lock_value "$label" builder_key_response_headers_sha256 9b8d53e30707524c26177cd4d080b319bf49b47e17e22e67c742fbaba917ffc6
  expect_lock_value "$label" builder_key_artifacts_sha256 a8decc4eaddb82a94322f3f901413713f221e6af2aa431dfa9fed093ea6de78a
  expect_lock_value "$label" builder_key_validation_sha256 ce122f491d1b83f7da96e943c4dc1c6b410de7969e2adc8c7b1b4dd5689cca59
  expect_lock_value "$label" future_mismatch_policy fail-closed
  expect_lock_value "$label" protected_omega_source_commit 4eeafcf1caffc4223055e32b33bc83067d72e20e
  expect_lock_value "$label" protected_content_policy anchor-tree-identity-plus-authorized-readme-commit
  expect_lock_value "$label" authorized_readme_commit 5179f3595f0b9e1c61417ee76d660fb05c7f102b
  expect_lock_value "$label" authorized_readme_parent_commit 4eeafcf1caffc4223055e32b33bc83067d72e20e
  expect_lock_value "$label" authorized_readme_blob 485c72eec8ef40c158d5fb259e4ae68dd04efdff
  expect_lock_value "$label" current_source_commit_policy derive-clean-head-at-preflight
  expect_lock_value "$label" config_compatibility verified-local-plan
  expect_lock_value "$label" builder_config_engine bin/ig
  expect_lock_value "$label" builder_config_execution_scope authenticated-config-metadata-and-pipeline-only
  expect_lock_value "$label" builder_config_network_isolation enforced-user-and-network-namespace
  expect_lock_value "$label" builder_config_plan_entry_count 34
  expect_lock_value "$label" builder_config_plan_sha256 c3f8efcccbed085eb6c38334e19568389e730641eb25bcca81a4dfd93cba796f
  expect_lock_value "$label" target_hardware raspberry-pi-5-8gb
  expect_lock_value "$label" target_os raspberry-pi-os-lite-64
  expect_lock_value "$label" target_suite trixie
  expect_lock_value "$label" target_debian_major 13
  expect_lock_value "$label" target_architecture arm64
  expect_lock_value "$label" storage_target high-endurance-microsd-128gb
  expect_lock_value "$label" image_geometry_bytes 34359738368
  expect_lock_value "$label" geometry_slack_bytes 536870912
  expect_lock_value "$label" partition_layout boot-fat32,root-ext4
  expect_lock_value "$label" output_format sparse-raw-img-xz
  expect_lock_value "$label" filesystem_expansion phase-5
  expect_lock_value "$label" secure_boot_otp phase-5
  expect_lock_value "$label" device_bound_encryption phase-5
  expect_lock_value "$label" timezone UTC
  expect_lock_value "$label" locale C.UTF-8
  expect_lock_value "$label" umask 0022
  expect_lock_value "$label" source_date_epoch 1787801458
  expect_lock_value "$label" network_policy declared-content-inputs-only
  expect_lock_value "$label" network_isolation enforced-by-build-wrapper-user-and-network-namespace
  expect_lock_value "$label" network_isolation_entrypoint scripts/network-namespace-exec.py
  expect_lock_value "$label" network_isolation_runtime_check separate-netns-loopback-only-no-ipv4-route

  local manifest_path manifest_digest
  manifest_path="$CANONICAL_IMAGE_ROOT/${LOCK_VALUES[builder_tree_manifest_path]}"
  require_regular_file 'builder tree manifest' "$manifest_path" 'locks/builder-tree.manifest'
  manifest_digest=$($SHA256SUM_TOOL -- "$manifest_path") || die 'BUILDER_TREE_MANIFEST_HASH_FAILED=YES'
  manifest_digest=${manifest_digest%% *}
  [ "$manifest_digest" = "${LOCK_VALUES[builder_tree_manifest_sha256]}" ] ||
    die "BUILDER_TREE_MANIFEST_SHA256_MISMATCH=$manifest_digest"

  size_to_bytes "$CONFIG_BOOT_PART_SIZE"
  boot_bytes=$SIZE_BYTES
  size_to_bytes "$CONFIG_ROOT_PART_SIZE"
  root_bytes=$SIZE_BYTES
  geometry=${LOCK_VALUES[image_geometry_bytes]}
  slack=${LOCK_VALUES[geometry_slack_bytes]}
  [ "$((boot_bytes + root_bytes + slack))" -eq "$geometry" ] ||
    die 'STATIC_GEOMETRY_MISMATCH=YES'

  BUILDER_RELEASE_AUTHENTICATION=${LOCK_VALUES[release_authentication]}
  BUILDER_CONFIG_COMPATIBILITY=${LOCK_VALUES[config_compatibility]}
  NETWORK_ISOLATION=${LOCK_VALUES[network_isolation]}
}

validate_apt_lock() {
  local path=$1 label='APT sources lock' manifest_path manifest_digest
  load_flat_lock "$label" apt-sources-lock "$path" 'locks/apt-sources.lock'
  require_lock_schema "$label" \
    schema status architecture snapshot_cutoff_utc metadata_manifest_path \
    metadata_manifest_sha256 metadata_signature_validation metadata_to_package_validation \
    debian_types debian_uri \
    debian_suites debian_components debian_signed_by debian_check_valid_until \
    debian_archive_key_fingerprint debian_release_key_fingerprint \
    debian_security_types debian_security_uri debian_security_suites \
    debian_security_components debian_security_signed_by \
    debian_security_check_valid_until debian_security_key_fingerprint \
    raspberrypi_types raspberrypi_uri raspberrypi_suite raspberrypi_components \
    raspberrypi_signed_by raspberrypi_checkpoint_mode raspberrypi_checkpoint_utc \
    raspberrypi_inrelease_sha256 raspberrypi_packages_arm64_sha256 \
    raspberrypi_approved_signer_fingerprint raspberrypi_key_ownership_status \
    raspberrypi_repository_trust raspberrypi_keyring_sha256 raspberrypi_trust_basis \
    raspberrypi_residual_risk raspberrypi_future_mismatch_policy \
    wazuh_types wazuh_uri wazuh_suite_checkpoint wazuh_components wazuh_key_url \
    wazuh_key_sha256 wazuh_signer_fingerprint wazuh_inrelease_sha256 \
    wazuh_packages_arm64_sha256 wazuh_repository_trust tailscale_types tailscale_uri \
    tailscale_suite tailscale_components tailscale_key_url tailscale_key_sha256 \
    tailscale_signer_fingerprint tailscale_inrelease_sha256 tailscale_packages_all_sha256 \
    tailscale_packages_arm64_sha256 tailscale_repository_trust construction_repository_mode \
    external_repositories_in_image unattended_upgrades third_party_repositories
  expect_lock_value "$label" schema omega-apt-sources-lock-v3
  expect_lock_value "$label" status resolved
  expect_lock_value "$label" architecture arm64
  expect_lock_value "$label" snapshot_cutoff_utc 2026-08-26T15:31:34Z
  expect_lock_value "$label" metadata_manifest_path locks/apt-metadata.manifest
  expect_lock_value "$label" metadata_manifest_sha256 8ce3117c7f342a69f7fcb7f8fa4221a9b2a93487fe9dfc84f7bad497676a3943
  expect_lock_value "$label" metadata_signature_validation six-inrelease-files-verified-against-locked-signers
  expect_lock_value "$label" metadata_to_package_validation signed-inrelease-sha256-to-index-sha256-to-deb-sha256
  expect_lock_value "$label" debian_types deb
  expect_lock_value "$label" debian_uri https://snapshot.debian.org/archive/debian/20260826T153134Z/
  expect_lock_value "$label" debian_suites trixie,trixie-updates
  expect_lock_value "$label" debian_components main,contrib,non-free,non-free-firmware
  expect_lock_value "$label" debian_signed_by /usr/share/keyrings/debian-archive-keyring.pgp
  expect_lock_value "$label" debian_check_valid_until disabled
  expect_lock_value "$label" debian_archive_key_fingerprint 04B54C3CDCA79751B16BC6B5225629DF75B188BD
  expect_lock_value "$label" debian_release_key_fingerprint 41587F7DB8C774BCCF131416762F67A0B2C39DE4
  expect_lock_value "$label" debian_security_types deb
  expect_lock_value "$label" debian_security_uri https://snapshot.debian.org/archive/debian-security/20260826T153134Z/
  expect_lock_value "$label" debian_security_suites trixie-security
  expect_lock_value "$label" debian_security_components main,contrib,non-free,non-free-firmware
  expect_lock_value "$label" debian_security_signed_by /usr/share/keyrings/debian-archive-keyring.pgp
  expect_lock_value "$label" debian_security_check_valid_until disabled
  expect_lock_value "$label" debian_security_key_fingerprint 5E04A1E3223A19A20706E20F9904613D4CCE68C6
  expect_lock_value "$label" raspberrypi_types deb
  expect_lock_value "$label" raspberrypi_uri https://archive.raspberrypi.com/debian
  expect_lock_value "$label" raspberrypi_suite trixie
  expect_lock_value "$label" raspberrypi_components main
  expect_lock_value "$label" raspberrypi_signed_by /usr/share/keyrings/raspberrypi-archive-keyring.pgp
  expect_lock_value "$label" raspberrypi_checkpoint_mode verified-inrelease-and-package-index-sha256
  expect_lock_value "$label" raspberrypi_checkpoint_utc 2026-09-07T16:33:24Z
  expect_lock_value "$label" raspberrypi_inrelease_sha256 75801a69a90ea610d1fd5a69229f7400a35c5ffb67dcdcf9fe933b801214a46b
  expect_lock_value "$label" raspberrypi_packages_arm64_sha256 ec31d7b83dfc1bd5709df588d48ce7d684e7ac212db5501f5aa92a30c16bdfb0
  expect_lock_value "$label" raspberrypi_approved_signer_fingerprint CF8A1AF502A2AA2D763BAE7E82B129927FA3303E
  expect_lock_value "$label" raspberrypi_key_ownership_status operationally-corroborated-not-independently-proven
  expect_lock_value "$label" raspberrypi_repository_trust operationally-approved-by-human-risk-acceptance
  expect_lock_value "$label" raspberrypi_keyring_sha256 3a29901549ae65a910de13a32551e6eea7f45ba1fd70f0cb67e5c70d98488071
  expect_lock_value "$label" raspberrypi_trust_basis official-archive-https-key-plus-matching-pi-gen-key-material-plus-valid-locked-inrelease
  expect_lock_value "$label" raspberrypi_residual_risk dependence-on-raspberry-pi-control-of-archive-endpoint-and-github-account-without-out-of-band-fingerprint-publication
  expect_lock_value "$label" raspberrypi_future_mismatch_policy fail-closed
  expect_lock_value "$label" wazuh_types deb
  expect_lock_value "$label" wazuh_uri https://packages.wazuh.com/4.x/apt
  expect_lock_value "$label" wazuh_suite_checkpoint 'stable@3c49bb0ee8d988d779b139b4b71020a2a2a6adcd3533ca7329b66bfe6ada0ff9'
  expect_lock_value "$label" wazuh_components main
  expect_lock_value "$label" wazuh_key_url https://packages.wazuh.com/key/GPG-KEY-WAZUH
  expect_lock_value "$label" wazuh_key_sha256 a378ca8dfa6b72122df288f64a0cde54f1cbfa3db9b43e6865cb73def35b5b17
  expect_lock_value "$label" wazuh_signer_fingerprint 0DCFCA5547B19D2A6099506096B3EE5F29111145
  expect_lock_value "$label" wazuh_inrelease_sha256 3c49bb0ee8d988d779b139b4b71020a2a2a6adcd3533ca7329b66bfe6ada0ff9
  expect_lock_value "$label" wazuh_packages_arm64_sha256 bcec2db5549415530456daf1aab56becd47d80d2ba172ca3fbbf1f944550e887
  expect_lock_value "$label" wazuh_repository_trust operationally-approved-by-exact-key-and-signed-metadata
  expect_lock_value "$label" tailscale_types deb
  expect_lock_value "$label" tailscale_uri https://pkgs.tailscale.com/stable/debian
  expect_lock_value "$label" tailscale_suite trixie
  expect_lock_value "$label" tailscale_components main
  expect_lock_value "$label" tailscale_key_url https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg
  expect_lock_value "$label" tailscale_key_sha256 3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39
  expect_lock_value "$label" tailscale_signer_fingerprint 2596A99EAAB33821893C0A79458CA832957F5868
  expect_lock_value "$label" tailscale_inrelease_sha256 08b3e6979c3ef7fbe18d81f4ed25a3a510ccc57c1e6c0cbc604e1b7e95d16335
  expect_lock_value "$label" tailscale_packages_all_sha256 07041713dfc26634d272be2cd51b5120dc38d497e9f1dea2aa2e72eb16d55f7d
  expect_lock_value "$label" tailscale_packages_arm64_sha256 5c7e23c86dfc229cc42125de5ae1b52dbb6e7c633e19f2ca9fd3013fe1edb8c7
  expect_lock_value "$label" tailscale_repository_trust operationally-approved-by-exact-key-and-signed-metadata
  expect_lock_value "$label" construction_repository_mode generated-content-verified-file-uri-only
  expect_lock_value "$label" external_repositories_in_image absent
  expect_lock_value "$label" unattended_upgrades disabled
  expect_lock_value "$label" third_party_repositories wazuh-and-tailscale-exact-signed-checkpoints-approved
  manifest_path="$CANONICAL_IMAGE_ROOT/${LOCK_VALUES[metadata_manifest_path]}"
  require_regular_file 'APT metadata manifest' "$manifest_path" 'locks/apt-metadata.manifest'
  manifest_digest=$($SHA256SUM_TOOL -- "$manifest_path") || die 'APT_METADATA_MANIFEST_HASH_FAILED=YES'
  manifest_digest=${manifest_digest%% *}
  [ "$manifest_digest" = "${LOCK_VALUES[metadata_manifest_sha256]}" ] ||
    die "APT_METADATA_MANIFEST_SHA256_MISMATCH=$manifest_digest"
  RASPBERRYPI_REPOSITORY_TRUST=${LOCK_VALUES[raspberrypi_repository_trust]}
}

validate_packages_lock() {
  local path=$1 label='packages lock' manifest_path manifest_digest
  load_flat_lock "$label" packages-lock "$path" 'locks/packages.lock'
  require_lock_schema "$label" \
    schema status architecture service_scope version_policy installer_policy \
    package_manifest_path package_manifest_sha256 package_count cache_object_path_policy \
    package_owner_policy package_permissions_policy package_link_policy \
    package_archive_validation offline_repository_suite offline_repository_component \
    offline_repository_trust offline_packages_index_sha256 offline_packages_index_bytes \
    offline_release_sha256 offline_release_bytes \
    suricata_package docker_packages wazuh_agent_package \
    tailscale_package pihole_delivery evebox_delivery
  expect_lock_value "$label" schema omega-packages-lock-v2
  expect_lock_value "$label" status resolved
  expect_lock_value "$label" architecture arm64
  expect_lock_value "$label" service_scope pihole,suricata,docker,evebox,wazuh-agent,tailscale
  expect_lock_value "$label" version_policy exact-versions-only
  expect_lock_value "$label" installer_policy verified-content-addressed-deb-only
  expect_lock_value "$label" package_manifest_path locks/packages.manifest
  expect_lock_value "$label" package_manifest_sha256 947445b8d7aecc5b075046828db5b5665ac78371a41a8945616dbccc9c596be5
  expect_lock_value "$label" package_count 313
  expect_lock_value "$label" cache_object_path_policy 'cache/objects/sha256/<lowercase-sha256>'
  expect_lock_value "$label" package_owner_policy invoking-uid-or-root
  expect_lock_value "$label" package_permissions_policy not-group-or-world-writable
  expect_lock_value "$label" package_link_policy exactly-one
  expect_lock_value "$label" package_archive_validation sha256-size-control-fields-and-debian-ar-format
  expect_lock_value "$label" offline_repository_suite omega
  expect_lock_value "$label" offline_repository_component main
  expect_lock_value "$label" offline_repository_trust manifest-verified-local-content-only
  expect_lock_value "$label" offline_packages_index_sha256 195b39e0d30658ebd4663cc23764edaee07056fd6eef7748eaa218af88cd9d12
  expect_lock_value "$label" offline_packages_index_bytes 334587
  expect_lock_value "$label" offline_release_sha256 d751dd2b9a473d0d0ea0e95e6a7fcee22d13487fae087c9c575f1d9133398a7c
  expect_lock_value "$label" offline_release_bytes 246
  expect_lock_value "$label" suricata_package 'suricata=1:7.0.10-1+deb13u4'
  expect_lock_value "$label" docker_packages 'docker.io=26.1.5+dfsg1-9+deb13u1,docker-cli=26.1.5+dfsg1-9+deb13u1,containerd=1.7.24~ds1-6+deb13u1,runc=1.1.15+ds1-2+b4,tini=0.19.0-3+b7'
  expect_lock_value "$label" wazuh_agent_package 'wazuh-agent=4.14.7-1'
  expect_lock_value "$label" tailscale_package 'tailscale=1.102.3'
  expect_lock_value "$label" pihole_delivery oci-image
  expect_lock_value "$label" evebox_delivery oci-image
  manifest_path="$CANONICAL_IMAGE_ROOT/${LOCK_VALUES[package_manifest_path]}"
  require_regular_file 'package manifest' "$manifest_path" 'locks/packages.manifest'
  manifest_digest=$($SHA256SUM_TOOL -- "$manifest_path") || die 'PACKAGE_MANIFEST_HASH_FAILED=YES'
  manifest_digest=${manifest_digest%% *}
  [ "$manifest_digest" = "${LOCK_VALUES[package_manifest_sha256]}" ] ||
    die "PACKAGE_MANIFEST_SHA256_MISMATCH=$manifest_digest"
  PACKAGE_LOCK_STATUS=${LOCK_VALUES[status]}
}

validate_oci_lock() {
  local path=$1 label='OCI images lock' manifest_path manifest_digest
  load_flat_lock "$label" oci-images-lock "$path" 'locks/oci-images.lock'
  require_lock_schema "$label" \
    schema status architecture service_scope reference_policy floating_tags \
    network_at_construction image_manifest_path image_manifest_sha256 image_count \
    object_count cache_object_path_policy object_owner_policy object_permissions_policy \
    object_link_policy object_validation offline_import_format offline_archive_sha256 \
    offline_archive_bytes pihole_reference \
    pihole_index_sha256 pihole_release_label pihole_release_label_role \
    pihole_source_revision pihole_ftl_version pihole_packaging_owner evebox_reference \
    evebox_index_sha256 evebox_release_label evebox_release_label_role \
    evebox_packaging_owner
  expect_lock_value "$label" schema omega-oci-images-lock-v2
  expect_lock_value "$label" status resolved
  expect_lock_value "$label" architecture arm64
  expect_lock_value "$label" service_scope pihole,evebox
  expect_lock_value "$label" reference_policy digest-only
  expect_lock_value "$label" floating_tags forbidden
  expect_lock_value "$label" network_at_construction forbidden
  expect_lock_value "$label" image_manifest_path locks/oci-images.manifest
  expect_lock_value "$label" image_manifest_sha256 32760a9e0dd793ea72166728a9fd20d24ce4ee552c9d4a35c3aafdcbee50bff4
  expect_lock_value "$label" image_count 2
  expect_lock_value "$label" object_count 22
  expect_lock_value "$label" cache_object_path_policy 'cache/objects/sha256/<lowercase-sha256>'
  expect_lock_value "$label" object_owner_policy invoking-uid-or-root
  expect_lock_value "$label" object_permissions_policy not-group-or-world-writable
  expect_lock_value "$label" object_link_policy exactly-one
  expect_lock_value "$label" object_validation index-manifest-config-layer-size-sha256-and-rootfs-diffid
  expect_lock_value "$label" offline_import_format deterministic-docker-archive
  expect_lock_value "$label" offline_archive_sha256 6aaeb43b5db42febd12b099286d95cf00c2796068bace351b097cb0a8aebcd60
  expect_lock_value "$label" offline_archive_bytes 244305920
  expect_lock_value "$label" pihole_reference 'docker.io/pihole/pihole@sha256:a29ad980775f38a8e7524a206ff9c125bc6fcfd9de8de1fc93d2de0671cc1d34'
  expect_lock_value "$label" pihole_index_sha256 f7d1be836e3bc608b56d82fc9904f5a831cdfbc0dc9c6d58f94e4c985c70038b
  expect_lock_value "$label" pihole_release_label 2026.07.2
  expect_lock_value "$label" pihole_release_label_role informational-only
  expect_lock_value "$label" pihole_source_revision dd91b4847d97f0aac68bfefd1c108ed0627e6c68
  expect_lock_value "$label" pihole_ftl_version v6.7
  expect_lock_value "$label" pihole_packaging_owner official-pihole-image
  expect_lock_value "$label" evebox_reference 'docker.io/jasonish/evebox@sha256:7ca9aab505eb0239cc3987a4cb30ff5864585d3856d1b3f0a66dbfb442ad987d'
  expect_lock_value "$label" evebox_index_sha256 216ef6eb5bfcc1d8d9b13a41ba38eb067060e68c3970fa4579d07c8f5d5a9326
  expect_lock_value "$label" evebox_release_label 0.28.0
  expect_lock_value "$label" evebox_release_label_role informational-only
  expect_lock_value "$label" evebox_packaging_owner upstream-evebox-image
  manifest_path="$CANONICAL_IMAGE_ROOT/${LOCK_VALUES[image_manifest_path]}"
  require_regular_file 'OCI image manifest' "$manifest_path" 'locks/oci-images.manifest'
  manifest_digest=$($SHA256SUM_TOOL -- "$manifest_path") || die 'OCI_MANIFEST_HASH_FAILED=YES'
  manifest_digest=${manifest_digest%% *}
  [ "$manifest_digest" = "${LOCK_VALUES[image_manifest_sha256]}" ] ||
    die "OCI_MANIFEST_SHA256_MISMATCH=$manifest_digest"
  OCI_LOCK_STATUS=${LOCK_VALUES[status]}
}

validate_overlay_membership() (
  local relative path directory
  local -A expected=()
  local -a pending=(rootfs-overlay) entries=()
  for relative in "$@"; do
    expected["$relative"]=1
  done
  # Include dotfiles and never follow directory symlinks. A manifest protects
  # only its named files unless the copied overlay is also closed to extras.
  shopt -s dotglob nullglob
  while [ "${#pending[@]}" -gt 0 ]; do
    directory=${pending[0]}
    pending=("${pending[@]:1}")
    path="$CANONICAL_IMAGE_ROOT/$directory"
    [ ! -L "$path" ] && [ -d "$path" ] && [ -r "$path" ] && [ -x "$path" ] ||
      die "OVERLAY_DIRECTORY_INVALID=$directory"
    entries=("$path"/*)
    for path in "${entries[@]}"; do
      relative=${path#"$CANONICAL_IMAGE_ROOT/"}
      [ ! -L "$path" ] || die "OVERLAY_SYMLINK_REJECTED=$relative"
      if [ -d "$path" ]; then
        pending+=("$relative")
      elif [ -f "$path" ]; then
        [ -n "${expected["$relative"]+present}" ] ||
          die "OVERLAY_UNLISTED_ENTRY=$relative"
      else
        die "OVERLAY_NONREGULAR_ENTRY=$relative"
      fi
    done
  done
)

validate_payload_manifest() {
  local manifest="$CANONICAL_IMAGE_ROOT/locks/payload.manifest"
  local manifest_digest expected_mode expected_digest relative extra path actual_mode actual_digest
  local line_number=0 entry_count=0
  local -a overlay_files=()
  require_regular_file 'payload manifest' "$manifest" 'locks/payload.manifest'
  manifest_digest=$($SHA256SUM_TOOL -- "$manifest") || die 'PAYLOAD_MANIFEST_HASH_FAILED=YES'
  manifest_digest=${manifest_digest%% *}
  [ "$manifest_digest" = 26a399c3021405213f91b317b942d9381ad491c195542f9edd561e4702e06da3 ] ||
    die "PAYLOAD_MANIFEST_SHA256_MISMATCH=$manifest_digest"
  while IFS=$'\t' read -r expected_mode expected_digest relative extra; do
    line_number=$((line_number + 1))
    case "$line_number" in
      1) [ "$expected_mode" = omega-image-payload-manifest-v1 ] && [ -z "$expected_digest$relative$extra" ] || die 'PAYLOAD_MANIFEST_HEADER_INVALID=YES' ;;
      2) [ "$expected_mode" = entry_count ] && [ "$expected_digest" = 34 ] && [ -z "$relative$extra" ] || die 'PAYLOAD_MANIFEST_COUNT_HEADER_INVALID=YES' ;;
      3) [ "$expected_mode" = columns ] && [ "$expected_digest" = mode ] && [ "$relative" = sha256 ] && [ "$extra" = path ] || die 'PAYLOAD_MANIFEST_COLUMNS_INVALID=YES' ;;
      *)
        [[ "$expected_mode" =~ ^0(644|755)$ ]] || die "PAYLOAD_MODE_INVALID_LINE=$line_number"
        [[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || die "PAYLOAD_SHA256_INVALID_LINE=$line_number"
        [[ "$relative" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$relative" != /* ]] && [[ "$relative" != *'..'* ]] && [ -z "$extra" ] ||
          die "PAYLOAD_PATH_INVALID_LINE=$line_number"
        path="$CANONICAL_IMAGE_ROOT/$relative"
        require_regular_file 'payload entry' "$path" "$relative"
        actual_mode=$($STAT_TOOL -c %a -- "$path") || die "PAYLOAD_MODE_UNREADABLE=$relative"
        [ "0$actual_mode" = "$expected_mode" ] || die "PAYLOAD_MODE_MISMATCH=$relative"
        actual_digest=$($SHA256SUM_TOOL -- "$path") || die "PAYLOAD_HASH_FAILED=$relative"
        actual_digest=${actual_digest%% *}
        [ "$actual_digest" = "$expected_digest" ] || die "PAYLOAD_SHA256_MISMATCH=$relative"
        if [[ "$relative" = rootfs-overlay/* ]]; then
          overlay_files+=("$relative")
        fi
        entry_count=$((entry_count + 1))
        ;;
    esac
  done < "$manifest"
  [ "$line_number" -eq 37 ] && [ "$entry_count" -eq 34 ] || die 'PAYLOAD_MANIFEST_ENTRY_COUNT_MISMATCH=YES'
  validate_overlay_membership "${overlay_files[@]}"
  printf 'IMAGE_PAYLOAD_VALID=YES\n'
}

validate_architecture() {
  local architecture=$1
  case "$architecture" in
    arm64|aarch64) return 0 ;;
    *) die "unsupported build architecture: $architecture; expected native arm64" ;;
  esac
}

print_foundation_status() {
  printf 'BUILDER_FOUNDATION_VALID=YES\n'
  printf 'STATIC_GEOMETRY_VALID=YES\n'
  printf 'BUILDER_RELEASE_AUTHENTICATION=%s\n' "${BUILDER_RELEASE_AUTHENTICATION^^}"
  printf 'RASPBERRYPI_REPOSITORY_TRUST=%s\n' "${RASPBERRYPI_REPOSITORY_TRUST^^}"
  printf 'BUILDER_CONFIG_COMPATIBILITY=%s\n' "${BUILDER_CONFIG_COMPATIBILITY^^}"
  printf 'NETWORK_ISOLATION=%s\n' "${NETWORK_ISOLATION^^}"
  printf 'SERVICE_PACKAGE_LOCK=%s\n' "${PACKAGE_LOCK_STATUS^^}"
  printf 'OCI_IMAGE_LOCK=%s\n' "${OCI_LOCK_STATUS^^}"
  printf 'BUILD_READINESS=READY\n'
}

IMAGE_ROOT=$DEFAULT_IMAGE_ROOT
REQUIRE_SERVICE_LOCKS=false
REQUIRE_BUILD_READINESS=false
ARCHITECTURE_ONLY=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image-root)
      [ "$#" -ge 2 ] || die 'IMAGE_ROOT_ARGUMENT_MISSING=YES'
      IMAGE_ROOT=$2
      shift 2
      ;;
    --require-service-locks)
      REQUIRE_SERVICE_LOCKS=true
      shift
      ;;
    --require-build-readiness)
      REQUIRE_BUILD_READINESS=true
      shift
      ;;
    --check-architecture)
      [ "$#" -ge 2 ] || die 'ARCHITECTURE_ARGUMENT_MISSING=YES'
      ARCHITECTURE_ONLY=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "UNKNOWN_ARGUMENT=$1" ;;
  esac
done

if [ -n "$ARCHITECTURE_ONLY" ]; then
  [ "$IMAGE_ROOT" = "$DEFAULT_IMAGE_ROOT" ] || die 'ARCHITECTURE_IMAGE_ROOT_CONFLICT=YES'
  [ "$REQUIRE_SERVICE_LOCKS" = false ] || die 'ARCHITECTURE_SERVICE_LOCK_CONFLICT=YES'
  [ "$REQUIRE_BUILD_READINESS" = false ] || die 'ARCHITECTURE_READINESS_CONFLICT=YES'
  validate_architecture "$ARCHITECTURE_ONLY"
  printf 'ARCHITECTURE_VALID=%s\n' "$ARCHITECTURE_ONLY"
  exit 0
fi

case "$IMAGE_ROOT" in
  /*) ;;
  *) die 'IMAGE_ROOT_NOT_ABSOLUTE=YES' ;;
esac
[ -d "$IMAGE_ROOT" ] || die "IMAGE_ROOT_DIRECTORY_INVALID=$IMAGE_ROOT"
[ ! -L "$IMAGE_ROOT" ] || die "IMAGE_ROOT_SYMLINK_REJECTED=$IMAGE_ROOT"
CANONICAL_IMAGE_ROOT=$($READLINK_TOOL -f -- "$IMAGE_ROOT") || die 'IMAGE_ROOT_RESOLUTION_FAILED=YES'
[ "$CANONICAL_IMAGE_ROOT" = "$IMAGE_ROOT" ] || die 'IMAGE_ROOT_NOT_CANONICAL=YES'

validate_config "$IMAGE_ROOT/config/omega-rpi5-trixie-arm64.yaml"
validate_builder_lock "$IMAGE_ROOT/locks/builder.lock"
validate_apt_lock "$IMAGE_ROOT/locks/apt-sources.lock"
validate_packages_lock "$IMAGE_ROOT/locks/packages.lock"
validate_oci_lock "$IMAGE_ROOT/locks/oci-images.lock"
validate_payload_manifest
print_foundation_status

if [ "$REQUIRE_SERVICE_LOCKS" = true ]; then
  printf 'SERVICE_LOCKS=RESOLVED\n'
fi

if [ "$REQUIRE_BUILD_READINESS" = true ]; then
  printf 'BUILD_READINESS_CHECK=PASS\n'
fi
