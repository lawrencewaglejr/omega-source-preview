# Deferred appliance release preparation and acceptance requirements

The 0.1.0-preview.1 [source preview](source-preview.md) is experimental and source-only.
This document covers deferred appliance-image acceptance, not prerequisites that
claim a spare card has already been tested.

This is a development preview. A software test pass does not establish that an
ARM64 image builds, boots, recovers safely, or is ready to publish.

## Installation scope

The protected [CLI installation guide](install.md) installs nine inspection
commands. `install.sh --dry-run` previews that installation; it does not build or
flash an image, provision networks, enroll agents, or start appliance services.
Use a disposable `--destdir` for installation lifecycle tests. Do not run an
installer against the host root as part of release assessment.

A complete appliance uses the [master-image build](../image/README.md) followed
by [first setup](dashboard-first-boot.md) and the restricted
[manager connection](wazuh-manager-setup.md). New device identity, credentials,
network and capture configuration, and explicit service activation are separate
operator steps. No deployment credentials or telemetry belong in a source release.

## Application storage and background readers

Completed gzip expansion caches may be released only after a completion marker
and a committed EOF cursor agree, with no partial record or dropping state and
with the same source version. Preserve the original gzip and all retained source
records. Durable consumed-version markers prevent repeat expansion on restart;
a changed archive version must be reconsidered. Incomplete or actively expanding
caches remain. This is application cache lifecycle behavior, not authorization to
run manual cleanup on an existing installation.

Background correlation starts only after the collector reports catch-up. It
must yield to explicit reports or shutdown and close its SQLite iterator on
success, cancellation, or failure. Regression tests must hold a reader reference
and demonstrate that a real synthetic WAL checkpoint is blocked during a read
and succeeds after cleanup, without changing any live database.

## Isolated software validation

Export only the reviewed source tree to a new private temporary directory; do
not import private Git history or an appliance filesystem. Apply the reviewed
patch there first. Bind only that workspace and system runtime into a disposable
sandbox with a private network namespace, empty home and temporary directories,
and no host service sockets, credentials, evidence, or backups. If the namespace
boundary cannot be established, report the tests as blocked and use a supported
disposable test host; do not bypass the boundary or weaken host security policy.

Run telemetry-store, dashboard, report-jobs, devices, and correlation tests;
both browser logic suites; and dashboard payload staging tests. Check completed
cache removal, original-record retention, restart deduplication, changed archive
versions, interrupted cleanup recovery, and preservation of partial records.
Exercise correlation catch-up gating and real database reader cleanup for every
exit path. Use new synthetic databases, never copied operational evidence.

Verify application and nested payload inventories against their actual bytes.
The dashboard inventory has eleven files. Changed inventory entries must name
only reviewed content and retain all unaffected entries. Do not alter protected
source anchors, approved exceptions, upstream hashes, or lock validation rules to
make a failing check pass. Full source-trust preflight requires a clean reviewed
Git revision; an intentionally uncommitted candidate cannot satisfy that gate.

The current application port leaves shipping inventories and verification pins
unchanged. Their expected byte mismatch blocks image staging until a separate
content-inventory review, including the verifier's hard-coded root inventory
digest. Keep this gate visible; do not report an image validation pass or weaken
the verifier to accommodate an unreviewed content change.

## Remaining release gates

1. Reverify the authenticated pinned builder source, exact configuration plan,
   package and service caches using the documented offline checks. A cached input
   verification pass is distinct from an actual native build. Preserve all trust
   enforcement and strict service-lock checks.
2. Use a native ARM64 Debian 13 builder with required tools, subordinate UID/GID
   ranges, functioning user/mount/network namespaces, and enough disk for the
   verified input cache, full build intermediates, and a new output directory.
   Check space before building. Construction must have only loopback and no
   external route. A host that cannot establish this isolation is unsuitable.
3. Build the reviewed clean revision to a previously nonexistent output directory.
   Verify image, checksums, SPDX, provenance, exact payloads, first-device import,
   absence of credentials/host identity/logs, and disabled pre-provisioning services.
   Repeat the build independently and investigate any byte or filesystem variance;
   do not describe content similarity as full reproducibility.
4. Fresh-card boot testing is deferred until spare media is available. Then use
   separately approved spare media, keeping the original card and backups intact.
   Verify boot, documented first setup, source permissions including WAL/SHM,
   real fresh events from every configured source, storage behavior, service
   restart recovery, and operation with WAN access absent. Do not substitute demo
   events or a running process for successful real collection.
5. Document and rehearse recovery on disposable media: retain the original boot
   medium and verified private backups, prove private configuration and evidence
   can be recovered, verify escalations and saved cursor continuity, and describe
   rollback and upgrade compatibility. Never ship recovery evidence in source or
   release artifacts. Record recovery time and failure cases before acceptance.
6. Select and verify the release-signing identity through a separate controlled
   process. Keep the private key outside the repository, image, and build cache;
   sign the final checksums only after acceptance and independently verify the
   detached signature and published fingerprint. Do not invent a trusted key or
   claim signing is complete because checksums exist.
7. Review the complete publication tree, every Git ref and historical blob, commit
   identities/messages, examples, URLs, screenshots, and generated artifacts for
   credentials and private operational data. Print findings by location and rule,
   never secret values. Review synthetic fixture matches explicitly. No scan can
   prove absence of every private identifier. OMEGA source is licensed under the
   [Apache License 2.0](../LICENSE), unless otherwise noted, with copyright
   attribution in [NOTICE](../NOTICE). Verify publication rights and preserve
   third-party licenses and notices before release; the project license does not
   relicense third-party components.

Record actual validation results separately from this acceptance checklist.
Committing, configuring a remote, pushing, signing, flashing, and publishing each
remain separate controlled release actions.
