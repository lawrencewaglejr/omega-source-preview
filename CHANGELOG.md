# Ω Omega Changelog

## Unreleased — Phase 3 runtime input hardening

### Changed

- Added a strict, non-executable optional `/etc/omega/omega.conf` contract consumed consistently by the four Suricata commands.
- Replaced privileged Suricata parsing with direct unprivileged reads from validated regular-file descriptors.
- Added pathname replacement/disappearance detection while permitting normal same-inode append.
- Expanded `omega-doctor` to verify all nine installed OMEGA commands and the new runtime input contract.
- Added isolated configuration, byte-safety, object-type, rotation, append, report-publication, command-layer, and result-precedence regression coverage.

## Phase 2 — installer lifecycle

### Changed

- Made top-level `install.sh` the canonical nine-command install and uninstall entry point.
- Added a manifest and checksummed current-state receipt as lifecycle sources of truth.
- Added dry-run and isolated `--destdir` operation, strict path and collision refusal, recognized legacy migration, frozen locked snapshots, lifecycle locking, private per-filesystem staging, and automatic catchable-failure rollback.
- Added installation of `omega-doctor` and selected only the hardened `scripts/omega-report.sh` implementation.
- Converted legacy installer entry points to thin wrappers or a non-mutating deprecation message.
- Removed the tracked legacy `scripts/omega-report`; its history remains available in Git.
- Preserved reports, bundles, configuration, logs, and `/opt/omega` data during uninstall.

## v0.2-command-layer — 2026-07-09

### Added
- Added `omega` main control menu
- Added `omega-status`
- Added `omega-health`
- Added `omega-report`
- Added `omega-alerts`
- Added `omega-summary`
- Added `install-omega-commands.sh`
- Added command documentation
- Updated README with project overview and command usage
- Added omega-bundle support bundle command
- Added omega-bundle to Omega menu
- Added omega-bundle to command installer
- Added SHA256 verification for support bundles
- Added omega-cleanup storage maintenance command
- Added omega-cleanup to Omega menu
- Added omega-cleanup to command installer
- Cleanup runs as dry-run by default

### Working Features
- Appliance status check
- Service health check
- Suricata event report
- Alert triage
- Plain-English security summary
- EveBox URL display
- Command installer into `/usr/local/bin`

### Current Stack
- Pi-hole
- Suricata
- EveBox
- Wazuh Agent
- Docker
- Tailscale

### Result
Omega now has a working local command layer for network security visibility and plain-English reporting.
