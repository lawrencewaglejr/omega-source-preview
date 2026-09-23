# Ω Omega Install Guide

`install.sh` is the single supported lifecycle entry point for the nine OMEGA commands. It installs exact regular files with mode `0755`; it does not provision, start, stop, or contact Pi-hole, Suricata, EveBox, Wazuh, Docker, Tailscale, or any network service.

## Preflight and Install

Run from a trusted release checkout. A dry run is an advisory, unlocked snapshot and never mutates the destination:

```bash
./install.sh install --dry-run
sudo ./install.sh install
```

The installer checks its lifecycle dependencies, Linux and Bash compatibility, the command manifest and source files, path and symlink safety, destination types, modes and hashes, and any current receipt. Missing runtime integrations are warnings only.

The command layer requires Bash, GNU core utilities (including `stat`), and `jq` for Suricata processing. Installation does not create `/etc/omega/omega.conf`, change Suricata log permissions, or provision services. On first run, the telemetry consumers use `/var/log/suricata/eve.json`; missing or unreadable telemetry is reported as `UNKNOWN`. If another path is required, install the strict root-owned mode-`0644` configuration described in `docs/configuration.md` and grant the invoking account direct read access to that regular log file.

Installation covers `omega`, `omega-status`, `omega-health`, `omega-report`, `omega-alerts`, `omega-summary`, `omega-doctor`, `omega-bundle`, and `omega-cleanup`. Only the hardened `scripts/omega-report.sh` is installed.

## Test Destination

An existing, safe absolute directory can model the complete lifecycle without root access or writes to the host installation paths:

```bash
mkdir /tmp/omega-lifecycle-root
./install.sh install --destdir /tmp/omega-lifecycle-root
./install.sh uninstall --destdir /tmp/omega-lifecycle-root
```

Relative paths, traversal components, control characters, symlinked path components, and unsupported destination types are rejected. Mutating operations acquire a lifecycle lock; dry runs intentionally do not.

## Upgrades and Collisions

Install freezes the authoritative manifest, destination, and source snapshot after its first locked preflight. Later preflights must match that snapshot before publication. It accepts absent destinations, files already identical to the trusted release, a valid current receipt whose installed files still match it, and only the legacy hashes or symlink targets explicitly named in `install/commands.manifest`.

Unknown, locally modified, wrongly permissioned, or unsupported destinations are refused before mutation. There is no `--force` mode. A known legacy installation is migrated only when every existing destination is exactly recognized. Completed-install rollback, arbitrary backup management, and restoring unmanaged content are intentionally out of scope.

Private staging and quarantine directories are created on each target filesystem. Publication uses same-filesystem renames. A catchable failure after mutation starts triggers rollback of the current operation. Incomplete rollback or cleanup returns exit `5` and retains the lock plus any available transaction artifacts for review; SIGKILL and power-loss recovery remain outside this lifecycle scope.

## Receipt and Uninstall

The current installed state is recorded at `/var/lib/omega-command-layer/installed.tsv` with mode `0600`. Under `--destdir`, that path is rooted below the supplied directory. The receipt records the manifest identity plus every destination, installed checksum, and mode. Uninstall requires the receipt manifest hash to match the trusted checkout.

Uninstall is the precise managed inverse of install. It removes a command only when the regular file, mode, and checksum match the receipt. Missing, altered, or unsafe managed content is refused. Reports, support bundles, configuration, logs, and all `/opt/omega` data are preserved.

Uninstall currently requires the same trusted release checkout. OMEGA does not install a hidden uninstaller or a self-updating lifecycle engine; that responsibility is deferred to future Debian packaging.

```bash
sudo ./install.sh uninstall
```

`uninstall.sh` and `scripts/install-omega-commands.sh` are thin compatibility wrappers. `scripts/install-omega-status.sh` is a non-mutating deprecation command and does not install anything.

## CLI and Exit Codes

```text
./install.sh install [--dry-run] [--destdir ABSOLUTE_PATH]
./install.sh uninstall [--dry-run] [--destdir ABSOLUTE_PATH]
./install.sh --help
```

- `0` — success, including an already-absent managed command layer.
- `1` — safe refusal because destination or receipt state is unknown, modified, or unsupported.
- `2` — invalid CLI, manifest, test hook, or destination-path input.
- `3` — platform, privilege, dependency, lock-contention, source, staging, or other preflight failure before mutation.
- `4` — the current operation failed after mutation began and automatic rollback completed.
- `5` — rollback or transaction/lock cleanup is incomplete, or a stale/incomplete transaction was detected and safely refused.
