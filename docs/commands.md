
# Ω Omega Commands

Omega commands are installed into /usr/local/bin and provide quick access to system health, security telemetry, alert triage, diagnostics, and plain-English reporting.

## Result Contract

The `omega-status`, `omega-health`, `omega-report`, `omega-alerts`, `omega-summary`, and `omega-doctor` commands end with exactly one machine-readable result line:

```text
OMEGA_RESULT=SUCCESS
```

The result line is the last nonblank line on standard output. Exit codes are:

- `0` — `SUCCESS`: all required observations completed and support the command result.
- `1` — `WARNING`: observations are trustworthy, but an actionable or noncritical condition exists.
- `2` — `UNKNOWN`: required evidence could not be obtained or trusted. The command must not make a healthy claim.
- `3` — `FAILURE`: a required component is confirmed unhealthy, or required output cannot be produced.

When several conditions occur, precedence is `FAILURE`, then `UNKNOWN`, then `WARNING`, then `SUCCESS`. A successful report or triage means the command processed its available evidence correctly; it is not proof that the network is secure.

Service checks accept a service as healthy only when `systemctl` returns exactly `active` with exit status 0. An empty Suricata stream is `WARNING`, never a zero-alert safety conclusion. Aggregation or validation errors are `UNKNOWN`.

`omega-summary`, `omega-alerts`, `omega-report`, and `omega-doctor` read Suricata telemetry directly as the invoking user. They use `/var/log/suricata/eve.json` when the optional strict `/etc/omega/omega.conf` is absent. They reject unsafe configuration, symlinks and non-regular telemetry before opening, consume one opened descriptor, and return `UNKNOWN` if its pathname disappears or is replaced. See `docs/configuration.md` for the exact byte, ownership, permission, and path contract.

## omega

Main Omega control menu.

Command:
omega

Menu options:
1. Status
2. Health Check
3. Security Report
4. Alert Triage
5. Plain-English Summary
6. Omega Doctor
7. Support Bundle
8. Cleanup
9. EveBox URL
10. Exit

## omega-status

Shows appliance status, service health, IP addresses, disk usage, memory, and EveBox status.

Command:
omega-status

## omega-health

Runs a deeper operational health check.

Command:
omega-health

Checks:
- Host information
- Network interfaces
- Disk usage
- Memory usage
- Pi-hole
- Suricata
- Wazuh Agent
- Docker containers
- EveBox HTTP response

## omega-report

Generates a readable Suricata report.

`eve.json` is processed as physical-line JSON Lines: every physical line must contain exactly one complete JSON object. Ordinary non-alert events do not need an `alert` object. Records whose `event_type` is `alert` must contain a nonempty alert signature and a positive integer severity; otherwise the security result is `UNKNOWN`.

Command:
omega-report

Includes:
- Suricata event summary
- Recent DNS queries
- Recent alerts
- Saved timestamped report output

Reports are saved under:
~/omega-reports/output/

Completed reports are generated privately from one validated telemetry snapshot and atomically published. Incomplete reports never replace completed reports; when diagnostic output can be retained safely, its filename includes `.incomplete` and its last line is `OMEGA_RESULT=UNKNOWN`.

An empty but valid telemetry stream produces a completed report with `WARNING` and an explicit statement that alert safety cannot be determined. Higher-priority alerts also produce `WARNING`. If `HOME` is unset, no report path can be selected and the command returns `FAILURE` without publishing a report.

## omega-alerts

Runs alert triage.

Triage reports `SUCCESS` only after the complete JSON Lines input has parsed and validated. Severity 1–2 alerts and empty telemetry produce `WARNING`; unreadable, malformed, invalid alert records, or failed aggregation produce `UNKNOWN`.

Command:
omega-alerts

Shows:
- Top alert signatures
- Recent alerts
- Possible noise / informational alerts
- Higher-priority alerts

## omega-summary

Creates a plain-English security summary.

Command:
omega-summary

Shows:
- System status
- Service status
- DNS event count
- Total alert count
- Higher-priority alert count
- Plain-English result
- Recommended next command

## omega-doctor

Runs a diagnostic check of the Omega command layer and core services.

Command:
omega-doctor

Checks:
- All nine installed Omega commands
- Required system tools
- Pi-hole service
- Suricata service
- Wazuh Agent service
- Docker service
- OMEGA runtime configuration and selected Suricata JSONL telemetry
- EveBox web response
- Report output directory

Expected healthy result:
Result: Omega command layer looks healthy.

## Command Installation Lifecycle

The canonical installer is the top-level `install.sh`. Preview and install with:

```bash
./install.sh install --dry-run
sudo ./install.sh install
```

Uninstall from the same trusted release checkout with `sudo ./install.sh uninstall`. The installer refuses unknown or modified destinations, migrates only exactly recognized legacy files or symlinks, records installed hashes in a private current-state receipt, and automatically rolls back catchable failures in the current operation. It preserves reports, bundles, configuration, logs, and `/opt/omega` data.

For a rootless isolated lifecycle, pass an existing safe absolute directory with `--destdir`. See `docs/install.md` for the complete CLI and exit-code contract. `scripts/install-omega-commands.sh` and `uninstall.sh` are compatibility wrappers; `scripts/install-omega-status.sh` only prints a deprecation message and never installs commands.

Installed commands:
- omega
- omega-status
- omega-health
- omega-report
- omega-alerts
- omega-summary
- omega-doctor
- omega-bundle
- omega-cleanup

## omega-bundle

Creates a timestamped Omega support bundle.

Command:
omega-bundle

Includes:
- omega-status output
- omega-health output
- omega-summary output
- omega-alerts output
- omega-report output
- omega-doctor output
- Git status
- Recent commits
- Git tags
- SHA256 hash

Bundles are saved under:
~/omega-support-bundles/


## omega-cleanup

Safely checks for old Omega report files and support bundles.

Command:
omega-cleanup

Dry run by default. It shows what would be deleted without deleting anything.

Delete files older than 7 days:
omega-cleanup --days 7 --force

Targets:
- ~/omega-reports/output/
- ~/omega-support-bundles/
