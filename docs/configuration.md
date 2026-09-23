# OMEGA Runtime Configuration

The four Suricata consumers—`omega-summary`, `omega-alerts`, `omega-report`, and `omega-doctor`—read one optional, non-executable configuration file:

```text
/etc/omega/omega.conf
```

If `/etc/omega` is genuinely absent, or `omega.conf` is absent inside a valid directory, the commands use `/var/log/suricata/eve.json`. Any existing unsafe parent or configuration object is an error; it never triggers fallback. The canonical example is `config/omega.conf.example`.

## Exact format

The file is exactly two newline-terminated physical lines:

```text
OMEGA_CONFIG_V1
suricata_eve_path=/var/log/suricata/eve.json
```

It is parsed as inert bytes under the C locale and is never sourced or evaluated. Comments, blank or extra lines, unknown or duplicate keys, missing final newlines, control bytes (including NUL), leading or trailing whitespace, files over 4096 bytes, lines over 2048 bytes, and paths over 2000 bytes are rejected.

The telemetry path must be absolute but not `/`. Empty, `.` and `..` components, duplicate separators, trailing separators, and control bytes are rejected.

## Ownership and permissions

- `/etc` and `/etc/omega` must be real root-owned directories, must not be group/other writable, and must be searchable by the caller.
- `omega.conf` must be a real root-owned regular file with mode exactly `0644`; symlinks and mode `0600` are unsupported.
- The selected telemetry object must be a directly readable regular file, not a symlink, FIFO, socket, device, or directory.

OMEGA does not use `sudo` to read Suricata telemetry. Grant the account running OMEGA the minimum read access required by the local Suricata policy, normally through the log’s owning group or a narrowly scoped ACL. Do not make the log world-writable.

## Runtime behavior

The command opens configuration and telemetry only after type checks, validates the opened descriptor against the pathname, consumes telemetry through that descriptor, and checks that the pathname still names the same device/inode afterward. Path disappearance or replacement is `UNKNOWN`. Same-inode append is permitted; an incomplete physical JSONL record that is actually consumed is `UNKNOWN`.

This prevents an existing special file from blocking normal operation and pins consumption to the opened object. It is reliability hardening for an unprivileged reader, not a claim of protection against a privileged administrator racing every check.

Phase 3 configuration and telemetry behavior has been verified only through the isolated local regression harness. It has not yet been validated against live telemetry on the real Raspberry Pi.

Invalid configuration produces `UNKNOWN` in summary, alerts, and report, and `FAILURE` in doctor. Configuration that cannot be acquired or changes during validation produces `UNKNOWN` in all four. Report records these conditions only through its normal atomically published `.incomplete` path and never replaces a completed report.
