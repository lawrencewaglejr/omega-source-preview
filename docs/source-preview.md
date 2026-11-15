# OMEGA 0.1.0-preview.1

**Experimental, source-only preview. Not an accepted appliance image.**
OMEGA source code and documentation are licensed under the
[Apache License, Version 2.0](../LICENSE), unless otherwise noted.
Copyright 2026 Lawrence Wagle Jr; see [NOTICE](../NOTICE).
Third-party components retain their own licenses and notices; this license does
not relicense the operating system, integrations, AI runtime or model.
See the [third-party source review](third-party-notices.md) and
[dated validation results](source-preview-validation.md) for publication scope.

## Run the fictional demo

On a Linux development workstation with Python 3.13 (3.13.5 was verified):

```bash
python3 -B dashboard/server.py --demo
```

Open http://127.0.0.1:8088. The demo uses fictional data and does not collect from
real sources. Keep it on loopback. Do not install services, import evidence, or use
production credentials for a source-preview test. The normal demo does not call AI.
The live mode requires separate private configuration, credentials and permissions;
see the first-boot and manager guides only as unaccepted appliance/deployment work.

## Dependencies and validation scope

Dashboard and owner-setup Python code use the standard library plus local modules;
there are no third-party pip dependencies to install for the demo. Current software
checks executed on Debian Python 3.13.5 and Node.js 20.19.2 in a disposable guest.
The earlier Python 3.14.4 / Node.js 22.22.1 results describe the original preview
checkpoint. Current Python 3.13 support is based on executed suites, not grammar
checks alone; see the [validation report](source-preview-validation.md).
Linux is required for service integration and POSIX permission behavior.

The nine-command installer requires Bash, GNU core utilities and jq for Suricata
processing. It does not install or provision the whole appliance. Its protected
installation guide remains authoritative for that command layer. Optional live
integrations require the relevant sensors, systemd, OpenSSH/rsync and separately
configured local AI. Manager ACL provisioning additionally needs ACL tools.
Image construction has a separate pinned ARM64 Debian build dependency contract,
including namespace mapping tools and ruamel.yaml; it is outside this preview.

Tests need Python, Node.js, rsync, zstd, Bubblewrap and working isolated namespaces.
The distinct-UID case also needs ACL tools, setpriv and the documented disposable
guest with a full identity map. It must not run against host or appliance paths.
Use synthetic passwd/group/NSS files where key fixtures require user lookup;
never mount host credentials or service sockets. Run source tests in a disposable
workspace with a private network namespace. No real evidence is a test fixture.

```bash
python3 -B tests/test-telemetry-store.py
python3 -B tests/test-dashboard.py
python3 -B tests/test-devices.py
python3 -B tests/test-correlation.py
python3 -B tests/test-ai-status.py
python3 -B tests/test-protection.py
python3 -B tests/test-text-report.py
python3 -B tests/test-report-jobs.py
python3 -B tests/test-wazuh-mirror.py
python3 -B tests/test-wazuh-permissions.py
python3 -B tests/test-onboarding.py
python3 -B tests/image/test-dashboard-payload.py
python3 -B tests/image/test-onboarding-payload.py
python3 -B tests/image/test-dashboard-setup.py
python3 -B tests/image/test-ai-payload.py
node tests/test-dashboard-ui.js
node tests/test-onboarding-ui.js
```

Cross-identity DAC and strict harness checks require the supported disposable
environment described in the validation report. Outside it, an unavailable
identity map or trusted-tool prerequisite is BLOCKED, not passed. Same-UID rsync
metadata checks do not prove another user's access. Do not weaken assertions or
replace host tools. The onboarding lock-release race was reproduced and fixed;
the response is now written only after releasing the operation lock.

## Changes being previewed

- Lossless hexadecimal representation of undecodable selected Pi-hole text in
  original records; normalized indicators omit the binary value and flag fields.
- Complete read batches survive a source-query deadline without skipping rows;
  other source I/O errors continue to fail closed.
- Expanded gzip copies are released only after committed EOF and completion,
  retaining original gzip and events. Durable version markers avoid repeat import;
  active, unread and partial caches remain. Failed cleanup can retry on restart.
- Background correlation waits for catch-up and closes its database iterator on
  every exit; explicit reports and shutdown take priority. First analysis starts
  after catch-up even on a freshly booted system; completed analyses retain the
  five-minute interval.
- A known rotated log retains unread cursor state when filesystem mtime rounds
  before collection start; unknown historical rotations retain their exclusion.
- Device readers use the last completed snapshot while a writer is busy.
- Permission failures are described as access errors rather than proof of corrupt
  gzip data. Source/expansion failures retain retry state and source evidence.

## Deferred appliance and publication work

No native ARM64 build, reproducibility result, fresh-card acceptance, power-loss
recovery, device provisioning or signing is claimed. Fresh-card testing waits for
spare media and separate approval. Preserve the original card and verified backups.

Shipping image manifests and verification pins are unchanged. They describe the
previous image payload and intentionally reject changed application bytes pending
separate content-inventory review. Do not repin protected content merely to pass a
check. Source test results are not image acceptance. The root changelog, protected
installer baseline and image locks have not been rewritten. The expanded project
README credits Founder & Security Architect Lawrence Wagle Jr and describes the source
preview. It differs from the builder's previously authorized README blob; a
separate reviewed README authorization is required for image source-trust
preflight. Existing README verification rules and pins have not been relaxed.

Before each publication: verify third-party notices and attribution, review
every proposed source path and Git object for private information, recheck
dependencies and test results against final bytes, and obtain separate
authorization for Git operations and publication. Private history, deployment
identities, logs, databases, backups, keys and incident material must never be
copied into the publication tree. Use an explicit reviewed file list: the
protected `.gitignore` is a useful baseline, not an exhaustive privacy boundary.
