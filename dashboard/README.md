# OMEGA dashboard

The dashboard provides source-aware alerts, device observations and editable
labels, retained telemetry, private report jobs, and local AI explanations.

Version **0.1.0-preview.1** is an **experimental, source-only preview**, not an
accepted appliance image. OMEGA source is licensed under the
[Apache License 2.0](../LICENSE); see [copyright attribution](../NOTICE).
See [source-preview scope, dependencies and gates](../docs/source-preview.md).
Current [validation results](../docs/source-preview-validation.md) distinguish
passing source tests from blocked checks and deferred appliance acceptance.

## Preview

Run `python3 -B dashboard/server.py --demo`; open http://127.0.0.1:8088.
Demo events and device identities are fictional. The plain demo does not call AI.

## Appliance setup

Follow [first setup](../docs/dashboard-first-boot.md) and the
[manager connection guide](../docs/wazuh-manager-setup.md). The server binds to
loopback. Keep credentials outside the repository and configure private storage
with a dedicated unprivileged service identity. Never expose the development
server directly to the Internet.

The collector retains new Suricata, Wazuh alerts, Wazuh archives, and Pi-hole
records from configured sources. Each source establishes its own starting point;
restarts resume saved cursors. Reports state coverage and gaps. Device observations
do not establish that a device is currently online. AI sees aggregates and selected
evidence, not every raw record individually. Correlations are investigation leads.

Portable Wazuh collection uses `wazuh_mirror.py`. The legacy household push helper
and preview tunnel are not distributed in this release copy.

Completed gzip expansion caches are released only after committed EOF; original
gzip/evidence, partial records and active readers are preserved. Correlation waits
for catch-up and explicitly closes readers. Undecodable selected Pi-hole text is
retained losslessly as `_omega_sqlite_text_hex` in original records and is omitted
from text indicators. Device snapshots expose only completed updates while a
writer is busy. Archive access failures require permission checks, not an assumption
that the source gzip is corrupt.
