# OMEGA dashboard

The dashboard provides source-aware alerts, device observations and editable
labels, retained telemetry, private report jobs, and local AI explanations.

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
