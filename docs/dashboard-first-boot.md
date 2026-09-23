# Dashboard and local AI provisioning contract

The master-image payload stages the dashboard, the pinned local AI runtime and
model, disabled service units, service-account definitions, and a configuration
example. It includes a paired browser setup wizard and a portable Wazuh manager
connection. A newly flashed card is unprovisioned; these units must not be
enabled in the master image. Packaging and
unit validation are not evidence that a fresh card has passed a hardware boot
test.

The offline operator helper `/usr/libexec/omega/configure-dashboard` checks
the prerequisites below and creates the first dashboard configuration. It
does not configure sensors, network access, or a Wazuh manager connection.
Device identity, network/sensor installation, and owner SSH access remain
prerequisites. Apply this workflow
to a newly provisioned device, not to a running appliance with existing identity
and evidence.

## Guided browser setup

From the owner's computer, connect to the newly provisioned appliance with both
private port forwards. Replace the account and host placeholders:

```bash
ssh -L 8090:127.0.0.1:8090 -L 8089:127.0.0.1:8089 <owner>@<appliance>
```

In that appliance terminal, run:

```bash
sudo /usr/libexec/omega/start-setup
```

Open `http://127.0.0.1:8090` on the owner's computer and enter the pairing code
printed in the terminal. The code is usable once and expires after 30 minutes;
the browser session lasts one hour. Reloading recovers the paired session.
The listener closes after 90 minutes and is never automatically enabled in the
image. Keep the terminal and tunnel open until setup finishes, then use Ctrl+C.
An in-flight configuration operation finishes before the process exits.

The wizard pairs the browser, connects sources, collects a new password and
retention choices, checks prerequisites, then asks the owner to activate and
verify. Saving configuration and starting services are separate actions. The
temporary root process exposes fixed setup operations, binds only to loopback,
and protects writes with Host/Origin checks and a session-specific token.
Passwords never enter URLs, job records, browser storage, or HTTP logs. This is
an operator-assisted setup interface; production HTTPS access is separate work.

For a remote Wazuh manager, create the appliance's own identity in the wizard,
copy its public key, and follow the downloadable
[manager reader instructions](wazuh-manager-setup.md) on that manager. Paste
its Ed25519 host public key obtained through a trusted channel. OMEGA pulls the
two fixed log streams with its dedicated key, independently of the laptop's
login agent. The manager must stay available, and granting reader access is an
explicit manager-administrator step. Local managers and existing mirrors are
also supported. Connection settings can be corrected before dashboard setup;
existing keys and collected mirror files are preserved.

Verification compares source counters before and after a real local-AI request.
It requires new evidence and current collection. Shared Wazuh alert/archive IDs
are accounted for without treating copies as independent observations.
Generate benign DNS/network and endpoint activity while the check runs. Quiet
sources remain unverified until new records arrive. A completed AI answer
proves inference ran, not broad answer quality or whole-network coverage.

For a development preview, run
`python3 -B onboarding/server.py --demo --port 8092` from the checkout and use
pairing code `OMEGA-PREVIEW`. The preview simulates setup without connecting to
sensors, generating keys, saving passwords, starting services, or calling AI.

## Operator setup command

First complete device identity, source initialization, and persistent reader
permissions as described below. Keep the dashboard and AI services stopped.
Copy the packaged example to a private configuration file and edit it for
this device:

```bash
sudo install -o root -g root -m 0600 \
  /etc/omega/dashboard-setup.json.example /etc/omega/dashboard-setup.json
sudoedit /etc/omega/dashboard-setup.json
sudo /usr/libexec/omega/configure-dashboard \
  --check --config /etc/omega/dashboard-setup.json
```

The JSON must contain exactly the nine keys in the example. Integer values are
JSON numbers: 1–8 AI threads, 1–3,650 retention days, and 1–50,000,000 maximum
events. Review retention against this device's available space and event rate.
Use distinct absolute source paths accessible inside the service sandbox.
For a local Wazuh manager, set `OMEGA_WAZUH_SYNC_STATUS` to `""` and point the
two logs to the actual manager files. For a mirror, its successful heartbeat
must be at most 120 seconds old.

`--check` verifies unused private state, stopped services, accounts, packaged
runtime and model integrity, initialized source files, service-account read
access, and at least 2 GiB free space. It makes no configuration changes and
does not prove fresh events or AI inference work. The image's post-build step
already assigns the private model tree to `omega-ai:omega-ai`; if constructing
a test device by hand, that ownership must be established before these checks.

After the check passes, run the first-use setup interactively:

```bash
sudo /usr/libexec/omega/configure-dashboard \
  --apply --config /etc/omega/dashboard-setup.json
```

Enter and repeat a new password of 16–1,024 characters when prompted. Do not
put a password in the command line or JSON. An unattended operator may instead
provide `--password-file /absolute/private/input`, a separate root-owned,
mode-0600 regular file with one filesystem link. Handle and remove that input
through the device's private credential-provisioning process after use.

The helper creates private dashboard state directories, `dashboard.env`, the
password file, and the ready marker. It refuses existing configuration or
evidence, checks again before publishing the marker, and rolls back its own new
outputs on failure. It is a first-use tool; it does not reset or repair an
already configured installation. Services remain stopped after success.

Once the approved owner connection is ready, activate and perform all
acceptance checks below:

```bash
sudo systemctl enable --now omega-ai.service omega-dashboard.service
```

The dashboard remains at `127.0.0.1:8089` on the appliance. A ready marker or
successful service start is not release acceptance.

## Device identity and private state

- Create a unique device hostname, machine identity, SSH host keys, and owner
  login credentials. Establish the approved network and remote-access settings.
  Never copy the development appliance's credentials, device labels, event
  ledger, report downloads, or personal SSH-agent configuration into an image.
- The image applies `omega-dashboard.conf` with systemd-sysusers. It creates the
  non-login `omega-dashboard` and `omega-ai` accounts and managed `omega-telemetry`
  reader group. These are service identities, not dashboard sign-in accounts.
- The helper creates `/var/lib/omega-dashboard` and its `live` subdirectory with
  owner and group `omega-dashboard`, mode `0700`. The unit's `StateDirectory` settings
  enforce the same ownership and mode when it starts. Keep the fresh
  `/var/lib/omega-dashboard/live/telemetry.sqlite3` path absent until its first
  start. Do not seed it with another installation's database.
- The helper obtains an owner-selected dashboard password of at least 16
  characters through a private prompt or file. It writes only that password to
  `/var/lib/omega-dashboard/password`, owned by `omega-dashboard`, mode `0600`.
  Do not put it in an image, environment variable, service command, or setup log.
  The current server has one password and no account/password-management UI;
  recovery and password rotation remain development work.
- Stage the verified offline model under `/var/lib/omega-ai/models`. The AI unit
  uses a private `0700` state directory and a non-login account. Verify it can
  read the pinned model manifest and every required blob. No registry pull is
  performed at service startup. Runtime-generated keys or state belong only to
  this device and must never be baked back into the master image.

## Initialize the actual telemetry sources

1. Complete the existing Pi-hole container provisioning and start it with its
   device-specific credentials. Its database must be initialized at the host
   volume path `/var/lib/omega/pihole/etc-pihole/pihole-FTL.db`. Route the intended
   clients' DNS traffic to Pi-hole through the approved network setup; merely
   starting its container does not establish network-wide visibility. Do not
   assume Pi-hole supplies DHCP or change the router's DHCP mode implicitly.
2. Configure Suricata's actual capture interface and `HOME_NET`. Confirm the
   sensor writes valid EVE JSON, including the required event types, to
   `/var/log/suricata/eve.json`. A running process alone does not prove useful
   traffic is visible on that interface.
3. Enroll the Wazuh agent with the selected manager. This image contains an
   **agent**, which does not provide the manager's `alerts.json` or
   `archives.json` streams. Configure the manager to retain JSON archives as well
   as alerts and provision a durable authenticated log mirror to
   `/var/lib/omega-wazuh-import`. The new `omega-wazuh-mirror.service` supplies this connection using a
   dedicated device key and verified host binding. Configure it through the
   wizard after granting restricted reader access on the manager. The older
   `dashboard/wazuh_sync.py` remains a personal deployment example.
4. A mirror must retain complete JSON records and unread rotations, resume after
   interruptions, and publish `sync-status.json` atomically after each attempt.
   The current reader expects an ISO-8601 UTC `checked_at` and a `sources` object
   with `alerts` and `archives`, each containing an `ok` boolean. Stale or failed
   heartbeats must remain visible. If a manager is deliberately installed on the
   appliance later, the environment can point directly to its real log files
   and set `OMEGA_WAZUH_SYNC_STATUS` to an empty value.
5. Grant `omega-telemetry` read access to the selected files and traversal access
   to every ancestor directory. Apply managed group permissions or ACLs to
   Suricata output, Pi-hole's host-volume database, its existing WAL/SHM files
   when present, and the Wazuh mirror and heartbeat. Pi-hole runs in a container:
   a matching host `pihole` account or group is **not** assumed. Confirm the
   writer's creation and rotation policies preserve reader access; a one-time
   permission fix is insufficient. The dashboard must not have permission to
   edit those source files. Source writers must initialize required SQLite
   companion files; the read-only dashboard does not create them.
   The current package lock does not include the `acl` command-line package;
   an ACL-based provisioning implementation must add a verified pinned helper
   or package rather than assuming `setfacl` is installed.

## Configure and activate the services

The helper writes `/etc/omega/dashboard.env` as `root:root`, mode `0600`, using
the reviewed JSON paths and installed model name. The packaged
`/etc/omega/dashboard.env.example` documents the resulting settings.
Its values are literal systemd environment assignments;
the unit expands each variable as one scalar argument and invokes no shell.
The default model is `qwen3:1.7b` with two inference threads. Do not substitute
an unverified model name merely to make setup appear complete.

The template carries forward the working deployment's limits of 3,650 days or
50,000,000 normalized events, whichever limit is reached first. These are
retention limits, **not** an estimate that an SD card can hold that much data.
First-boot setup must review and choose explicit limits against the expanded
filesystem, event rate, expected report size, and free-space reserve. Collection
pauses when free space falls below 2 GiB. These defaults are configurable and do
not promise unlimited retention. Changing the image template does not change a
running appliance's existing configuration.

After checking configuration, credentials, source access, and model files, the
helper creates `/etc/omega/dashboard.ready` as a root-owned regular file. Both
units require this explicit marker. Enable and start
`omega-ai.service` and `omega-dashboard.service` only on the provisioned device,
then run the acceptance checks below. The marker is an activation gate, not a
claim that those checks passed. Keep it absent from the master image. To stop a
running deployment, stop the services; removing a condition file alone does not
stop an already-running service.

The dashboard listens only on `127.0.0.1:8089`; local AI listens only on
`127.0.0.1:11434`. Both units restrict network access to loopback. AI cloud
features are disabled and models are supplied offline. Provide an authenticated
owner connection to the dashboard, such as a device-specific SSH tunnel; a
production HTTPS/access setup is still required for a general customer UI. Do
not expose the AI endpoint directly. Browser notifications also require an
owner gesture, browser permission, and an open dashboard page.

## Fresh-device acceptance evidence

Record the image digest, device/model identity, configuration policy, collection
boundary, test timestamps, and observed outcomes. Do not record passwords or
private keys in the acceptance report.

- Verify both units were disabled and the ready marker, configuration file,
  password, personal event history, and machine credentials absent from the
  unprovisioned image. Verify the pinned runtime and model hashes before use.
- After activation, sign in through the approved owner connection. Verify all
  four sources are readable and current: Suricata, Wazuh alerts, Wazuh archives,
  and Pi-hole. Confirm the Wazuh heartbeat reflects actual successful transfers,
  not only successful reads of old mirrored files.
- Confirm `collection_mode` is `from_now` and record each source's first-read
  baseline. Existing log bytes and query rows are intentionally skipped. A zero
  count immediately after this baseline is valid; generate known benign events
  afterward and verify their arrival. A source that becomes readable later has
  its own later baseline, so do not claim continuous coverage for that gap.
- Verify a known DNS request, a Suricata observation, a manager alert, and a
  manager archive record appear with their original data. Record collection
  latency. Check attribution against real hostnames and addresses; leave
  unsupported device identities unknown.
- Restart the dashboard, reconnect the manager mirror, and rotate each log.
  Confirm saved cursors resume, fresh records arrive, duplicated Wazuh relay
  records are not treated as independent confirmation, and missing/unreadable
  sources or stale heartbeats are shown honestly.
- Generate a full report with local AI analysis. Measure completion time and
  resource use on the target Pi. Check cited event/correlation IDs, verify the
  answer ends normally, compare exported normalized and original record counts
  with the report's retained snapshot, and confirm source gaps and retention
  limits are included. AI receives combined aggregates and selected evidence;
  it does not independently read every raw record. A successful model-list
  request is not a successful analysis test.
- Verify shutdown/reboot recovery, private-file permissions, intended loopback
  listeners, and explicit error states for unavailable AI and sources. Perform
  sustained collection and storage-pressure testing before release.

Adult-content filtering and opt-in message review currently save setup
preferences only. They do not enforce policy or connect messaging accounts.
First-boot setup must not describe those features as active protection.
