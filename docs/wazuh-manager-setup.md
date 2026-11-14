# Connect a Wazuh manager to a new OMEGA appliance

OMEGA pulls manager JSON logs with its own device SSH key. The laptop push
example in `dashboard/wazuh_sync.py` is not used by this connector. The manager
must be reachable from the appliance, and its owner must install the public
key with read-only restrictions. The setup page does not log into the manager,
create its accounts, or change Wazuh collection settings.

The appliance image already pins OpenSSH and rsync. No package is downloaded by
the connector or its setup helper. The procedure below targets a conventional
Linux manager with `/var/ossec/logs`. A container, cluster, custom manager layout,
or manager without SSH needs an owner-reviewed equivalent that exposes the same
two restricted roots. A Wazuh agent alone cannot supply manager logs.

## 1. Prepare the manager's actual sources

The manager owner must check that `/var/ossec/logs/alerts/alerts.json` and
`/var/ossec/logs/archives/archives.json` exist and represent the intended manager.
JSON event archives require `logall_json` to be enabled in the manager's global
configuration; the default does not provide this full event stream. The manager
owner must review the additional storage requirements, validate any change,
and use their approved Wazuh restart procedure. OMEGA does not enable archiving.
Events that were never archived cannot be reconstructed. See the
[Wazuh event logging documentation](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html).

The manager must have a maintained OpenSSH server, rsync, the restricted `rrsync`
helper, and the ACL tools `setfacl` and `getfacl` already installed. These paths
are the concrete prerequisites for the commands below:

```bash
test -x /usr/bin/rrsync
test -x /usr/bin/rsync
test -x /usr/bin/setfacl
test -x /usr/bin/getfacl
test -x /bin/dash
test -f /var/ossec/logs/alerts/alerts.json
test -f /var/ossec/logs/archives/archives.json
```

If a check fails, stop and have the manager owner provision the missing supported
component through their normal package/configuration process. Do not substitute
a downloaded executable or use a general administrator SSH key.

## 2. Generate this appliance's public key

In the OMEGA setup page, choose **Create device key**, or run on the appliance:

```bash
sudo /usr/libexec/omega/configure-wazuh-mirror --identity
```

Keep the returned `public_key` line and its SHA256 fingerprint. Only the public
line moves to the manager; the private key stays on the appliance. Calling this
operation again returns the same identity. A partial or unrecognized identity
is preserved for owner recovery, never silently replaced.

## 3. Install one restricted manager account

The following actions are for the authorized manager administrator **on the
manager**. They are not commands for the appliance. Stop if the `omega-reader`
account or its home already exists; inspect and integrate the existing policy
manually instead of replacing any account, key, or configuration.

```bash
getent passwd omega-reader
sudo test ! -e /var/lib/omega-reader
```

The first command must return no account and a nonzero status; the second must
succeed. Then create a new dedicated account with a locked password:

```bash
sudo useradd --system --user-group --home-dir /var/lib/omega-reader \
  --no-create-home --shell /bin/dash omega-reader
sudo passwd --lock omega-reader
sudo install -d -o root -g root -m 0755 /var/lib/omega-reader
sudo install -d -o root -g root -m 0755 /var/lib/omega-reader/.ssh
```

The manager account needs a shell that can execute the forced `rrsync` command;
`nologin` would reject the connection. It receives no sudo membership, password
login, forwarding, or interactive key. Its root-owned home and key file prevent
it from changing the SSH restriction. A manager policy that blocks all locked
accounts must provide a supported public-key-only account policy; do not enable
password authentication to work around that policy.

Create a new file at `/var/lib/omega-reader/.ssh/authorized_keys`, owned by
`root:root`, mode `0644`, containing exactly one line. Replace the placeholder
with the appliance's actual `ssh-ed25519` public key, including its optional
comment. Never paste the private key:

```text
restrict,command="/usr/bin/rrsync -ro /var/ossec/logs" ssh-ed25519 APPLIANCE_PUBLIC_KEY_BASE64 omega-device-wazuh
```

For example, use `sudoedit /var/lib/omega-reader/.ssh/authorized_keys` on the
new path, then set its owner/mode and inspect the line. Add a reviewed `from=`
restriction if the appliance has a stable source address. Ensure the SSH server
accepts this key only with its forced command and has no other authorized key
source granting this account unrestricted access. The forced read-only command
limits this identity to `/var/ossec/logs`; the filesystem permissions below
further restrict access to the two intended trees. `rrsync` rejects unsafe
options such as symlink dereferencing and protected arguments. See the
[rrsync restriction documentation](https://download.samba.org/pub/rsync/rrsync.1)
and [OpenSSH authorized key options](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT).

These are separately authorized manager-provisioning operations, not source-preview
installation or a maintenance permission sweep. Inspect exact paths, identities,
ACL masks and rotation behavior first. Do not run recursive ACL examples to repair
a small number of already mirrored files; use the narrow verified correction.

Grant traversal on the two ancestors and read access only to the alerts and
archives trees. These are source permission changes authorized by the manager
owner; they do not change Wazuh's event policy:

```bash
sudo setfacl -m u:omega-reader:--x /var/ossec /var/ossec/logs
sudo setfacl -R -P -m u:omega-reader:r-X \
  /var/ossec/logs/alerts /var/ossec/logs/archives
sudo find /var/ossec/logs/alerts /var/ossec/logs/archives -type d \
  -exec setfacl -m d:u:omega-reader:r-x '{}' +
sudo -u omega-reader test -r /var/ossec/logs/alerts/alerts.json
sudo -u omega-reader test -r /var/ossec/logs/archives/archives.json
sudo -u omega-reader test ! -w /var/ossec/logs/alerts/alerts.json
sudo -u omega-reader test ! -w /var/ossec/logs/archives/archives.json
```

Use `getfacl` to review effective permissions and masks. Verify again after an
actual manager log rotation: a restrictive creation mode, ACL mask, log policy,
or later permission repair can remove the expected access. The account must not
own or be able to modify the logs, their containing directories, or its own SSH
configuration. Do not grant read access to manager credentials or all of
`/var/ossec` as a shortcut. The helper is a read-only file-transfer boundary,
not a general manager administration interface.

## 4. Verify the manager host key and save the connection

At the manager's trusted console, obtain the Ed25519 SSH host public key and its
fingerprint:

```bash
sudo cat /etc/ssh/ssh_host_ed25519_key.pub
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Transfer the public key through an owner-authenticated channel and compare the
fingerprint with that trusted console. A network scan alone does not establish
the server's identity. The initial connector supports ordinary Ed25519 host
keys; it does not accept certificates, wildcard host entries, arbitrary SSH
options, passwords, or trust-on-first-use host keys. The key is bound to the
configured connection and SSH rejects a changed or unknown key. See
[OpenSSH host key verification settings](https://man.openbsd.org/ssh_config#StrictHostKeyChecking).

In the setup page, enter the manager DNS name or IP, `omega-reader`, the SSH port,
and the verified host public key. Save the connection and wait for **both** log
transfers to succeed. The appliance service starts promptly; authentication or
network failures remain visible while it retries. Configuration can be corrected
in the setup page before the dashboard has been provisioned. Corrections stop
the fixed mirror service, preserve the device key and all mirrored evidence,
update the verified host binding, clear old transfer readiness, and restart it.
Saving unchanged settings retries service activation without generating keys.

For an operator workflow, put exactly these four settings in a separate
root-owned mode-0600 JSON file and supply its absolute path:

```json
{"host":"manager.example.net","user":"omega-reader","port":22,"host_key":"ssh-ed25519 VERIFIED_MANAGER_PUBLIC_KEY_BASE64"}
```

```bash
sudo /usr/libexec/omega/configure-wazuh-mirror --configure /root/omega-manager.json
sudo /usr/libexec/omega/configure-wazuh-mirror --status
```

Once dashboard configuration or evidence exists, this first-use helper refuses
connection changes. Deployed connection/key rotation requires the owner's
maintenance process: stop the mirror, preserve its identity and evidence,
independently verify replacement host keys, review the private settings and
matching known-host binding together, then restart and verify fresh records.
Do not delete device state to make an installation appear new.

## Transfer behavior and acceptance

The single `omega-wazuh-mirror.service` runs as `omega-mirror`, with no root
privileges, laptop agent, or inherited user SSH configuration. Its private
settings/key directory is `/var/lib/omega-wazuh-mirror`, mode `0700`; all four
identity and configuration files are mode `0600`. `omega-telemetry` readers can
read the published `/var/lib/omega-wazuh-import` trees and heartbeat, not the
private settings or key. Published directories use mode `2750` and files `0640`.

Each attempt pulls the fixed manager-relative `alerts/` and `archives/` roots
into private cache staging. Only successful transfers with the active source
present can publish. Staging uses local published files as a copy basis; it
does not modify them. A growing active file appends only after verifying the
existing bytes are an exact prefix, preserving the collector's inode cursor.
A truncation or rewrite retains the old active file as a recognized local
rotation before publishing the replacement. Completed JSON/gzip rotations are
retained locally when upstream deletes them. Interrupted staged data is not
published; the next attempt retries using retained local files. This is not an
all-files-at-once snapshot of a changing manager. These transfer choices use
[rsync's documented temporary-file and copy-destination behavior](https://download.samba.org/pub/rsync/rsync.1).

The atomic heartbeat records UTC `checked_at`, plus `sources.alerts.ok` and
`sources.archives.ok`. Pending, failed, missing-source, low-space, and timed-out
attempts stay visible; raw log contents and SSH stderr are not returned to the
setup page. Each transfer is limited to 45 seconds and the next cycle starts
after 15 seconds. A stopped service eventually has a stale heartbeat; a fresh
heartbeat must be at most 120 seconds old. Readiness means successful transfer
and source presence, not proof of a newly generated event.

Stop new transfers below a 2 GiB free-space reserve. There is no automatic
deletion of retained raw mirror history, and staging needs additional room
while a file is copied. Operators must plan local capacity and retained-log
maintenance separately from the dashboard's normalized-event retention policy.
Upstream files deleted before the appliance obtains them, time spent offline
beyond manager retention, and events never logged remain irrecoverable gaps.

On a spare-card installation, record an owner-approved alert and archive event,
verify arrival with original data, repeat after mirror/service restart and log
rotation, and confirm the dashboard has read-only access. Verify disconnection,
wrong host key, account denial, and archive absence produce failed/stale source
health while retained data remains available. Reboot and confirm only one
connector starts without a laptop. Source-package tests cannot establish these
real manager, ARM image, or hardware outcomes.
