#!/bin/bash
set -euo pipefail

root=${1:?target root is required}

for unit in docker.service docker.socket containerd.service suricata.service wazuh-agent.service tailscaled.service pihole-FTL.service evebox.service omega-oci-import.service omega-dashboard.service omega-ai.service omega-wazuh-mirror.service; do
  if [ -e "$root/usr/lib/systemd/system/$unit" ] || [ -e "$root/lib/systemd/system/$unit" ]; then
    /usr/bin/systemctl --root="$root" disable "$unit" >/dev/null
  fi
done

# Service identities are generic; secrets and activation belong to first boot.
/usr/sbin/chroot "$root" /usr/bin/systemd-sysusers
# Give the packaged private model tree its final service ownership before any
# first-boot readiness probe. Chowning only the top directory is insufficient.
/usr/sbin/chroot "$root" /usr/bin/chown -R omega-ai:omega-ai /var/lib/omega-ai
for path in etc/omega/dashboard.ready etc/omega/dashboard.env etc/omega/dashboard-setup.json etc/omega/wazuh-mirror.json etc/omega/pihole.env etc/omega/evebox.env var/lib/omega-dashboard/password var/lib/omega-ai/id_ed25519 var/lib/omega-ai/id_ed25519.pub var/lib/tailscale/tailscaled.state; do
  if [ -e "$root/$path" ] || [ -L "$root/$path" ]; then
    printf 'Unexpected provisioned dashboard state in master image: %s\n' "$path" >&2
    exit 1
  fi
done
for path in var/lib/omega-dashboard var/lib/omega-wazuh-import var/lib/omega-wazuh-mirror var/cache/omega-wazuh-mirror; do
  if [ -e "$root/$path" ] || [ -L "$root/$path" ]; then
    printf 'Unexpected appliance state directory in master image: %s\n' "$path" >&2
    exit 1
  fi
done
if [ -s "$root/var/ossec/etc/client.keys" ]; then
  printf 'Unexpected enrolled Wazuh agent identity in master image\n' >&2
  exit 1
fi

rm -f "$root/etc/machine-id" "$root/var/lib/dbus/machine-id"
install -m 0644 /dev/null "$root/etc/machine-id"
rm -f "$root"/etc/ssh/ssh_host_*
if /usr/sbin/chroot "$root" /usr/bin/id -u pi >/dev/null 2>&1; then
  /usr/sbin/chroot "$root" /usr/sbin/userdel --remove pi
fi
rm -f "$root/etc/sudoers.d/010_rpi-passwd"
rm -f "$root/etc/apt/sources.list"
rm -rf "$root/etc/apt/sources.list.d"/* "$root/var/lib/apt/lists"/*
rm -f "$root/root/.bash_history"

cat > "$root/etc/rpi-issue" <<'EOF'
Generated using authenticated rpi-image-gen v2.8.0 on 2026-08-27
Artefact version: omega-v1
EOF
