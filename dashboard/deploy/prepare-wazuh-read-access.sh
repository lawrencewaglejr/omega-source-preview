#!/bin/sh
# Grants only log read/traversal access. Does not change Wazuh collection rules.
set -eu
test "$(id -u)" = 0 || { echo 'Run this helper with sudo.' >&2; exit 1; }
reader=${SUDO_USER:-}
test -n "$reader" && test "$reader" != root || { echo 'Run sudo from the dashboard owner account.' >&2; exit 1; }
id "$reader" >/dev/null
command -v setfacl >/dev/null || { echo 'The acl package is required.' >&2; exit 1; }
for parent in /var/ossec /var/ossec/logs; do
    test -d "$parent" && test ! -L "$parent" || exit 1
    setfacl -m "u:$reader:--x" "$parent"
done
for logs in /var/ossec/logs/alerts /var/ossec/logs/archives; do
    if test -d "$logs" && test ! -L "$logs"; then
        setfacl -R -P -m "u:$reader:r-X" "$logs"
        find "$logs" -type d -exec setfacl -m "d:u:$reader:r-x" '{}' +
        echo "Read-only log access enabled: $logs"
    else
        echo "Source not present: $logs"
    fi
done
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as E
root = E.fromstring('<root>' + Path('/var/ossec/etc/ossec.conf').read_text() + '</root>')
values = [node.text for node in root.findall('.//global/logall_json')]
print('Wazuh JSON archive setting:', ', '.join(values) if values else 'not explicitly enabled')
print('No Wazuh settings or service states were changed.')
PY
if test "${1:-}" = --enable-archives; then
    python3 - <<'PY'
import datetime, os, re, shutil, stat, subprocess
from pathlib import Path
import xml.etree.ElementTree as E
path = Path('/var/ossec/etc/ossec.conf')
if path.is_symlink() or not path.is_file():
    raise SystemExit('Expected a regular Wazuh configuration file.')
raw = path.read_text()
root = E.fromstring('<root>'+raw+'</root>')
options = root.findall('.//global/logall_json')
if len(options) > 1:
    raise SystemExit('Multiple logall_json settings require manual review.')
if options and options[0].text.strip().lower() == 'yes':
    print('Full JSON event archiving is already enabled.')
    raise SystemExit(0)
if options:
    changed, count = re.subn(r'(<logall_json>)[^<]*(</logall_json>)', r'\g<1>yes\g<2>', raw)
else:
    changed, count = re.subn(r'<global>', '<global>\n    <logall_json>yes</logall_json>', raw, count=1)
if count != 1:
    raise SystemExit('Cannot safely identify the archive setting.')
E.fromstring('<root>'+changed+'</root>')
backup = path.with_name('ossec.conf.omega-backup-'+datetime.datetime.now().strftime('%Y%m%dT%H%M%S'))
shutil.copy2(path, backup)
path.write_text(changed)
check = subprocess.run(['/var/ossec/bin/wazuh-analysisd','-t'], capture_output=True)
if check.returncode:
    shutil.copy2(backup,path)
    raise SystemExit('Wazuh validation failed; original configuration restored.')
subprocess.run(['systemctl','restart','wazuh-manager'],check=True)
print('Full Wazuh JSON event archiving enabled. Backup:',backup)
print('Previously unsaved events cannot be reconstructed.')
PY
fi
