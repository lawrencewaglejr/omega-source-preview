#!/usr/bin/env python3
"""Synthetic rsync modes and distinct-identity DAC in a disposable test guest.

These tests do not assert that a same-UID or root reader models the live collector.
No real source, import, evidence, service or credential path is used.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

class MirrorPermissionContractTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('rsync'), 'rsync is unavailable in the isolated test runtime')
    def test_existing_repair_survives_sync_and_new_compressed_rotation_is_read_mode(self):
        with tempfile.TemporaryDirectory(prefix='omega-permission-contract-') as temporary:
            root = Path(temporary)
            source, target = root / 'source', root / 'target'
            source.mkdir(mode=0o750); target.mkdir(mode=0o2750); target.chmod(0o2750)
            payload = gzip.compress(b'{"id":"fixture-one"}\n')
            original = source / 'ossec-alerts-01.json.gz'
            original.write_bytes(payload); original.chmod(0o640)
            command = ['rsync','-rt','--inplace','--no-links','--chmod=D2750,F640',str(source)+'/',str(target)+'/']
            def sync(): subprocess.run(command,check=True,capture_output=True,timeout=10)
            sync(); copied = target / original.name
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o640)
            copied.chmod(0o600); sync()
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o600, '--chmod without --perms preserves an existing destination mode')
            copied.chmod(0o640); sync()
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o640)
            rotated = source / 'ossec-alerts-02.json.gz'
            rotated.write_bytes(gzip.compress(b'{"id":"fixture-two"}\n')); rotated.chmod(0o640)
            sync()
            self.assertEqual(stat.S_IMODE((target/rotated.name).stat().st_mode),0o640)
            self.assertEqual((target/rotated.name).stat().st_gid,target.stat().st_gid)
            self.assertEqual(copied.read_bytes(),payload)
            self.assertEqual(original.read_bytes(),payload)

    def test_distinct_publisher_and_collector_kernel_access(self):
        """Exercise real unprivileged readers, never a root/same-UID substitute."""
        marker = Path('/run/omega-validation-guest')
        if (os.geteuid() != 0 or not marker.is_file()
                or marker.stat().st_uid != 0
                or marker.read_text().strip() != 'isolated-qemu'
                or 'omega.validation=1' not in Path('/proc/cmdline').read_text().split()):
            self.skipTest('BLOCKED: requires the documented disposable guest with distinct identities')
        for command in ('setpriv', 'setfacl', 'rsync'):
            self.assertIsNotNone(shutil.which(command), command + ' is required in the guest')
        publisher, collector, shared = 2001, 2002, 2100
        for mapping in ('uid_map', 'gid_map'):
            self.assertEqual(Path('/proc/self/' + mapping).read_text().split(),
                             ['0', '0', '65536'], 'Explicit guest identity range must be mapped')

        def as_user(uid, code, *args):
            identity = ("import os; from pathlib import Path; "
                        f"assert os.getuid() == os.geteuid() == {uid} != 0; "
                        "assert 'CapEff:\\t0000000000000000' in Path('/proc/self/status').read_text(); ")
            command = ['setpriv', '--reuid=' + str(uid), '--regid=' + str(uid + 300),
                       '--groups=' + str(shared), '--bounding-set=-all', '--inh-caps=-all',
                       '--ambient-caps=-all', '--no-new-privs', sys.executable, '-B', '-c',
                       identity + code, *map(str, args)]
            result = subprocess.run(command, check=True, capture_output=True, text=True,
                                    timeout=20, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            return result.stdout.strip()

        def read_as_collector(path):
            code = '''import errno, hashlib, json, sys
try:
    data = Path(sys.argv[1]).read_bytes()
    result = {'uid': os.getuid(), 'sha256': hashlib.sha256(data).hexdigest()}
except OSError as error:
    result = {'uid': os.getuid(), 'errno': error.errno}
print(json.dumps(result))
'''
            return json.loads(as_user(collector, code, path))

        def denies(path):
            self.assertEqual(read_as_collector(path), {'uid': collector, 'errno': 13})

        def allows(path, data):
            self.assertEqual(read_as_collector(path),
                             {'uid': collector, 'sha256': hashlib.sha256(data).hexdigest()})

        def chmod(path, mode):
            as_user(publisher, 'import sys; Path(sys.argv[1]).chmod(int(sys.argv[2], 8))', path, mode)

        with tempfile.TemporaryDirectory(prefix='omega-distinct-dac-') as temporary:
            root = Path(temporary)
            os.chown(root, publisher, shared); root.chmod(0o2750)
            source, target = root / 'source', root / 'target'
            as_user(publisher, "import sys; Path(sys.argv[1]).mkdir(mode=0o700); Path(sys.argv[2]).mkdir(mode=0o2750)", source, target)
            chmod(target, '2750')
            original = source / 'ossec-alerts-01.json.gz'
            copied = target / original.name
            payload = gzip.compress(b'{"id":"distinct-identity-fixture"}\n')
            write = 'import sys; Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2])); Path(sys.argv[1]).chmod(int(sys.argv[3], 8))'
            as_user(publisher, write, original, payload.hex(), '0640')
            as_user(publisher, write, copied, payload.hex(), '0600')
            self.assertEqual(copied.stat().st_uid, publisher)
            self.assertEqual(copied.stat().st_gid, shared)
            denies(copied)
            chmod(copied, '0640'); allows(copied, payload)
            chmod(target, '2700'); denies(copied)
            chmod(target, '2750'); allows(copied, payload)
            denies(original)  # Publisher's source directory is not collector-readable.

            sync = ("import subprocess, sys; subprocess.run(['rsync', '-rt', '--inplace', "
                    "'--no-links', '--chmod=D2750,F640', sys.argv[1]+'/', sys.argv[2]+'/'], check=True)")
            chmod(copied, '0600'); as_user(publisher, sync, source, target); denies(copied)
            chmod(copied, '0640'); as_user(publisher, sync, source, target); allows(copied, payload)
            rotated = source / 'ossec-alerts-02.json.gz'
            next_payload = gzip.compress(b'{"id":"distinct-rotation-fixture"}\n')
            as_user(publisher, write, rotated, next_payload.hex(), '0640')
            as_user(publisher, sync, source, target)
            self.assertEqual((target / rotated.name).stat().st_gid, shared)
            allows(target / rotated.name, next_payload)

            acl_dir = root / 'acl'
            as_user(publisher, 'import sys; Path(sys.argv[1]).mkdir(mode=0o700)', acl_dir)
            acl = 'u:2002:r-x,d:u::rwx,d:u:2002:r--,d:g::---,d:m::r--,d:o::---'
            set_acl = "import subprocess, sys; subprocess.run(['setfacl', '-m', sys.argv[2], sys.argv[1]], check=True)"
            as_user(publisher, set_acl, acl_dir, acl)
            acl_file = acl_dir / 'rotation.json.gz'
            as_user(publisher, 'import sys; os.umask(0o077); Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))', acl_file, payload.hex())
            allows(acl_file, payload)
            as_user(publisher, set_acl, acl_file, 'm::---'); denies(acl_file)
            as_user(publisher, set_acl, acl_file, 'm::r--'); allows(acl_file, payload)
            as_user(publisher, set_acl, acl_dir, 'm::---'); denies(acl_file)
            as_user(publisher, set_acl, acl_dir, 'm::r-x'); allows(acl_file, payload)
            write_attempt = '''import json, sys
try:
    with Path(sys.argv[1]).open('ab') as output:
        output.write(b'unexpected-write')
    result = {'uid': os.getuid(), 'errno': None}
except OSError as error:
    result = {'uid': os.getuid(), 'errno': error.errno}
print(json.dumps(result))
'''
            self.assertEqual(json.loads(as_user(collector, write_attempt, acl_file)),
                             {'uid': collector, 'errno': 13})
            self.assertEqual(original.read_bytes(), payload)
            self.assertEqual(copied.read_bytes(), payload)
            self.assertEqual(acl_file.read_bytes(), payload)

if __name__ == '__main__': unittest.main()
