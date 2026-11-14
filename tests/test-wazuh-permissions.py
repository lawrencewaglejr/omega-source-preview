#!/usr/bin/env python3
"""Synthetic rsync mode contract; cross-identity DAC remains explicitly blocked.

These tests do not assert that a same-UID or root reader models the live collector.
No real source, import, evidence, service or credential path is used.
"""
import gzip
import os
from pathlib import Path
import shutil
import stat
import subprocess
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

    @unittest.skip('BLOCKED: no supported disposable cross-identity host/UID mapping; same-UID metadata checks are not a DAC substitute')
    def test_distinct_publisher_and_collector_kernel_access(self):
        """Requires two real mapped identities in a separately approved disposable guest.

        A publisher-owned 0600 archive must deny the group reader; adding only
        group-read must allow it; parent traversal/default ACL/rotation variants
        must be checked with the actual unprivileged reader. Never use evidence.
        """
        self.fail('Cross-identity isolation prerequisite must be implemented and verified before enabling this test')

if __name__ == '__main__': unittest.main()
