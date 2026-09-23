#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
from protection import ProtectionSetup


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "protection.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_preferences_persist_without_activating_access(self):
        result = ProtectionSetup(self.path).save(True, True)
        self.assertFalse(result["filtering_active"])
        self.assertFalse(result["message_access_active"])
        restored = ProtectionSetup(self.path).snapshot()
        self.assertEqual(result, restored)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(ProtectionSetup(self.path).save(False, False)["preferences"]["adult_filter"])

    def test_demo_does_not_write_and_resets(self):
        self.assertTrue(ProtectionSetup(self.path, demo=True).save(True, True)["preferences"]["adult_filter"])
        self.assertFalse(self.path.exists())
        self.assertFalse(ProtectionSetup(self.path, demo=True).snapshot()["preferences"]["adult_filter"])

    def test_unconfigured_storage_cannot_save(self):
        setup = ProtectionSetup()
        self.assertFalse(setup.snapshot()["available"])
        with self.assertRaises(OSError):
            setup.save(True, False)

    def test_only_boolean_preferences_accepted(self):
        for value in ("true", 1, None, [], {}):
            with self.assertRaises(ValueError):
                ProtectionSetup(self.path).save(value, False)
        self.assertFalse(self.path.exists())

    def test_corrupt_state_is_preserved_and_fails_closed(self):
        self.path.write_text('{"version":2}')
        self.path.chmod(0o600)
        setup = ProtectionSetup(self.path)
        self.assertFalse(setup.snapshot()["available"])
        with self.assertRaises(OSError):
            setup.save(True, False)
        self.assertEqual(self.path.read_text(), '{"version":2}')

    def test_unsafe_files_and_directories_rejected(self):
        ProtectionSetup(self.path).save(False, False)
        self.path.chmod(0o644)
        self.assertFalse(ProtectionSetup(self.path).snapshot()["available"])
        self.path.chmod(0o600)
        linked = self.root / "link"
        linked.symlink_to(self.path)
        self.assertFalse(ProtectionSetup(linked).snapshot()["available"])
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        self.assertFalse(ProtectionSetup(fifo).snapshot()["available"])
        self.root.chmod(0o755)
        self.assertFalse(ProtectionSetup(self.path).snapshot()["available"])


if __name__ == "__main__":
    unittest.main()
