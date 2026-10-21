# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Portable tests of macOS observer rejection and safe Keychain restoration."""

import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parents[1] / "qualification"
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC = importlib.util.spec_from_file_location(
        "qualification_macos", DIRECTORY / "run_macos.py"
    )
    MAC = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MAC)
finally:
    sys.path.pop(0)


class MacObserverTests(unittest.TestCase):
    """Inspection failures and unrelated processes cannot become passing evidence."""

    def test_failed_process_read_is_not_clean_observation(self):
        observer = object.__new__(MAC.MacObserver)
        observer.token = b"fake-sentinel"
        with patch.object(
            MAC.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=1, stdout=b""),
        ):
            with self.assertRaises(OSError):
                observer.inspect(123)

    def test_sentinel_detected_in_memory(self):
        observer = object.__new__(MAC.MacObserver)
        observer.token = b"fake-sentinel"
        result = SimpleNamespace(returncode=0, stdout=b"command ENV=fake-sentinel")
        with patch.object(MAC.subprocess, "run", return_value=result):
            self.assertTrue(observer.inspect(123))

    def test_unrelated_process_rejected(self):
        observer = object.__new__(MAC.MacObserver)
        observer.process_getter = lambda: SimpleNamespace(pid=123)
        with patch.object(
            MAC.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=b"1"),
        ):
            self.assertFalse(observer.descendant(456))

    def test_descendant_accepted(self):
        observer = object.__new__(MAC.MacObserver)
        observer.process_getter = lambda: SimpleNamespace(pid=123)
        with patch.object(
            MAC.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=b"123"),
        ):
            self.assertTrue(observer.descendant(456))


class CleanupTests(unittest.TestCase):
    """Failure to restore defaults must never trigger store deletion."""

    def test_failed_restore_preserves_temporary_store(self):
        q = object.__new__(MAC.MacQualification)
        with tempfile.TemporaryDirectory() as directory:
            q.args = SimpleNamespace(report=Path(directory) / "report.json")
            q.active = q.observer = q.bridge = q.relay = None
            q.created = True
            q.original = ["original.keychain-db"]
            q.search = ["original.keychain-db"]
            q.keychain = Path(directory) / "test.keychain-db"
            q.report = {}
            calls = []

            def fail_restore(*args):
                calls.append(args)
                raise RuntimeError("restore failed")

            q.security = fail_restore
            with self.assertRaises(RuntimeError):
                q.close()
            self.assertFalse(q.report["cleanup"])
            self.assertFalse(any(call[0] == "delete-keychain" for call in calls))
            self.assertTrue(q.args.report.exists())


if __name__ == "__main__":
    unittest.main()
