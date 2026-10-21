# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""A failed status assertion must preserve network/child/process evidence."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

DIRECTORY = Path(__file__).resolve().parents[1] / "qualification"
SPEC = importlib.util.spec_from_file_location("qualification_run", DIRECTORY / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC.loader.exec_module(RUN)
finally:
    sys.path.pop(0)


@unittest.skipUnless(
    sys.platform.startswith("linux"), "requires Linux /proc process observation"
)
class FailureEvidenceTest(unittest.TestCase):
    """Use a harmless child failure, without any credentials or keyring."""

    def test_status_mismatch_retains_attempt_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                binary=Path(sys.executable),
                instrumented=Path(sys.executable),
                live=False,
                report=root / "report.json",
            )
            q = RUN.Qualification(args, root)
            marker = root / "child-marker"
            try:
                with self.assertRaises(RuntimeError):
                    q.stalled_run(
                        "intentional mismatch",
                        ["-c", "raise SystemExit(10)"],
                        30,
                        marker,
                    )
                attempt = q.report["network_attempts"][-1]
                operation = attempt["operation"]
                self.assertEqual(operation["expected_status"], 20)
                self.assertEqual(operation["actual_status"], 10)
                self.assertGreaterEqual(operation["seconds"], 0)
                self.assertTrue(operation["observed_pids"])
                self.assertEqual(operation["surviving_observed_pids"], [])
                self.assertFalse(attempt["child_marker_present"])
                self.assertIn("held_replies", attempt["after"])
            finally:
                q.close()
            report = json.loads(args.report.read_text(encoding="utf-8"))
            self.assertTrue(report["cleanup"])
            self.assertEqual(
                report["network_attempts"][-1]["operation"]["actual_status"], 10
            )


if __name__ == "__main__":
    unittest.main()
