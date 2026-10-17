# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Verify that the vendored profile checker understands CLI usage lines."""

from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

CHECKER = runpy.run_path(str(Path(__file__).parents[1] / "check-release-profile.py"))


class SmokeProfileTest(unittest.TestCase):
    """Require real command names, including executable-prefixed usage output."""

    def check_help(self, help_text):
        """Return findings for a profile requesting doctor."""
        lines = ["## Smoke contract\n", "| S1 | `op-go doctor --json` | ok |\n"]
        findings = []
        with patch(
            "subprocess.run", return_value=SimpleNamespace(stdout=help_text, stderr="")
        ):
            CHECKER["check_smoke"](
                lines, {"## Smoke contract": (0, 2)}, "/tmp/op-go", findings
            )
        return findings

    def test_usage_and_command_list_formats(self):
        self.assertEqual(self.check_help("Usage:\n  op-go doctor [options]\n"), [])
        self.assertEqual(self.check_help("Commands:\n  doctor check metadata\n"), [])

    def test_rejects_absent_command_and_prose_only(self):
        self.assertTrue(self.check_help("Usage:\n  op-go run [options]\n"))
        self.assertTrue(self.check_help("Read the doctor instructions.\n"))


if __name__ == "__main__":
    unittest.main()
