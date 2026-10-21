# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Keep generated overlay packages out of repository-wide Go discovery."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class OverlayDiscoveryTest(unittest.TestCase):
    """Exercise Go discovery with real generated overlay files."""

    @unittest.skipUnless(shutil.which("go"), "Go required")
    def test_nested_overlay_is_not_discovered(self):
        prepare = Path(__file__).resolve().parents[1] / "qualification/prepare.py"
        env = dict(os.environ)
        env.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
        env["GOWORK"] = "off"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text(
                "module example.test/discovery\n\ngo 1.26.10\n"
            )
            (root / "main.go").write_text("package main\nfunc main() {}\n")
            subprocess.run(
                [sys.executable, str(prepare), str(root / "overlay")],
                env=env,
                check=True,
                capture_output=True,
            )
            result = subprocess.run(
                ["go", "list", "./..."],
                cwd=root,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.stdout.strip(), "example.test/discovery")
