# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Verify signed apt metadata with a temporary test key and fake packages."""

import email.utils
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ("dpkg-deb", "dpkg-scanpackages", "apt-ftparchive", "gpg")


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "apt tools required")
class AptRepositoryTest(unittest.TestCase):
    """Exercise signing and retained versions without using a personal keyring."""

    def test_signed_pool_and_expiry(self):
        with tempfile.TemporaryDirectory(prefix="op-go-apt-test-") as temporary:
            directory = Path(temporary)
            keyring = directory / "gnupg"
            keyring.mkdir(mode=0o700)
            environment = {**os.environ, "GNUPGHOME": str(keyring)}
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    "Release Test <test@example.invalid>",
                    "ed25519",
                    "sign",
                    "1d",
                ],
                env=environment,
                check=True,
                capture_output=True,
            )
            listing = subprocess.check_output(
                ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
                env=environment,
                text=True,
            )
            fingerprint = next(
                line.split(":")[9]
                for line in listing.splitlines()
                if line.startswith("fpr:")
            )
            binary = directory / "op-go"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            assets = directory / "assets"
            for version in ("1.2.3", "1.2.4"):
                for arch in ("amd64", "arm64"):
                    subprocess.run(
                        [
                            "bash",
                            str(ROOT / "packaging/scripts/package.sh"),
                            version,
                            f"linux-{arch}",
                            str(binary),
                            str(assets),
                        ],
                        check=True,
                        capture_output=True,
                    )
            output = directory / "apt"
            command = [
                "bash",
                str(ROOT / "packaging/scripts/build-apt-repo.sh"),
                str(assets),
                str(output),
                fingerprint,
            ]
            subprocess.run(command, env=environment, check=True, capture_output=True)
            release = output / "dists/stable/Release"
            fields = dict(
                line.split(": ", 1)
                for line in release.read_text().splitlines()
                if ": " in line and not line.startswith(" ")
            )
            interval = email.utils.parsedate_to_datetime(
                fields["Valid-Until"]
            ) - email.utils.parsedate_to_datetime(fields["Date"])
            self.assertEqual(interval.total_seconds(), 30 * 24 * 3600)
            self.assertEqual(len(list((output / "pool/main/o/op-go").glob("*.deb"))), 4)
            for arch in ("amd64", "arm64"):
                packages = (
                    output / f"dists/stable/main/binary-{arch}/Packages"
                ).read_text()
                self.assertIn("Version: 1.2.3", packages)
                self.assertIn("Version: 1.2.4", packages)
                self.assertEqual(packages.count(f"Architecture: {arch}"), 2)
            subprocess.run(
                ["gpg", "--batch", "--verify", str(output / "dists/stable/InRelease")],
                env=environment,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--verify",
                    str(output / "dists/stable/Release.gpg"),
                    str(release),
                ],
                env=environment,
                check=True,
                capture_output=True,
            )
            self.assertTrue(
                (output / "op-go.asc")
                .read_text()
                .startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            )
            self.assertNotEqual(
                subprocess.run(
                    command, env=environment, capture_output=True, check=False
                ).returncode,
                0,
            )


if __name__ == "__main__":
    unittest.main()
