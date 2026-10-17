# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Check release layouts, exact binary preservation, and fail-closed inputs."""

import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PackagingTest(unittest.TestCase):
    """Use a fake executable; packaging never executes the input binary."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="op-go-packaging-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.binary = self.directory / "op-go"
        self.binary.write_bytes(b"#!/bin/sh\nexit 99\n")
        self.binary.chmod(0o755)
        self.output = self.directory / "dist"

    def package(self, version="1.2.3", target="darwin-universal", binary=None):
        """Invoke the same script used by the release workflow."""
        return subprocess.run(
            [
                "bash",
                str(ROOT / "packaging/scripts/package.sh"),
                version,
                target,
                str(binary or self.binary),
                str(self.output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def verify_checksums(self):
        """Each asset has a sidecar compatible with sha256sum --check."""
        for path in self.output.iterdir():
            if path.suffix == ".sha256":
                continue
            expected = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            self.assertEqual(
                path.with_name(path.name + ".sha256").read_text(), expected
            )

    def test_archives_preserve_binary_and_normalize_metadata(self):
        result = self.package()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.verify_checksums()
        layouts = {
            "op-go-v1.2.3-darwin-universal.tar.gz": "op-go-1.2.3/op-go",
            "op-go-1.2.3.all.bottle.tar.gz": "op-go/1.2.3/bin/op-go",
        }
        for name, executable in layouts.items():
            with tarfile.open(self.output / name) as archive:
                self.assertEqual(
                    archive.extractfile(executable).read(), self.binary.read_bytes()
                )
                self.assertEqual(archive.getmember(executable).mode, 0o755)
                for member in archive:
                    self.assertEqual(
                        (member.uid, member.gid, member.uname, member.gname),
                        (0, 0, "", ""),
                    )
                    self.assertFalse(member.name.startswith("/"))
                    self.assertNotIn("..", Path(member.name).parts)
        with tarfile.open(self.output / "op-go-1.2.3.all.bottle.tar.gz") as archive:
            self.assertIn("op-go/1.2.3/.brew/op-go.rb", archive.getnames())

    def test_invalid_versions_and_targets(self):
        for version in ("v1.2.3", "1.2", "01.2.3", "1.2.3-rc1", "../1.2.3"):
            self.assertEqual(self.package(version=version).returncode, 2)
        self.assertEqual(self.package(target="linux-riscv64").returncode, 2)
        self.assertFalse(self.output.exists())

    def test_rejects_missing_and_symlink_binaries(self):
        self.assertEqual(self.package(binary=self.directory / "missing").returncode, 2)
        link = self.directory / "link"
        link.symlink_to(self.binary)
        self.assertEqual(self.package(binary=link).returncode, 2)

    def test_refuses_overwriting_assets(self):
        self.assertEqual(self.package().returncode, 0)
        previous = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.assertEqual(self.package().returncode, 2)
        self.assertEqual(
            previous, {path.name: path.read_bytes() for path in self.output.iterdir()}
        )

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb required")
    def test_debian_architectures_and_layout(self):
        for arch in ("amd64", "arm64"):
            result = self.package(target=f"linux-{arch}")
            self.assertEqual(result.returncode, 0, result.stderr)
            package = self.output / f"op-go_1.2.3_{arch}.deb"
            field = subprocess.check_output(
                ["dpkg-deb", "-f", str(package), "Architecture"], text=True
            )
            self.assertEqual(field.strip(), arch)
            unpacked = self.directory / arch
            subprocess.run(["dpkg-deb", "-x", str(package), str(unpacked)], check=True)
            self.assertEqual(
                (unpacked / "usr/bin/op-go").read_bytes(), self.binary.read_bytes()
            )
            self.assertTrue((unpacked / "usr/share/doc/op-go/copyright").is_file())
        self.verify_checksums()


if __name__ == "__main__":
    unittest.main()
