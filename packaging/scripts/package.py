#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Package a prebuilt executable without changing its bytes or signature."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

TARGETS = {
    "darwin-universal": "all",
    "linux-amd64": "x86_64_linux",
    "linux-arm64": "arm64_linux",
}
ROOT = Path(__file__).resolve().parents[2]
RELEASES = "https://github.com/curtisgalloway/op-go/releases/download"


def checksum(path):
    """Write a portable sha256sum sidecar using only the asset basename."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(
        f"{digest}  {path.name}\n", encoding="utf-8"
    )
    return digest


def archive(path, entries):
    """Write normalized tar metadata; do not copy usernames or xattrs."""
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(
                fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT
            ) as tar:
                for name, (data, mode) in sorted(entries.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.mode = mode
                    tar.addfile(entry, io.BytesIO(data))
    return checksum(path)


def bottle_formula(version, target, digest):
    """Record the formula corresponding to this bottle's binary archive."""
    return f"""class OpGo < Formula
  desc "Launch commands with secrets resolved through the 1Password SDK"
  homepage "https://github.com/curtisgalloway/op-go"
  url "{RELEASES}/v{version}/op-go-v{version}-{target}.tar.gz"
  version "{version}"
  sha256 "{digest}"
  license "Apache-2.0"

  def install
    bin.install "op-go"
    doc.install "README.md", "LICENSE"
  end

  test do
    assert_match "op-go {version}", shell_output("#{{bin}}/op-go --version")
  end
end
""".encode()


def debian(version, target, binary, output):
    """Build an unprivileged Debian package with root ownership metadata."""
    arch = target.removeprefix("linux-")
    with tempfile.TemporaryDirectory(prefix="op-go-deb-") as temporary:
        stage = Path(temporary)
        (stage / "DEBIAN").mkdir()
        (stage / "usr/bin").mkdir(parents=True)
        docs = stage / "usr/share/doc/op-go"
        docs.mkdir(parents=True)
        executable = stage / "usr/bin/op-go"
        executable.write_bytes(binary)
        executable.chmod(0o755)
        shutil.copyfile(ROOT / "LICENSE", docs / "copyright")
        shutil.copyfile(ROOT / "README.md", docs / "README.md")
        (stage / "DEBIAN/control").write_text(
            f"Package: op-go\nVersion: {version}\nArchitecture: {arch}\n"
            "Section: utils\nPriority: optional\n"
            "Maintainer: Curtis Galloway <curtisgalloway@users.noreply.github.com>\n"
            "Homepage: https://github.com/curtisgalloway/op-go\n"
            "Description: Launch commands with secrets from the 1Password SDK\n"
            " Credentials use explicit operating-system or protected-file backends.\n",
            encoding="utf-8",
        )
        # TemporaryDirectory is private, but the installed filesystem root must not be.
        stage.chmod(0o755)
        for path in stage.rglob("*"):
            path.chmod(0o755 if path.is_dir() or path == executable else 0o644)
        result = output / f"op-go_{version}_{arch}.deb"
        subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", str(stage), str(result)],
            check=True,
            env={**os.environ, "SOURCE_DATE_EPOCH": "0"},
        )
        checksum(result)


def main():
    """Build an archive, a Homebrew bottle, and (on Linux) a Debian package."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="stable version X.Y.Z, without v")
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.version
    ):
        parser.error("version must be a stable X.Y.Z without leading zeros")
    if not args.binary.is_file() or args.binary.is_symlink():
        parser.error("binary must be a regular file, not a symlink")
    if not os.access(args.binary, os.X_OK):
        parser.error("binary must be executable")
    if args.target.startswith("linux-") and not shutil.which("dpkg-deb"):
        parser.error("Linux packaging requires dpkg-deb")
    args.output.mkdir(parents=True, exist_ok=True)
    archive_name = f"op-go-v{args.version}-{args.target}.tar.gz"
    bottle_name = f"op-go-{args.version}.{TARGETS[args.target]}.bottle.tar.gz"
    names = [archive_name, bottle_name]
    if args.target.startswith("linux-"):
        arch = args.target.removeprefix("linux-")
        names.append(f"op-go_{args.version}_{arch}.deb")
    for name in names:
        if any((args.output / (name + suffix)).exists() for suffix in ("", ".sha256")):
            parser.error("output asset already exists; use an empty staging directory")
    binary = args.binary.read_bytes()
    docs = {name: (ROOT / name).read_bytes() for name in ("README.md", "LICENSE")}
    prefix = f"op-go-{args.version}"
    entries = {f"{prefix}/op-go": (binary, 0o755)}
    entries.update({f"{prefix}/{name}": (data, 0o644) for name, data in docs.items()})
    digest = archive(args.output / archive_name, entries)
    keg = f"op-go/{args.version}"
    entries = {
        f"{keg}/bin/op-go": (binary, 0o755),
        f"{keg}/LICENSE": (docs["LICENSE"], 0o644),
        f"{keg}/share/doc/op-go/README.md": (docs["README.md"], 0o644),
        f"{keg}/share/doc/op-go/LICENSE": (docs["LICENSE"], 0o644),
        f"{keg}/.brew/op-go.rb": (
            bottle_formula(args.version, args.target, digest),
            0o644,
        ),
    }
    archive(args.output / bottle_name, entries)
    if args.target.startswith("linux-"):
        debian(args.version, args.target, binary, args.output)
    print(f"Packaged op-go {args.version} for {args.target}")


if __name__ == "__main__":
    main()
