#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Qualify signed apt download and native Debian installation in temporary state."""

import argparse
import hashlib
import io
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ("apt-get", "dpkg", "dpkg-deb", "dpkg-scanpackages", "apt-ftparchive", "gpg")


def qualify(assets, version, directory):
    """Run only against a temporary keyring, sources, database, and install root."""
    environment = {
        "PATH": os.defpath + ":/usr/sbin:/sbin",
        "HOME": str(directory),
        "TMPDIR": str(directory),
        "LANG": "C",
        "GNUPGHOME": str(directory / "gnupg"),
    }

    def run(*command):
        return subprocess.check_output(
            list(map(str, command)),
            cwd=directory,
            env=environment,
            text=True,
            stderr=subprocess.STDOUT,
            timeout=180,
        )

    architecture = run("dpkg", "--print-architecture").strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError("apt qualification requires native amd64 or arm64 Linux")
    original = assets / f"op-go_{version}_{architecture}.deb"
    if not original.is_file():
        raise RuntimeError("native release package is missing")
    Path(environment["GNUPGHOME"]).mkdir(mode=0o700)
    run(
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
    )
    listing = run("gpg", "--batch", "--with-colons", "--list-secret-keys")
    fingerprint = next(
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    )
    repository = directory / "repository"
    run(
        "bash",
        ROOT / "packaging/scripts/build-apt-repo.sh",
        assets,
        repository,
        fingerprint,
    )

    state = directory / "state"
    cache = directory / "cache"
    etc = directory / "etc"
    log = directory / "log"
    installed = directory / "installed"
    for path in (
        state / "lists/partial",
        cache / "archives/partial",
        log,
        etc / "apt.conf.d",
        etc / "sources.list.d",
        etc / "trusted.gpg.d",
        etc / "preferences.d",
        installed / "var/lib/dpkg",
    ):
        path.mkdir(parents=True)
    status = installed / "var/lib/dpkg/status"
    status.touch()
    (etc / "sources.list").write_text(
        f"deb [arch={architecture} signed-by={repository}/op-go.asc] "
        f"{repository.as_uri()} stable main\n",
        encoding="utf-8",
    )
    configuration = directory / "apt.conf"
    # APT_CONFIG is read BEFORE system configuration. Redirect main and parts here
    # so host update hooks and extra sources cannot load in the first place.
    configuration.write_text(
        f'Dir::Etc "{etc}";\n'
        'Dir::Etc::main "apt.conf";\n'
        'Dir::Etc::parts "apt.conf.d";\n'
        'Dir::Etc::sourcelist "sources.list";\n'
        'Dir::Etc::sourceparts "sources.list.d";\n'
        f'Dir::State "{state}";\n'
        f'Dir::State::status "{status}";\n'
        f'Dir::Cache "{cache}";\n'
        f'Dir::Log "{log}";\n'
        f'APT::Architecture "{architecture}";\n'
        f'APT::Sandbox::User "{pwd.getpwuid(os.geteuid()).pw_name}";\n'
        'APT::Get::AllowUnauthenticated "false";\n'
        'Acquire::AllowInsecureRepositories "false";\n'
        'Acquire::Check-Valid-Until "true";\n',
        encoding="utf-8",
    )
    environment["APT_CONFIG"] = str(configuration)
    run("apt-get", "update", "--error-on=any")
    run("apt-get", "download", f"op-go:{architecture}={version}")
    downloads = list(directory.glob("*.deb"))
    if len(downloads) != 1:
        raise RuntimeError("apt did not download exactly one native package")
    package = downloads[0]
    if (
        hashlib.sha256(package.read_bytes()).digest()
        != hashlib.sha256(original.read_bytes()).digest()
    ):
        raise RuntimeError("apt downloaded a different package")
    control = subprocess.check_output(
        ["dpkg-deb", "--ctrl-tarfile", str(package)],
        env=environment,
        cwd=directory,
    )
    with tarfile.open(fileobj=io.BytesIO(control)) as archive:
        for entry in archive:
            if entry.isdir():
                continue
            if entry.name.removeprefix("./") not in ("control", "md5sums"):
                raise RuntimeError(
                    "package contains unexpected control scripts or triggers"
                )
    # No sudo and no host database. Packages have no maintainer scripts or triggers.
    # A failed install fails qualification; extraction is not an equivalent check.
    dpkg_log = log / "dpkg.log"
    run(
        "dpkg",
        "--force-not-root",
        f"--root={installed}",
        f"--log={dpkg_log}",
        "--install",
        package,
    )
    if "Status: install ok installed" not in status.read_text(encoding="utf-8"):
        raise RuntimeError("temporary dpkg database does not record installation")
    run(
        sys.executable,
        ROOT / "scripts/smoke-release.py",
        installed / "usr/bin/op-go",
        version,
    )


def main():
    """Qualify release assets without using host apt state or credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "assets", type=Path, help="directory with both Linux .deb files"
    )
    parser.add_argument("version")
    args = parser.parse_args()
    if not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.version
    ):
        parser.error("version must be a stable X.Y.Z without leading zeros")
    missing = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing:
        parser.error("required tools are missing: " + ", ".join(missing))
    try:
        # A predictable parent without spaces avoids apt's unquoted source URI syntax.
        with tempfile.TemporaryDirectory(prefix="op-go-apt-smoke-", dir="/tmp") as temp:
            qualify(args.assets.resolve(), args.version, Path(temp))
    except subprocess.CalledProcessError as error:
        parser.exit(
            1,
            f"apt qualification command failed ({error.returncode}):\n{error.output}\n",
        )
    print("PASS: signed apt download, temporary dpkg installation, installed CLI smoke")


if __name__ == "__main__":
    main()
