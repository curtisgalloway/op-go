#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Exercise a packaged CLI offline with disposable, fake file credentials."""

# pylint: disable=invalid-name

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def smoke(binary, version, directory):
    """Check public commands and the private worker without accessing real stores."""
    environment = {
        "PATH": os.defpath,
        "HOME": str(directory),
        "TMPDIR": str(directory),
        "LANG": "C",
    }

    def run(*arguments, status=0, extra_env=None):
        result = subprocess.run(
            [str(binary), *map(str, arguments)],
            env={**environment, **(extra_env or {})},
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != status:
            # Keep unexpected-failure diagnostics bounded and credential-free.
            raise RuntimeError(
                f"{arguments[0]} returned {result.returncode}; expected {status}"
            )
        return result.stdout

    if not run("--version").startswith(f"op-go {version} ("):
        raise RuntimeError("packaged version does not match the release")
    if "op-go run" not in run("--help"):
        raise RuntimeError("help is missing launcher usage")
    if "op-go" not in run("--skill"):
        raise RuntimeError("embedded skill is missing")

    token = directory / "fake-token"
    token.write_text("fake-release-smoke-token", encoding="utf-8")
    token.chmod(0o600)
    backend = ["--backend", "file", "--token-file", str(token)]
    doctor = json.loads(run("doctor", *backend, "--json"))
    if not doctor.get("ok") or not doctor.get("enrolled") or doctor.get("online_check"):
        raise RuntimeError("offline file metadata check failed")
    token.chmod(0o644)
    run("doctor", *backend, "--json", status=12)
    token.chmod(0o600)

    env_file = directory / "smoke.env"
    env_file.write_text(
        "APP_SECRET=op://example-vault/example-item/key\nAPP_LITERAL=release-smoke\n",
        encoding="utf-8",
    )
    report = json.loads(
        run("dry-run", *backend, "--env-file", env_file, "--json", "--", "/bin/sh")
    )
    if report.get("reference_keys") != ["APP_SECRET"] or set(
        report.get("keys", [])
    ) != {
        "APP_SECRET",
        "APP_LITERAL",
    }:
        raise RuntimeError("dry-run reported incorrect environment keys")
    env_file.write_text("APP_LITERAL=release-smoke\n", encoding="utf-8")
    run(
        "run",
        *backend,
        "--env-file",
        env_file,
        "--",
        "/bin/sh",
        "-c",
        'test "$APP_LITERAL" = release-smoke || exit 90; '
        'test "${OP_CONNECT_TOKEN+x}" != x || exit 91; '
        'test "${OP_SESSION_release_smoke+x}" != x || exit 92; '
        'test "${OP_SERVICE_ACCOUNT_TOKEN+x}" != x || exit 93; exit 42',
        status=42,
        extra_env={"OP_CONNECT_TOKEN": "fake", "OP_SESSION_release_smoke": "fake"},
    )
    # Supplying even a fake inherited service-account token must fail closed.
    run(
        "run",
        *backend,
        "--env-file",
        env_file,
        "--",
        "/bin/sh",
        "-c",
        "exit 99",
        status=12,
        extra_env={"OP_SERVICE_ACCOUNT_TOKEN": "fake"},
    )


def main():
    """Run smoke checks against the exact installed executable."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("version")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="op-go-smoke-") as temporary:
        smoke(args.binary.resolve(), args.version, Path(temporary))
    print(
        "PASS: version, help, skill, file worker, permissions, "
        "dry-run, exec, auth filtering"
    )


if __name__ == "__main__":
    main()
