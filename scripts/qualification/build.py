#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Build source-pinned qualification executables without replacing installed CLIs.

All builds run in an archive of a committed revision. macOS uses the repository
signing script and the same identity/identifier/entitlements for the opt-in probe.
Instrumented executables are separate and must never be distributed as releases.
The output directory must not exist; it contains private build logs and metadata.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ref", default="HEAD", help="committed source revision")
    args = parser.parse_args()
    if platform.system() not in ("Darwin", "Linux"):
        parser.error("only macOS and Linux are supported")
    output = args.output.resolve()
    if output.exists():
        parser.error("output must be a new directory")
    revision = subprocess.check_output(
        ["git", "rev-parse", "--verify", args.ref + "^{commit}"], cwd=ROOT, text=True
    ).strip()
    epoch = int(
        subprocess.check_output(
            ["git", "show", "-s", "--format=%ct", revision], cwd=ROOT, text=True
        )
    )
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    os.umask(0o077)
    output.mkdir(parents=True)
    source = output / "source"
    source.mkdir()
    subprocess.run(
        ["git", "archive", "--format=tar", "-o", str(output / "source.tar"), revision],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(["tar", "-xf", output / "source.tar", "-C", source], check=True)
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("OP_SERVICE_ACCOUNT_TOKEN", "EXTISM_ENABLE_WASI_OUTPUT", "GOFLAGS")
        and not k.startswith("OP_GO_QUALIFICATION_")
    }
    env.update(OP_GO_VERSION="0.1.0-dev", OP_GO_COMMIT=revision, OP_GO_DATE=date)
    manifest = {
        "commit": revision,
        "date": date,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "builds": [],
        "go": subprocess.check_output(["go", "version"], env=env, text=True).strip(),
    }
    log = output / "build.log"

    def run(command, extra=None):
        with log.open("ab") as stream:
            subprocess.run(
                [str(x) for x in command],
                cwd=source,
                env={**env, **(extra or {})},
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=True,
            )

    def sign(binary):
        identity = env.get("MACOS_SIGNING_IDENTITY", "Developer ID Application")
        run(
            [
                "codesign",
                "--force",
                "--sign",
                identity,
                "--identifier",
                "com.github.curtisgalloway.op-go",
                "--options",
                "runtime",
                "--timestamp",
                "--entitlements",
                source / "scripts/macos-entitlements.plist",
                binary,
            ]
        )
        run(["codesign", "--verify", "--strict", binary])
        result = subprocess.run(
            ["codesign", "-dvvv", binary], capture_output=True, text=True, check=True
        )
        if not all(
            s in result.stderr
            for s in (
                "Authority=Developer ID Application:",
                "TeamIdentifier=",
                "runtime",
                "Timestamp=",
            )
        ):
            raise RuntimeError("probe signing did not meet candidate protections")

    def record(name, instrumented=False):
        path = output / name
        manifest["builds"].append(
            {
                "file": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "instrumented": instrumented,
            }
        )
        print("Built:", name, flush=True)

    try:
        for name, overlay in [
            ("baseline", None),
            ("candidate", None),
            ("instrumented", output / "overlay/overlay.json"),
        ]:
            env["OP_GO_VERSION"] = "0.0.0-dev" if name == "baseline" else "0.1.0-dev"
            if overlay:
                run(
                    [
                        sys.executable,
                        "scripts/qualification/prepare.py",
                        output / "overlay",
                    ]
                )
            flags = "-buildvcs=false" + (" -overlay=" + str(overlay) if overlay else "")
            if platform.system() == "Darwin":
                run(["bash", "scripts/build-macos.sh"], {"GOFLAGS": flags})

                shutil.copy2(source / "bin/op-go", output / name)
            else:
                package = "github.com/curtisgalloway/op-go/internal/cli"
                version = env["OP_GO_VERSION"]
                ldflags = (
                    f"-X {package}.Version={version} "
                    f"-X {package}.Commit={revision} -X {package}.Date={date}"
                )
                run(
                    [
                        "go",
                        "build",
                        "-trimpath",
                        "-ldflags",
                        ldflags,
                        "-o",
                        output / name,
                        "./cmd/op-go",
                    ],
                    {"CGO_ENABLED": "0", "GOFLAGS": flags},
                )
            record(name, bool(overlay))
        for name, package in [
            ("probe", "./scripts/qualification/probe"),
            ("transport-probe", "./scripts/qualification/transportcheck"),
        ]:
            run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-buildvcs=false",
                    "-o",
                    output / name,
                    package,
                ]
            )
            if platform.system() == "Darwin":
                sign(output / name)
            record(name)
        run(
            [
                sys.executable,
                "scripts/smoke-release.py",
                output / "candidate",
                "0.1.0-dev",
            ]
        )
        manifest["offline_smoke"] = "PASS"
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print("Manifest:", output / "manifest.json")
    except subprocess.CalledProcessError:
        print("Build failed; inspect the private build log:", log, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
