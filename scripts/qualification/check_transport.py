#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Reproduce the handshake-stall mistake and verify the repaired opaque relay.

No real credentials or external network are used. The Go probe serves TLS on
loopback and trusts only that disposable server's certificate for this test.
"""

import argparse
from functools import partial
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile

from network import Bridge, Relay, set_mode


def connect_fixture(destination, address, timeout):
    """Redirect the fixture's allowed hostname exclusively to its local server."""
    assert address == ("test.1password.com", 443)
    return socket.create_connection(("localhost", destination["port"]), timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="op-go-transport-check-") as directory:
            root = Path(directory)
            for mode, seconds in [
                ("handshake-stall", 30),
                ("stall", 30),
                ("stall", 5),
                ("pass", 30),
            ]:
                set_mode(root / "mode", mode)
                destination = {}

                relay = Relay(
                    root / "relay",
                    root / "mode",
                    root / "stats",
                    connector=partial(connect_fixture, destination),
                )
                bridge = Bridge(root / "relay")
                process = None
                try:
                    process = subprocess.Popen(
                        [
                            str(args.probe),
                            "--proxy",
                            f"http://localhost:{bridge.port}",
                            "--deadline",
                            f"{seconds}s",
                        ],
                        env={
                            k: v
                            for k, v in os.environ.items()
                            if k != "OP_SERVICE_ACCOUNT_TOKEN"
                        },
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    )
                    if not select.select([process.stdout], [], [], 5)[0]:
                        raise RuntimeError("TLS probe startup timeout")
                    destination.update(json.loads(process.stdout.readline()))
                    out, _ = process.communicate(b"start\n", timeout=seconds + 10)
                    result = json.loads(out)
                    result.update(
                        mode=mode,
                        requested_deadline=seconds,
                        counters=dict(relay.counters),
                    )
                    if mode == "handshake-stall":
                        ok = (
                            not result["tls_verified"]
                            and not result["context_expired"]
                            and 9 <= result["seconds"] <= 12
                        )
                    elif mode == "stall":
                        ok = (
                            result["tls_verified"]
                            and result["request_written"]
                            and result["context_expired"]
                            and seconds - 0.5 <= result["seconds"] <= seconds + 5
                        )
                    else:
                        ok = (
                            result["success"]
                            and result["tls_verified"]
                            and result["request_written"]
                        )
                    result["result"] = (
                        "PASS" if ok and process.returncode == 0 else "FAIL"
                    )
                    results.append(result)
                    print(
                        result["result"] + ": " + mode + " " + str(seconds) + "s",
                        flush=True,
                    )
                    if result["result"] != "PASS":
                        return 1
                finally:
                    if process and process.poll() is None:
                        process.kill()
                        process.wait()
                    bridge.close()
                    relay.close()
        return 0
    finally:
        args.report.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
