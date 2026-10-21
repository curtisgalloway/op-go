#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name
"""Opt-in real GNOME Keyring checks on a private bus; never use desktop stores.

Run --synthetic first, then --live from a local terminal. Only op-go reads the
live token, with terminal echo disabled. No captured subprocess output is logged.
Each run stops its private daemons and deletes its disposable encrypted store,
even on failure. A killed controller may leave that store: its path and daemon
PIDs are recorded in the private report for recovery. Never use these cleanup
instructions against the desktop service. No software is installed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time


class Validation:
    """Own disposable services, bounded checks, and secret-free reports."""

    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="op-go-isolated-"))
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("OP_")
            and k
            not in (
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "GNOME_KEYRING_CONTROL",
                "DBUS_SESSION_BUS_ADDRESS",
                "EXTISM_ENABLE_WASI_OUTPUT",
            )
        }
        self.env.update(
            HOME=str(self.root),
            XDG_DATA_HOME=str(self.root / "data"),
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_RUNTIME_DIR=str(self.root / "runtime"),
        )
        (self.root / "runtime").mkdir(mode=0o700)
        self.password = secrets.token_hex(32).encode()
        self.token = ("synthetic-op-go-" + secrets.token_hex(32)).encode()
        self.report = {
            "checks": [],
            "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "temporary_store": str(self.root),
            "mode": "live" if args.live else "synthetic",
            "cleanup": False,
        }
        self.bus = self.daemon = None
        self.active = None

    def record(self, name, ok, **details):
        self.report["checks"].append(
            dict(name=name, result="PASS" if ok else "FAIL", **details)
        )
        print(("PASS: " if ok else "FAIL: ") + name, flush=True)
        if not ok:
            raise RuntimeError(name)

    def run(self, name, arguments, expected=0, data=None, terminal=False, limit=15):
        settings = termios.tcgetattr(0) if os.isatty(0) else None
        start = time.monotonic()
        process = subprocess.Popen(
            [str(a) for a in arguments],
            env=self.env,
            stdin=None if terminal else subprocess.PIPE,
            stdout=None if terminal else subprocess.PIPE,
            stderr=None if terminal else subprocess.PIPE,
        )
        self.active = process
        stop = threading.Event()
        samples, leaks = [], []

        def inspect():
            while not stop.is_set():
                pending = [process.pid]
                while pending:
                    pid = pending.pop()
                    base = Path("/proc") / str(pid)
                    try:
                        pending.extend(
                            map(
                                int,
                                (base / "task" / str(pid) / "children")
                                .read_text()
                                .split(),
                            )
                        )
                        for field in ("cmdline", "environ"):
                            content = (base / field).read_bytes()
                            samples.append(pid)
                            if self.token in content:
                                leaks.append(True)
                    except (OSError, ValueError):
                        pass
                stop.wait(0.001)

        monitor = None
        if not self.args.live:
            monitor = threading.Thread(target=inspect)
            monitor.start()
        try:
            out, err = process.communicate(data, timeout=limit)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            self.active = None
            stop.set()
            if monitor:
                monitor.join()
            if settings:
                termios.tcsetattr(0, termios.TCSANOW, settings)
        elapsed = time.monotonic() - start
        self.record(
            name,
            process.returncode == expected,
            status=process.returncode,
            seconds=round(elapsed, 3),
        )
        if monitor:
            self.record(
                name + " synthetic process sampling",
                bool(samples) and not leaks,
                samples=len(samples),
            )
            self.record(
                name + " synthetic output redaction",
                self.token not in (out or b"") + (err or b""),
            )
        return out, elapsed

    def cli(self, name, args, **kwargs):
        return self.run(name, [self.args.binary, *args], **kwargs)

    def buscall(self, method, *args):
        out, _ = self.run(
            method,
            [
                "gdbus",
                "call",
                "--address",
                self.env["DBUS_SESSION_BUS_ADDRESS"],
                "--dest",
                "org.freedesktop.secrets",
                "--object-path",
                "/org/freedesktop/secrets",
                "--method",
                "org.freedesktop.Secret.Service." + method,
                *args,
            ],
        )
        return out.decode()

    def unlock(self, name, password=None, interrupt=None):
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [str(self.args.binary), "unlock"],
            env=self.env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
        )
        self.active = process
        output = b""
        try:
            deadline = time.monotonic() + 10
            while (
                b"GNOME login keyring password: " not in output
                or termios.tcgetattr(slave)[3] & termios.ECHO
            ):
                if time.monotonic() > deadline or process.poll() is not None:
                    raise RuntimeError("hidden unlock prompt unavailable")
                if select.select([master], [], [], 0.05)[0]:
                    output += os.read(master, 4096)
            if interrupt:
                process.send_signal(interrupt)
            else:
                os.write(master, password + b"\n")
            code = process.wait(timeout=10)
            while select.select([master], [], [], 0)[0]:
                output += os.read(master, 4096)
            expected = (
                -interrupt if interrupt else (0 if password == self.password else 11)
            )
            self.record(
                name,
                code == expected
                and bool(termios.tcgetattr(slave)[3] & termios.ECHO)
                and self.password not in output
                and output.count(b"GNOME login keyring password: ") == 1,
                status=code,
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            self.active = None
            os.close(master)
            os.close(slave)

    def start(self):
        policy = (
            '<deny send_destination="org.freedesktop.secrets" '
            'send_interface="org.freedesktop.Secret.Item" send_member="GetSecret"/>'
            if self.args.deny
            else ""
        )
        config = self.root / "bus.conf"
        config.write_text(
            "<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen>"
            '<auth>EXTERNAL</auth><policy context="default">'
            '<allow send_destination="*"/><allow receive_sender="*"/>'
            '<allow own="*"/>' + policy + "</policy></busconfig>"
        )
        self.bus = subprocess.Popen(
            [
                "dbus-daemon",
                "--nofork",
                "--print-address=1",
                "--config-file=" + str(config),
            ],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if not select.select([self.bus.stdout], [], [], 10)[0]:
            raise RuntimeError("private bus startup deadline")
        self.env["DBUS_SESSION_BUS_ADDRESS"] = (
            self.bus.stdout.readline().decode().strip()
        )
        self.daemon = subprocess.Popen(
            [
                "gnome-keyring-daemon",
                "--foreground",
                "--unlock",
                "--components=secrets",
                "--control-directory",
                str(self.root / "control"),
            ],
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.daemon.stdin.write(self.password)
        self.daemon.stdin.close()
        self.report.update(bus_pid=self.bus.pid, keyring_pid=self.daemon.pid)
        self.args.report.write_text(json.dumps(self.report, indent=2) + "\n")
        time.sleep(1)
        output = self.buscall("ReadAlias", "default")
        match = re.fullmatch(r"\(objectpath '(/[A-Za-z0-9_/]+)',\)\s*", output)
        self.record(
            "isolated default login collection",
            bool(match) and output == self.buscall("ReadAlias", "login"),
        )
        self.collection = match.group(1)
        self.cli("initial enrollment absent", ["doctor", "--json"], expected=3)

    def validate(self):
        refs = self.root / "reference.env"
        refs.write_text("TEST_VALUE=op://Test Vault/API Credentials/username\n")
        marker = self.root / "child-executed"
        fail_child = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",
            str(marker),
        ]
        self.env.update(
            OP_CONNECT_TOKEN="harmless-filter-test",
            OP_SESSION_TEST="harmless-filter-test",
        )

        def delivery(name):
            code = (
                'import os,sys; good=os.environ.get("TEST_VALUE")=="op-go-test-value"; '
                'clean=not any(k in ("OP_SERVICE_ACCOUNT_TOKEN","OP_CONNECT_TOKEN") '
                'or k.startswith("OP_SESSION_") for k in os.environ); '
                "sys.exit(0 if good and clean else 1)"
            )
            self.cli(
                name,
                ["run", "--env-file", refs, "--", sys.executable, "-c", code],
                limit=45,
            )

        if self.args.live:
            print(
                "Enter the dedicated TEST service-account token only at "
                "op-go's hidden prompt.",
                flush=True,
            )
            self.cli("hidden enrollment", ["enroll"], terminal=True, limit=300)
        else:
            self.cli("synthetic enrollment", ["enroll", "--stdin"], data=self.token)
        self.cli("metadata after enrollment", ["doctor", "--json"])
        if self.args.deny:
            self.cli(
                "real keyring policy denial",
                ["run", "--env-file", refs, "--", *fail_child],
                expected=12,
            )
            self.record("denial prevents child execution", not marker.exists())
        elif self.args.live:
            delivery("exact live value and auth filtering")
            print("At the overwrite prompt enter no.", flush=True)
            self.cli(
                "overwrite declined", ["enroll"], expected=2, terminal=True, limit=300
            )
            delivery("declined overwrite preserves live enrollment")
            print("Approve overwrite with yes; enter the test token again.", flush=True)
            self.cli("replacement", ["enroll"], terminal=True, limit=300)
            delivery("live delivery after replacement")
        else:
            self.cli(
                "synthetic retrieval authentication refusal",
                ["run", "--env-file", refs, "--", *fail_child],
                expected=10,
                limit=45,
            )
            self.record("authentication refusal prevents child", not marker.exists())

        if not self.args.deny:
            self.buscall("Lock", "['" + self.collection + "']")
            self.cli("locked doctor", ["doctor", "--json"], expected=11, limit=10)
            self.cli(
                "locked run",
                ["run", "--env-file", refs, "--", *fail_child],
                expected=11,
                limit=10,
            )
            self.record("locked run prevents child", not marker.exists())
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                self.unlock(
                    "unlock interruption restores echo " + sig.name, interrupt=sig
                )
            self.unlock(
                "one incorrect password without retry",
                password=b"incorrect-disposable-password",
            )
            self.cli(
                "still locked after wrong password", ["doctor", "--json"], expected=11
            )
            self.unlock("separate correct password unlock", password=self.password)
            if self.args.live:
                delivery("live delivery after unlock")
                print("At the removal prompt enter no.", flush=True)
                self.cli(
                    "removal declined", ["remove"], expected=2, terminal=True, limit=300
                )
                delivery("declined removal preserves live enrollment")
            self.daemon.send_signal(signal.SIGSTOP)
            try:
                _, elapsed = self.cli(
                    "actually stalled Secret Service request",
                    ["doctor", "--json"],
                    expected=20,
                    limit=12,
                )
                self.record("store deadline near five seconds", 4 <= elapsed <= 9)
            finally:
                self.daemon.send_signal(signal.SIGCONT)
        self.cli("approved removal", ["remove", "--yes"])
        self.cli("missing enrollment after removal", ["doctor", "--json"], expected=3)

    def close(self):
        if self.active and self.active.poll() is None:
            self.active.kill()
            self.active.wait()
        for process in (self.daemon, self.bus):
            if process and process.poll() is None:
                process.send_signal(signal.SIGCONT)
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        shutil.rmtree(self.root)
        self.report["cleanup"] = True
        self.args.report.write_text(json.dumps(self.report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synthetic", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--deny", action="store_true")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    args.report = args.report.resolve()
    if args.live and (not os.isatty(0) or args.deny):
        parser.error("live mode needs a local terminal and cannot use --deny")
    os.umask(0o077)
    validation = Validation(args)
    settings = termios.tcgetattr(0) if os.isatty(0) else None

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        validation.start()
        validation.validate()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        print(
            "INCOMPLETE: stopped; see check statuses. No authentication retry.",
            flush=True,
        )
        validation.report["result"] = "INCOMPLETE"
        return 1
    else:
        validation.report["result"] = "PASS_FOR_COVERED_CHECKS"
        return 0
    finally:
        validation.close()
        if settings:
            termios.tcsetattr(0, termios.TCSANOW, settings)
        print(
            "Private keyring deleted and private daemons stopped. Desktop unchanged.",
            flush=True,
        )
        print("Report:", args.report, flush=True)


if __name__ == "__main__":
    sys.exit(main())
