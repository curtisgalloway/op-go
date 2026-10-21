#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Opt-in Linux qualification. --inside is run in a disposable network namespace.

Only the relay controller uses the host network. The privileged operation creates
an empty network namespace, enables its loopback, then drops to the caller's UID
before starting any credential code. No host firewall, DNS, or desktop bus changes.
"""

import argparse
import importlib.util
import json
import os
import pty
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
import urllib.error
import urllib.request

from network import Bridge, Observer, Relay, set_mode

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "real_keyring", ROOT / "scripts/validate-linux-real.py"
)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Qualification(base.Validation):
    """Reuse the real-keyring lifecycle, adding bounded independent checks."""

    def __init__(self, args, shared):
        super().__init__(args)
        self.shared = shared
        self.canceled_workers = set()
        self.observer = Observer(self.root / "observer", shared / "mode")
        self.observer.process_getter = lambda: self.active
        self.observer.token = self.token if not args.live else b""
        self.bridge = Bridge(shared / "relay") if args.live else None
        self.report["instrumented_binary"] = str(args.instrumented)
        self.env["OP_GO_QUALIFICATION_SOCKET"] = str(self.observer.path)
        if self.bridge:
            for key in list(self.env):
                if key.lower().endswith("_proxy"):
                    self.env.pop(key)
            self.env.update(
                HTTPS_PROXY=f"http://localhost:{self.bridge.port}",
                HTTP_PROXY=f"http://localhost:{self.bridge.port}",
                NO_PROXY="",
            )

    def run(self, name, arguments, expected=0, data=None, terminal=False, limit=15):
        settings = termios.tcgetattr(0) if os.isatty(0) else None
        started = time.monotonic()
        before = len(self.observer.events)
        process = subprocess.Popen(
            [str(a) for a in arguments],
            env=self.env,
            stdin=None if terminal else subprocess.PIPE,
            stdout=None if terminal else subprocess.PIPE,
            stderr=None if terminal else subprocess.PIPE,
        )
        self.active = self.observer.process = process
        stop = threading.Event()
        observed, exposed = set(), []

        def sample():
            while not stop.is_set():
                pending = [process.pid]
                seen = set()
                while pending:
                    pid = pending.pop()
                    if pid in seen:
                        continue
                    seen.add(pid)
                    proc = Path("/proc") / str(pid)
                    try:
                        for task in (proc / "task").iterdir():
                            pending.extend(
                                map(int, (task / "children").read_text().split())
                            )
                        for field in ("cmdline", "environ"):
                            data = (proc / field).read_bytes()
                            if self.observer.token and self.observer.token in data:
                                exposed.append(True)
                        observed.add(pid)
                    except OSError:
                        pass
                stop.wait(0.001)

        monitor = threading.Thread(target=sample)
        monitor.start()
        try:
            out, err = process.communicate(data, timeout=limit)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            self.active = self.observer.process = None
            stop.set()
            monitor.join()
            if settings:
                termios.tcsetattr(0, termios.TCSANOW, settings)
        elapsed = time.monotonic() - started
        events = self.observer.events[before:]
        category = {
            0: "success",
            2: "usage-or-consent",
            3: "missing-precondition",
            10: "authentication",
            11: "locked",
            12: "denied",
            20: "operation-failed-or-timeout",
            23: "rate-limit",
        }.get(process.returncode, "other")
        self.report.setdefault("operations", []).append(
            {
                "name": name,
                "expected_status": expected,
                "actual_status": process.returncode,
                "seconds": round(elapsed, 3),
                "category": category,
                "observed_pids": sorted(observed),
                "surviving_observed_pids": sorted(
                    pid for pid in observed if Path("/proc", str(pid)).exists()
                ),
                "checkpoint_phases": sorted({e["phase"] for e in events}),
                "sampled_token_exposure": bool(exposed),
                "output_token_exposure": bool(
                    self.observer.token
                    and self.observer.token in (out or b"") + (err or b"")
                ),
            }
        )
        self.record(
            name,
            (
                process.returncode in expected
                if isinstance(expected, tuple)
                else process.returncode == expected
            ),
            status=process.returncode,
            category=category,
            seconds=round(elapsed, 3),
        )
        if self.observer.token:
            self.record(
                name + " output redaction",
                self.observer.token not in (out or b"") + (err or b""),
            )
            self.record(
                name + " process-tree samples",
                bool(observed) and not exposed,
                process_count=len(observed),
                coverage="sampling only, supplemented by instrumented checkpoints",
            )
        self.record(
            name + " observed descendants exited",
            all(not Path("/proc", str(pid)).exists() for pid in observed),
        )
        if events:
            expected_workers = {
                e["child"] for e in events if e["phase"] == "worker-started"
            }
            received = {
                e["pid"] for e in events if e["phase"].startswith("worker-request-")
            }
            returned = {
                e["pid"] for e in events if e["phase"].startswith("worker-result-")
            }
            self.record(
                name + " synchronized exposure",
                all(e.get("observed") and not e.get("exposed") for e in events),
                phases=sorted({e["phase"] for e in events}),
                workers=len(expected_workers),
            )
            if expected_workers:
                if expected == 20:
                    self.canceled_workers.update(expected_workers - returned)
                self.record(
                    name + " every worker checkpoint",
                    expected_workers == received
                    and expected_workers
                    == returned | (expected_workers & self.canceled_workers),
                )
                self.record(
                    name + " every instrumented worker exited",
                    all(
                        not Path("/proc", str(pid)).exists() for pid in expected_workers
                    ),
                )
        return out, elapsed

    def compare_lookup_failure(self, reference):
        """Compare a non-auth failure with the SDK alone, without retries."""
        last = self.report["checks"][-1]
        if last.get("status") in (10, 23):
            self.report["lookup_comparison"] = "stopped on authentication or rate limit"
            return
        path = self.root / "sdk-reference"
        path.write_text(reference)
        out, _ = self.run(
            "SDK-only comparison completed",
            [self.args.probe, "--reference-file", path],
            expected=(0, 10, 20, 23),
            limit=45,
        )
        self.report["sdk_only_comparison"] = json.loads(out)
        self.report["official_cli_comparison"] = (
            "INCOMPLETE: service-account CLI credential handling must be verified; "
            "no token will be supplied via arguments or environment"
        )

    def load_observer_token(self):
        reader, writer = os.pipe()
        process = subprocess.Popen(
            [str(self.args.probe), "--observer-fd", str(writer)],
            env={
                k: v for k, v in self.env.items() if k != "OP_GO_QUALIFICATION_SOCKET"
            },
            pass_fds=(writer,),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(writer)
        token = b""
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if select.select([reader], [], [], 0.1)[0]:
                    part = os.read(reader, 65536)
                    if not part:
                        break
                    token += part
                    if len(token) > 65536:
                        raise RuntimeError("observer token invalid")
            else:
                raise RuntimeError("observer pipe deadline")
            code = process.wait(timeout=5)
            self.record(
                "private in-memory observer token transport", code == 0 and bool(token)
            )
            self.observer.token = token
        finally:
            os.close(reader)
            if process.poll() is None:
                process.kill()
                process.wait()

    def synthetic_hidden_enroll(self):
        """Exercise hidden input without putting the sentinel in args or env."""
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [str(self.args.instrumented), "enroll"],
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
                b"Service-account token: " not in output
                or termios.tcgetattr(slave)[3] & termios.ECHO
            ):
                if time.monotonic() > deadline or process.poll() is not None:
                    raise RuntimeError("hidden enrollment prompt unavailable")
                if select.select([master], [], [], 0.05)[0]:
                    output += os.read(master, 4096)
            os.write(master, self.token + b"\n")
            code = process.wait(timeout=15)
            while select.select([master], [], [], 0)[0]:
                output += os.read(master, 4096)
            self.record(
                "synthetic hidden enrollment and echo restoration",
                code == 0
                and self.token not in output
                and bool(termios.tcgetattr(slave)[3] & termios.ECHO),
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            self.active = None
            os.close(master)
            os.close(slave)

    def target(self, marker):
        return [
            sys.executable,
            "-c",
            (
                "import os,sys,pathlib,socket,json; "
                'ok=os.environ.get("TEST_VALUE")=="op-go-test-value" and '
                'not any(k in ("OP_SERVICE_ACCOUNT_TOKEN","OP_CONNECT_TOKEN") '
                'or k.startswith("OP_SESSION_") for k in os.environ); '
                "pathlib.Path(sys.argv[1]).touch(); "
                "c=socket.socket(socket.AF_UNIX); "
                'c.connect(os.environ["OP_GO_QUALIFICATION_SOCKET"]); '
                'c.sendall((json.dumps({"Phase":"child-after-exec",'
                '"PID":os.getpid(),"Child":0})+chr(10)).encode()); '
                "ack=c.recv(1); c.close(); sys.exit(0 if ok and ack==bytes([1]) else 1)"
            ),
            str(marker),
        ]

    def stats(self):
        path = self.shared / "stats"
        return (
            json.loads(path.read_text())
            if path.exists()
            else dict(
                connected=0, client_records=0, held_replies=0, application_connections=0
            )
        )

    def additional_checks(self):
        self.load_observer_token()
        ids = json.loads(self.args.ids.read_text())
        variants = [
            ("names-names", "Test Vault", "API Credentials"),
            ("names-ids", "Test Vault", ids["item"]),
            ("ids-names", ids["vault"], "API Credentials"),
            ("ids-ids", ids["vault"], ids["item"]),
        ]
        refs = self.root / "lookup.env"
        marker = self.root / "child-marker"
        for label, vault, item in variants:
            refs.write_text(f"TEST_VALUE=op://{vault}/{item}/username\n")
            for number in range(5):
                marker.unlink(missing_ok=True)
                try:
                    self.cli(
                        f"lookup {label} fresh process {number+1}",
                        ["run", "--env-file", refs, "--", *self.target(marker)],
                        limit=45,
                    )
                except RuntimeError:
                    self.compare_lookup_failure(f"op://{vault}/{item}/username")
                    raise
                time.sleep(1)
        self.report["lookup_conclusion"] = (
            "historical intermittency not reproduced; not proven fixed"
        )
        self.network_checks()

    def stalled_run(self, name, args, timeout, marker):
        """Retain attempt evidence even when the status assertion raises."""
        before = self.stats()
        event_start = len(self.observer.events)
        try:
            return self.cli(name, args, expected=20, limit=timeout + 10)
        finally:
            after = self.stats()
            operation = next(
                (
                    v
                    for v in reversed(self.report.get("operations", []))
                    if v["name"] == name
                ),
                {},
            )
            self.report.setdefault("network_attempts", []).append(
                {
                    "name": name,
                    "requested_deadline": timeout,
                    "before": before,
                    "after": after,
                    "child_marker_present": marker.exists(),
                    "checkpoint_phases": sorted(
                        {e["phase"] for e in self.observer.events[event_start:]}
                    ),
                    "operation": operation,
                }
            )

    def network_checks(self):
        """Affected checks only; no lookup matrix or credential lifecycle replay."""
        refs = self.root / "network.env"
        marker = self.root / "network-child-marker"

        refs.write_text("TEST_VALUE=op://Test Vault/API Credentials/username\n")
        self.cli(
            "candidate pre-stall exact-value control",
            ["run", "--env-file", refs, "--", *self.target(marker)],
            limit=45,
        )
        for timeout in (30, 5):
            marker.unlink(missing_ok=True)
            before = self.stats()
            set_mode(self.shared / "mode", "stall")
            try:
                args = ["run", "--env-file", refs]
                if timeout != 30:
                    args += ["--timeout", f"{timeout}s"]
                _, elapsed = self.stalled_run(
                    f"candidate network stall {timeout}s",
                    [*args, "--", *self.target(marker)],
                    timeout,
                    marker,
                )
                after = self.stats()
                self.record(
                    f"candidate pending network evidence {timeout}s",
                    after["connected"] > before["connected"]
                    and after["client_records"] > before["client_records"]
                    and after["held_replies"] > before["held_replies"]
                    and after["application_connections"]
                    > before["application_connections"]
                    and not marker.exists()
                    and timeout - 0.5 <= elapsed <= timeout + 5,
                    phase="not instrumented; phase attribution requires separate probe",
                    overhead_seconds=round(elapsed - timeout, 3),
                )
            finally:
                set_mode(self.shared / "mode", "pass")
        self.cli(
            "candidate restored-network control",
            ["run", "--env-file", refs, "--", *self.target(marker)],
            limit=45,
        )

        original = self.args.binary
        self.args.binary = self.args.instrumented
        try:
            self.cli(
                "instrumented successful live launch",
                ["run", "--env-file", refs, "--", *self.target(marker)],
                limit=45,
            )
            event_start = len(self.observer.events)
            marker.unlink(missing_ok=True)
            set_mode(self.shared / "mode", "stall")
            try:
                self.stalled_run(
                    "instrumented first-network stall",
                    [
                        "run",
                        "--timeout",
                        "5s",
                        "--env-file",
                        refs,
                        "--",
                        *self.target(marker),
                    ],
                    5,
                    marker,
                )
                phases = {e["phase"] for e in self.observer.events[event_start:]}
                self.report["first_network_stall_phase"] = (
                    "resolution" if "sdk-resolution" in phases else "initialization"
                )
            finally:
                set_mode(self.shared / "mode", "pass")
            for timeout in (30, 5):
                marker.unlink(missing_ok=True)
                before = self.stats()
                event_start = len(self.observer.events)
                self.observer.stall_after_init = True
                try:
                    _, elapsed = self.stalled_run(
                        f"instrumented resolution stall {timeout}s",
                        [
                            "run",
                            "--timeout",
                            f"{timeout}s",
                            "--env-file",
                            refs,
                            "--",
                            *self.target(marker),
                        ],
                        timeout,
                        marker,
                    )
                    after = self.stats()
                    phases = {e["phase"] for e in self.observer.events[event_start:]}
                    self.record(
                        f"resolution-stage network evidence {timeout}s",
                        {"sdk-initialized", "sdk-resolution"} <= phases
                        and after["held_replies"] > before["held_replies"]
                        and not marker.exists()
                        and timeout - 0.5 <= elapsed <= timeout + 5,
                        overhead_seconds=round(elapsed - timeout, 3),
                    )
                finally:
                    self.observer.stall_after_init = False
                    set_mode(self.shared / "mode", "pass")
            self.cli(
                "instrumented restored-network control",
                ["run", "--env-file", refs, "--", *self.target(marker)],
                limit=45,
            )
        finally:
            self.args.binary = original

    def close(self):
        self.observer.close()
        if self.bridge:
            self.bridge.close()
        super().close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--instrumented", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--ids", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--inside", type=Path)
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--network-only", action="store_true")
    args = parser.parse_args()
    args.live, args.deny = not args.synthetic, False
    os.umask(0o077)
    for name in ("binary", "instrumented", "probe", "ids", "report"):
        setattr(args, name, getattr(args, name).resolve())
    if args.synthetic or args.inside:
        if args.preflight:
            bridge = Bridge(args.inside / "relay")
            try:
                proxy = urllib.request.ProxyHandler(
                    {"https": f"http://localhost:{bridge.port}"}
                )
                opener = urllib.request.build_opener(proxy)
                try:
                    response = opener.open("https://my.1password.com/", timeout=15)
                    response.close()
                except urllib.error.HTTPError:
                    pass
                print(
                    "PASS: namespace relay reached HTTPS with certificate verification"
                )
                return 0
            except (OSError, urllib.error.URLError):
                print("FAIL: namespace HTTPS relay preflight")
                return 1
            finally:
                bridge.close()
        if args.live and not os.isatty(0):
            parser.error("live token entry requires a local terminal")
        shared = args.inside or Path(
            tempfile.mkdtemp(prefix="op-go-synthetic-control-")
        )
        q = Qualification(args, shared)
        settings = termios.tcgetattr(0) if os.isatty(0) else None

        def interrupt(signum, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, interrupt)
        signal.signal(signal.SIGHUP, interrupt)
        try:
            if args.live:
                q.record(
                    "private network namespace",
                    os.readlink("/proc/self/ns/net")
                    != (shared / "host-netns").read_text()
                    and {
                        link["ifname"]
                        for link in json.loads(
                            subprocess.check_output(["ip", "-j", "link", "show"])
                        )
                    }
                    == {"lo"},
                )
            q.start()
            if args.synthetic:
                q.args.binary = args.instrumented
                q.synthetic_hidden_enroll()
                q.cli("hidden synthetic enrollment cleanup", ["remove", "--yes"])
                q.cli(
                    "synthetic enrollment checkpoints",
                    ["enroll", "--stdin"],
                    data=q.token,
                )
                q.cli(
                    "synthetic replacement checkpoints",
                    ["enroll", "--stdin", "--yes"],
                    data=q.token,
                )
                reference = q.root / "synthetic.env"
                reference.write_text(
                    "TEST_VALUE=op://Test Vault/API Credentials/username\n"
                )
                q.env["OP_GO_QUALIFICATION_SYNTHETIC"] = "1"
                try:
                    q.cli(
                        "instrumented synthetic fixture successful launch",
                        [
                            "run",
                            "--env-file",
                            reference,
                            "--",
                            *q.target(q.root / "synthetic-child"),
                        ],
                    )
                finally:
                    q.env.pop("OP_GO_QUALIFICATION_SYNTHETIC")
                q.cli("synthetic cleanup", ["remove", "--yes"])
            if args.network_only:
                if args.synthetic:
                    parser.error("--network-only needs live local enrollment")
                q.report["lookup_matrix"] = "not repeated; prior 20 reads passed"
                print(
                    "Enter the dedicated token at the hidden prompt "
                    "for network-only checks."
                )
                q.cli(
                    "network-only hidden enrollment",
                    ["enroll"],
                    terminal=True,
                    limit=300,
                )
                q.load_observer_token()
                q.network_checks()
                q.cli("network-only approved removal", ["remove", "--yes"])
                q.cli(
                    "network-only enrollment absent", ["doctor", "--json"], expected=3
                )
            else:
                q.validate()
            events = q.observer.events
            workers = {e["child"] for e in events if e["phase"] == "worker-started"}
            requests = {
                e["pid"] for e in events if e["phase"].startswith("worker-request-")
            }
            results = {
                e["pid"] for e in events if e["phase"].startswith("worker-result-")
            }
            q.record(
                "all instrumented workers covered",
                bool(workers)
                and workers == requests
                and workers == results | q.canceled_workers
                and all(e.get("observed") and not e.get("exposed") for e in events),
                workers=len(workers),
                canceled_workers=len(q.canceled_workers),
            )
            q.report["result"] = "PASS_FOR_COVERED_CHECKS"
            return 0
        except (RuntimeError, OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
            q.report["result"] = "INCOMPLETE"
            print(
                "INCOMPLETE: stopped without authentication retries; "
                "inspect named verdicts."
            )
            return 1
        finally:
            q.report["observer_events"] = q.observer.events
            q.close()
            if not args.inside:
                shutil.rmtree(shared)
            if settings:
                termios.tcsetattr(0, termios.TCSANOW, settings)
            print(
                "Isolated keyring and private services cleaned up; desktop unchanged."
            )
    shared = Path(tempfile.mkdtemp(prefix="op-go-network-control-"))
    set_mode(shared / "mode", "pass")
    (shared / "host-netns").write_text(os.readlink("/proc/self/ns/net"))
    relay = Relay(shared / "relay", shared / "mode", shared / "stats")
    command = [
        "sudo",
        "--",
        "unshare",
        "--net",
        "--",
        "/bin/sh",
        "-c",
        'ip link set dev lo up && uid="$1" && gid="$2" && shift 2 && '
        'exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$@"',
    ]
    command += [
        "op-go-private-net",
        str(os.getuid()),
        str(os.getgid()),
        sys.executable,
        str(Path(__file__).resolve()),
        *sys.argv[1:],
        "--inside",
        str(shared),
    ]
    clean = {k: v for k, v in os.environ.items() if k != "OP_SERVICE_ACCOUNT_TOKEN"}
    process = None

    def interrupt_outer(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt_outer)
    signal.signal(signal.SIGHUP, interrupt_outer)
    try:
        process = subprocess.Popen(command, env=clean)
        return process.wait()
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        relay.close()
        if args.report.exists() and not args.preflight:
            report = json.loads(args.report.read_text())
            report["relay_cleanup"] = True
            report["namespace_controller_exited"] = bool(
                process and process.poll() is not None
            )
            report["host_network_namespace_unchanged"] = (
                os.readlink("/proc/self/ns/net") == (shared / "host-netns").read_text()
            )
            if (shared / "stats").exists():
                report["network_counters"] = json.loads((shared / "stats").read_text())
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        shutil.rmtree(shared)


if __name__ == "__main__":
    sys.exit(main())
