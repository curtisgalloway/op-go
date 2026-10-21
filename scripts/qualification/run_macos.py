#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Opt-in signed macOS worker and network qualification.

Temporarily selects a disposable Keychain as the user's default, restores the
original default/search list, and deletes only that disposable store. Close apps
that create credentials during this interval. Recovery commands are saved BEFORE
changing the default. SIGKILL/power loss cannot run cleanup. Uses a per-process
verified-TLS proxy; never changes the host firewall, DNS, or system proxy.

--synthetic requires no real token. --live reads the dedicated test token through
op-go's hidden terminal prompt and exports it only over a private in-memory pipe
to the observer. Reports contain verdicts, timings and PIDs, never raw ps output.
Candidate and instrumented coverage are explicitly separate. No package install
or notarization is performed. No Linux network-namespace isolation is claimed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import time

from network import Bridge, Observer, Relay, set_mode
from run import Qualification


def process_exists(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class MacObserver(Observer):
    """Inspect suspended checkpoints with macOS ps, not Linux /proc."""

    def descendant(self, pid):
        process = self.process_getter()
        if not process:
            return False
        seen = set()
        while pid > 1 and pid not in seen:
            if pid == process.pid:
                return True
            seen.add(pid)
            try:
                result = subprocess.run(
                    ["/bin/ps", "-p", str(pid), "-o", "ppid="],
                    capture_output=True,
                    timeout=1,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return False
            if result.returncode:
                return False
            try:
                pid = int(result.stdout.strip())
            except ValueError:
                return False
        return False

    def inspect(self, pid):
        try:
            result = subprocess.run(
                ["/bin/ps", "eww", "-p", str(pid), "-o", "command="],
                capture_output=True,
                timeout=1,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise OSError("checkpoint inspection timed out") from error
        if result.returncode or not result.stdout.strip():
            raise OSError("checkpoint process could not be inspected")
        return bool(self.token) and self.token in result.stdout


class MacQualification(Qualification):
    """Reuse the Linux deadline assertions without its keyring or process APIs."""

    # The parent initializer creates Linux-specific stores and environments.
    def __init__(self, args):  # pylint: disable=super-init-not-called
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="opqm-", dir="/private/tmp"))
        self.shared = self.root
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("OP_")
            and not k.lower().endswith("_proxy")
            and k != "EXTISM_ENABLE_WASI_OUTPUT"
        }
        self.token = ("synthetic-op-go-" + secrets.token_hex(24)).encode()
        self.password = secrets.token_hex(24)
        self.active = None
        self.canceled_workers = set()
        self.original = self.search = None
        self.created = False
        self.observer = self.bridge = self.relay = None
        self.keychain = self.root / "test.keychain-db"
        self.report = {
            "checks": [],
            "operations": [],
            "cleanup": False,
            "mode": (
                "package-upgrade"
                if args.package_upgrade
                else "live"
                if args.live
                else "synthetic"
            ),
            "temporary_store": str(self.root),
            "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "instrumented_sha256": hashlib.sha256(
                args.instrumented.read_bytes()
            ).hexdigest(),
            "limits": [
                "checkpoint evidence applies to the instrumented build",
                "macOS ps arguments/environment interface only; not memory/debugging",
                "candidate worker coverage is not universal",
                "per-process proxy; no network namespace isolation",
            ],
        }

    def setup(self):
        set_mode(self.root / "mode", "pass")
        self.observer = MacObserver(self.root / "observer", self.root / "mode")
        self.observer.process_getter = lambda: self.active
        self.observer.token = b"" if self.args.live else self.token
        self.env["OP_GO_QUALIFICATION_SOCKET"] = str(self.observer.path)
        if (
            self.args.live
            and not self.args.direct_control
            and not self.args.package_upgrade
        ):
            self.relay = Relay(
                self.root / "relay", self.root / "mode", self.root / "stats"
            )
            self.bridge = Bridge(self.root / "relay")
            self.env.update(
                HTTPS_PROXY=f"http://localhost:{self.bridge.port}",
                HTTP_PROXY=f"http://localhost:{self.bridge.port}",
                NO_PROXY="",
            )
        elif not self.args.live:
            self.env["OP_GO_QUALIFICATION_SYNTHETIC"] = "1"

        self.original = shlex.split(self.security("default-keychain", "-d", "user"))
        self.search = shlex.split(self.security("list-keychains", "-d", "user"))
        if len(self.original) != 1:
            raise RuntimeError("Cannot determine original default Keychain")
        recovery = "\n".join(
            [
                shlex.join(
                    [
                        "/usr/bin/security",
                        "default-keychain",
                        "-d",
                        "user",
                        "-s",
                        self.original[0],
                    ]
                ),
                shlex.join(
                    [
                        "/usr/bin/security",
                        "list-keychains",
                        "-d",
                        "user",
                        "-s",
                        *self.search,
                    ]
                ),
            ]
        )
        (self.root / "restore.sh").write_text("#!/bin/sh\nset -e\n" + recovery + "\n")
        print("Recovery instructions:", self.root / "restore.sh", flush=True)
        # The keychain password is disposable, not a user password or account token.
        self.security("create-keychain", "-p", self.password, self.keychain)
        self.created = True
        self.security("unlock-keychain", "-p", self.password, self.keychain)
        self.security("default-keychain", "-d", "user", "-s", self.keychain)
        self.record(
            "temporary default selected",
            shlex.split(self.security("default-keychain", "-d", "user"))
            == [str(self.keychain)],
        )

    def security(self, *args):
        result = subprocess.run(
            ["/usr/bin/security", *map(str, args)],
            env=self.env,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("Keychain operation failed: " + args[0])
        return result.stdout.decode()

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
        self.active = process
        out = err = b""
        timed_out = False
        try:
            out, err = process.communicate(data, timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if process.poll() is None:
                process.kill()
                out, err = process.communicate()
            self.active = None
            if settings:
                termios.tcsetattr(0, termios.TCSANOW, settings)
        elapsed = time.monotonic() - started
        events = self.observer.events[before:]
        workers = {e["child"] for e in events if e["phase"] == "worker-started"}
        pids = workers | {e["pid"] for e in events if "pid" in e} | {process.pid}
        survivors = [pid for pid in pids if process_exists(pid)]
        exposed = bool(
            self.observer.token and self.observer.token in (out or b"") + (err or b"")
        )
        operation = dict(
            name=name,
            expected_status=expected,
            actual_status=process.returncode,
            seconds=round(elapsed, 3),
            timed_out=timed_out,
            observed_pids=sorted(pids),
            surviving_observed_pids=survivors,
            checkpoint_phases=sorted({e["phase"] for e in events}),
            output_token_exposure=exposed,
            relay_counters=self.stats(),
        )
        if process.returncode != expected and not exposed and not terminal:
            # Launcher diagnostics are sanitized by design; keep the last line
            # so a failure records its error category, never raw SDK text.
            lines = (err or b"").decode(errors="replace").strip().splitlines()
            operation["diagnostic"] = lines[-1][:200] if lines else ""
        self.report["operations"].append(operation)
        # Record evidence before raising so failed stalls retain diagnostics.
        self.record(
            name,
            not timed_out and process.returncode == expected,
            status=process.returncode,
            seconds=round(elapsed, 3),
        )
        if self.observer.token:
            self.record(name + " output redaction", not exposed)
        self.record(name + " observed processes exited", not survivors)
        if events:
            self.record(
                name + " checkpoint exposure",
                all(e.get("observed") and not e.get("exposed") for e in events),
                phases=operation["checkpoint_phases"],
                workers=len(workers),
            )
        if workers:
            requests = {
                e["pid"] for e in events if e["phase"].startswith("worker-request-")
            }
            results = {
                e["pid"] for e in events if e["phase"].startswith("worker-result-")
            }
            self.record(name + " every worker observed", workers == requests == results)
        return out, elapsed

    def synthetic(self):
        # Reuse hidden-input automation with the macOS checkpoint observer.
        start = len(self.observer.events)
        self.synthetic_hidden_enroll()
        events = self.observer.events[start:]
        workers = {e["child"] for e in events if e["phase"] == "worker-started"}
        requests = {
            e["pid"] for e in events if e["phase"].startswith("worker-request-")
        }
        results = {e["pid"] for e in events if e["phase"].startswith("worker-result-")}
        self.record(
            "hidden enrollment every worker observed",
            bool(workers) and workers == requests == results,
        )
        self.record(
            "hidden enrollment checkpoint exposure",
            all(e.get("observed") and not e.get("exposed") for e in events),
        )
        self.record(
            "hidden enrollment workers exited",
            all(not process_exists(pid) for pid in workers),
        )
        original = self.args.binary
        self.args.binary = self.args.instrumented
        try:
            self.cli(
                "synthetic replacement",
                ["enroll", "--stdin", "--yes"],
                data=self.token + b"\n",
            )
            self.cli("synthetic metadata", ["doctor", "--json"])
            refs = self.root / "synthetic.env"
            refs.write_text("TEST_VALUE=op://Test Vault/API Credentials/username\n")
            self.env.update(OP_CONNECT_TOKEN="fake", OP_SESSION_TEST="fake")
            self.cli(
                "synthetic retrieval and successful child",
                ["run", "--env-file", refs, "--", *self.target(self.root / "child")],
                limit=45,
            )
            self.cli("synthetic removal", ["remove", "--yes"])
            self.cli("synthetic absence", ["doctor", "--json"], expected=3)
            self.cli(
                "synthetic reenrollment", ["enroll", "--stdin"], data=self.token + b"\n"
            )
            self.security("lock-keychain", self.keychain)
            self.cli("locked metadata", ["doctor", "--json"], expected=11)
            marker = self.root / "locked-child"
            self.cli(
                "locked run",
                ["run", "--env-file", refs, "--", *self.target(marker)],
                expected=11,
            )
            self.record("locked child absent", not marker.exists())
            self.security("unlock-keychain", "-p", self.password, self.keychain)
            self.cli("remove before denial", ["remove", "--yes"])
            self.security(
                "add-generic-password",
                "-a",
                "service-account",
                "-s",
                "op-go",
                "-T",
                "/usr/bin/security",
                "-w",
                self.token.decode(),
                self.keychain,
            )
            self.cli("restricted metadata", ["doctor", "--json"])
            self.cli(
                "denied run",
                ["run", "--env-file", refs, "--", *self.target(marker)],
                expected=12,
            )
            self.record("denied child absent", not marker.exists())
        finally:
            self.args.binary = original

    def signing(self, binary):
        """Return the designated requirement, which Keychain trust is keyed on."""
        result = subprocess.run(
            ["/usr/bin/codesign", "-d", "-r-", str(binary)],
            capture_output=True,
            timeout=15,
            check=False,
        )
        lines = (result.stdout + result.stderr).decode().splitlines()
        return [line for line in lines if line.startswith("designated =>")]

    def package_upgrade(self):
        """Enroll with the signed development build, then run the notarized bytes.

        Covers same-path replacement (archive or disk image copied over the old
        executable) and a new path (Homebrew installs each version in its own
        Cellar directory). No proxy, lookup matrix, or network stall is repeated.
        """
        candidate = self.args.binary
        baseline = self.args.baseline
        self.report["baseline_sha256"] = hashlib.sha256(
            baseline.read_bytes()
        ).hexdigest()
        assessment = subprocess.run(
            ["/usr/sbin/spctl", "--assess", "-vv", "--type", "install", candidate],
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.record(
            "candidate notarized Developer ID",
            assessment.returncode == 0
            and b"source=Notarized Developer ID" in assessment.stderr,
        )
        self.record(
            "baseline not notarized-identical",
            baseline.read_bytes() != candidate.read_bytes(),
        )
        designated = self.signing(candidate)
        self.record(
            "same designated requirement",
            bool(designated) and designated == self.signing(baseline),
        )
        installed = self.root / "prefix" / "bin" / "op-go"
        installed.parent.mkdir(parents=True)
        shutil.copy2(baseline, installed)
        self.args.binary = installed
        print("Enter the dedicated TEST token at op-go's hidden prompt.", flush=True)
        socket_path = self.env.pop("OP_GO_QUALIFICATION_SOCKET")
        try:
            self.cli("hidden baseline enrollment", ["enroll"], terminal=True, limit=300)
        finally:
            self.env["OP_GO_QUALIFICATION_SOCKET"] = socket_path
        self.load_observer_token()
        self.env.update(OP_CONNECT_TOKEN="fake", OP_SESSION_TEST="fake")
        refs = self.root / "upgrade.env"
        refs.write_text("TEST_VALUE=op://Test Vault/API Credentials/username\n")
        marker = self.root / "upgrade-child"
        run = ["run", "--env-file", refs, "--", *self.target(marker)]
        self.cli("baseline live delivery", run, limit=45)
        # Back-to-back control: a failure here is a lookup problem, not upgrade trust.
        self.cli("baseline immediate repeat delivery", run, limit=45)
        shutil.copy2(candidate, installed)
        self.cli("notarized same-path upgrade delivery", run, limit=45)
        cellar = self.root / "Cellar" / "op-go" / "0.1.0" / "bin" / "op-go"
        cellar.parent.mkdir(parents=True)
        shutil.copy2(candidate, cellar)
        self.args.binary = cellar
        self.cli("notarized new-path delivery", run, limit=45)
        self.cli("notarized metadata", ["doctor", "--json"])
        self.record(
            "upgrade no trust repair",
            input(
                "No permission prompt or trust repair appeared after either "
                "upgrade? Type yes: "
            ).strip()
            == "yes",
        )
        self.cli("notarized enrollment removal", ["remove", "--yes"])
        self.cli("notarized absence", ["doctor", "--json"], expected=3)
        self.args.binary = candidate

    def live(self):
        if self.args.package_upgrade:
            self.package_upgrade()
            return
        original = self.args.binary
        if not (self.args.network_only or self.args.direct_control):
            baseline = self.args.baseline or (original.parent / "baseline")
            self.record(
                "upgrade binaries differ",
                baseline.read_bytes() != original.read_bytes(),
            )
            installed = self.root / "op-go"
            shutil.copy2(baseline, installed)
            self.args.binary = installed
        print("Enter the dedicated TEST token at op-go's hidden prompt.", flush=True)
        socket_path = self.env.pop("OP_GO_QUALIFICATION_SOCKET")
        try:
            self.cli("hidden live enrollment", ["enroll"], terminal=True, limit=300)
        finally:
            self.env["OP_GO_QUALIFICATION_SOCKET"] = socket_path
        self.load_observer_token()
        self.env.update(OP_CONNECT_TOKEN="fake", OP_SESSION_TEST="fake")
        if not (self.args.network_only or self.args.direct_control):
            refs = self.root / "upgrade.env"
            refs.write_text("TEST_VALUE=op://Test Vault/API Credentials/username\n")
            marker = self.root / "upgrade-child"
            self.cli(
                "baseline live delivery",
                ["run", "--env-file", refs, "--", *self.target(marker)],
                limit=45,
            )
            shutil.copy2(original, self.args.binary)
            self.cli(
                "same-path signed upgrade delivery",
                ["run", "--env-file", refs, "--", *self.target(marker)],
                limit=45,
            )
            self.record(
                "upgrade no trust repair",
                input(
                    "No new permission prompt or trust repair after upgrade? Type yes: "
                ).strip()
                == "yes",
            )
            if self.args.ids:
                ids = json.loads(self.args.ids.read_text())
            else:
                ids = {
                    "vault": input("Test vault ID (nonsecret): ").strip(),
                    "item": input("Test item ID (nonsecret): ").strip(),
                }
            self.record(
                "lookup IDs valid",
                all(
                    re.fullmatch(r"[A-Za-z0-9]{26}", ids.get(k, ""))
                    for k in ("vault", "item")
                ),
            )
            for label, vault, item in [
                ("names-names", "Test Vault", "API Credentials"),
                ("names-ids", "Test Vault", ids["item"]),
                ("ids-names", ids["vault"], "API Credentials"),
                ("ids-ids", ids["vault"], ids["item"]),
            ]:
                refs.write_text(f"TEST_VALUE=op://{vault}/{item}/username\n")
                for number in range(5):
                    self.cli(
                        f"lookup {label} {number+1}",
                        ["run", "--env-file", refs, "--", *self.target(marker)],
                        limit=45,
                    )
                    time.sleep(1)
            self.report["lookup_conclusion"] = "not reproduced, not proven fixed"
        self.args.binary = original
        if self.args.direct_control:
            refs = self.root / "direct.env"
            refs.write_text("TEST_VALUE=op://Test Vault/API Credentials/username\n")
            self.cli(
                "direct exact-value control without proxy",
                [
                    "run",
                    "--env-file",
                    refs,
                    "--",
                    *self.target(self.root / "direct-child"),
                ],
                limit=45,
            )
        else:
            self.network_checks()
        self.cli("live enrollment removal", ["remove", "--yes"])
        self.cli("live absence", ["doctor", "--json"], expected=3)

    def close(self):
        if self.active and self.active.poll() is None:
            self.active.kill()
            self.active.wait()
        errors = []
        for resource in (self.observer, self.bridge, self.relay):
            if resource:
                try:
                    resource.close()
                except OSError:
                    errors.append("observer/proxy cleanup")
        if self.created:
            try:
                self.security("default-keychain", "-d", "user", "-s", self.original[0])
                self.security("list-keychains", "-d", "user", "-s", *self.search)
                restored = (
                    shlex.split(self.security("default-keychain", "-d", "user"))
                    == self.original
                    and shlex.split(self.security("list-keychains", "-d", "user"))
                    == self.search
                )
                if not restored:
                    raise RuntimeError("restore verification")
                self.security("delete-keychain", self.keychain)
            except (RuntimeError, subprocess.TimeoutExpired):
                errors.append("Keychain restore/delete; use saved restore.sh")
        self.report["cleanup"] = not errors
        self.report["cleanup_errors"] = errors
        self.args.report.parent.mkdir(parents=True, exist_ok=True)
        self.args.report.write_text(json.dumps(self.report, indent=2) + "\n")
        if errors:
            raise RuntimeError(
                "Cleanup incomplete; inspect report and recovery instructions"
            )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    for name in ("binary", "instrumented", "probe", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument(
        "--baseline", type=Path, help="signed older binary; defaults beside candidate"
    )
    parser.add_argument(
        "--ids", type=Path, help="private JSON with vault/item IDs, otherwise prompts"
    )
    parser.add_argument(
        "--network-only",
        action="store_true",
        help="skip already-passing upgrade and lookup checks",
    )
    parser.add_argument(
        "--direct-control",
        action="store_true",
        help="one live exact-value check without the proxy; stops on failure",
    )
    parser.add_argument(
        "--package-upgrade",
        action="store_true",
        help="enroll with --baseline, then deliver with the notarized --binary",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synthetic", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument(
        "--confirm-keychain-switch",
        action="store_true",
        help="acknowledge temporary default-Keychain change without another prompt",
    )
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS required")
    for name in ("binary", "instrumented", "probe", "report"):
        setattr(args, name, getattr(args, name).resolve())
    if args.report.exists():
        parser.error(
            "use a new report filename; existing evidence is never overwritten"
        )
    if args.live and not os.isatty(0):
        parser.error("live checks require a terminal")
    if args.direct_control and (not args.live or args.network_only):
        parser.error("--direct-control requires --live and cannot use --network-only")
    if args.package_upgrade:
        if not args.live or args.network_only or args.direct_control:
            parser.error("--package-upgrade requires --live alone")
        if not args.baseline:
            parser.error("--package-upgrade requires --baseline")
        args.baseline = args.baseline.resolve()
    os.umask(0o077)
    print(
        "Temporarily switching the default Keychain.\n"
        "Close apps that create credentials.\n"
        "The login Keychain will not be locked or have entries changed.",
        flush=True,
    )
    if (
        not args.confirm_keychain_switch
        and input("Type yes to continue: ").strip() != "yes"
    ):
        return 1
    for binary in (args.binary, args.instrumented, args.probe, args.baseline):
        if binary is None:
            continue
        subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", binary], check=True
        )
    q = MacQualification(args)

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    result = 0
    try:
        q.setup()
        if args.live:
            q.live()
        else:
            q.synthetic()
        q.report["result"] = "PASS_FOR_COVERED_CHECKS"
    except (Exception, KeyboardInterrupt) as error:  # pylint: disable=broad-exception-caught
        q.report["result"] = "STOPPED_OR_FAILED"
        # Do not print arbitrary exception text that might include process data.
        q.report["exception_type"] = type(error).__name__
        print(
            "Stopped; inspect named verdicts. No automatic authentication retry.",
            flush=True,
        )
        result = 1
    finally:
        try:
            q.close()
        except RuntimeError:
            print("Cleanup incomplete: use the saved recovery script.", flush=True)
            result = 1
        print("Report:", args.report, flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
