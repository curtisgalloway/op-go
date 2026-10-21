# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Opaque CONNECT forwarding and test-only checkpoints. Never log payloads."""

import json
from pathlib import Path
import select
import socket
import threading
import time


def set_mode(path, mode):
    """Publish a forwarding mode atomically across the namespace boundary."""
    temporary = path.with_suffix(".next")
    temporary.write_text(mode, encoding="utf-8")
    temporary.replace(path)


class TLSApplicationGate:
    """Recognize client application records from headers, without decrypting TLS.

    Go's TLS 1.3 client emits its encrypted Finished in the first type-23 record;
    application writes start with the second. TLS 1.2 sends encrypted Finished
    as type 22 after ChangeCipherSpec, so its first type-23 record is application
    data. Payloads are skipped, not decoded or retained by this classifier.
    """

    def __init__(self):
        self.header = bytearray()
        self.remaining = 0
        self.ccs = False
        self.tls12 = False
        self.encrypted_records = 0
        self.application_started = False

    def feed(self, data):
        offset = 0
        while offset < len(data):
            if self.remaining:
                count = min(self.remaining, len(data) - offset)
                self.remaining -= count
                offset += count
                continue
            count = min(5 - len(self.header), len(data) - offset)
            self.header.extend(data[offset : offset + count])
            offset += count
            if len(self.header) != 5:
                continue
            kind, major = self.header[:2]
            if major != 3 or kind not in (20, 21, 22, 23):
                raise ValueError("unsupported TLS framing")
            self.remaining = int.from_bytes(self.header[3:5], "big")
            self.header.clear()
            if kind == 20:
                self.ccs = True
            elif kind == 22 and self.ccs:
                self.tls12 = True
            elif kind == 23:
                self.encrypted_records += 1
                self.application_started = self.tls12 or self.encrypted_records >= 2


class Relay:
    """A private UNIX socket transports TLS without inspecting its contents."""

    def __init__(self, path, control, stats, connector=None):
        self.path, self.control, self.stats = path, control, stats
        self.stop = threading.Event()
        self.connections = set()
        self.lock = threading.Lock()
        self.connector = connector
        self.counters = {
            "connected": 0,
            "client_records": 0,
            "held_replies": 0,
            "application_connections": 0,
        }
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def bump(self, key):
        with self.lock:
            self.counters[key] += 1
            temp = self.stats.with_suffix(".new")
            temp.write_text(json.dumps(self.counters))
            temp.replace(self.stats)

    def accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections.add(conn)
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, client):
        upstream = None
        try:
            client.settimeout(10)
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                part = client.recv(1)
                if not part:
                    return
                header += part
                if len(header) > 8192:
                    return
            first = header.split(b"\r\n", 1)[0].decode("ascii").split()
            if len(first) != 3 or first[0] != "CONNECT":
                return
            host, port = first[1].rsplit(":", 1)
            if port != "443" or not any(
                host.endswith(suffix)
                for suffix in (".1password.com", ".1password.eu", ".1password.ca")
            ):
                return
            connector = self.connector or socket.create_connection
            upstream = connector((host, 443), timeout=10)
            self.connections.add(upstream)
            self.bump("connected")
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            gate = TLSApplicationGate()
            while not self.stop.is_set():
                ready, _, _ = select.select([client, upstream], [], [], 0.2)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    if source is client:
                        was_application = gate.application_started
                        gate.feed(data)
                        if gate.application_started and not was_application:
                            self.bump("application_connections")
                        self.bump("client_records")
                        upstream.sendall(data)
                    else:
                        mode = self.control.read_text().strip()
                        stalled = mode == "handshake-stall" or (
                            mode == "stall" and gate.application_started
                        )
                        if stalled:
                            self.bump("held_replies")
                        while stalled and not self.stop.wait(0.05):
                            mode = self.control.read_text().strip()
                            stalled = mode == "handshake-stall" or (
                                mode == "stall" and gate.application_started
                            )
                        if self.stop.is_set():
                            return
                        client.sendall(data)
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            for conn in (client, upstream):
                if conn:
                    self.connections.discard(conn)
                    conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        for conn in list(self.connections):
            conn.close()
        self.thread.join(timeout=2)
        self.path.unlink(missing_ok=True)


class Bridge:
    """Expose only a loopback CONNECT proxy inside the otherwise empty namespace."""

    def __init__(self, path):
        self.path = path
        self.listener = socket.socket()
        self.listener.bind(("localhost", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.closed = False
        self.connections = set()
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.closed:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def serve(self, client):
        remote = socket.socket(socket.AF_UNIX)
        self.connections.update((client, remote))
        try:
            remote.connect(str(self.path))
            while not self.closed:
                ready, _, _ = select.select([client, remote], [], [], 0.2)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (remote if source is client else client).sendall(data)
        except OSError:
            pass
        finally:
            for conn in (client, remote):
                self.connections.discard(conn)
                conn.close()

    def close(self):
        self.closed = True
        self.listener.close()
        for conn in list(self.connections):
            conn.close()


class Observer:
    """Synchronized inspection of instrumented processes, with no raw output."""

    def __init__(self, path, control):
        self.path, self.control = path, control
        self.token = b""
        self.process = None
        self.process_getter = lambda: self.process
        self.events = []
        self.stall_after_init = False
        self.closed = False
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        self.listener.listen()
        threading.Thread(target=self.accept, daemon=True).start()

    def inspect(self, pid):
        """Read only the checkpoint process; never persist its raw data."""
        exposed = False
        for field in ("cmdline", "environ"):
            data = Path(f"/proc/{pid}/{field}").read_bytes()
            exposed |= bool(self.token) and self.token in data
        return exposed

    def descendant(self, pid):
        while pid > 1:
            process = self.process_getter()
            if process and pid == process.pid:
                return True
            try:
                status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
                pid = int(
                    next(
                        line.split()[1]
                        for line in status.splitlines()
                        if line.startswith("PPid:")
                    )
                )
            except (OSError, StopIteration):
                return False
        return False

    def accept(self):
        while not self.closed:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2)
                    message = b""
                    while not message.endswith(b"\n"):
                        part = conn.recv(1024)
                        if not part or len(message) > 4096:
                            raise ValueError("invalid checkpoint")
                        message += part
                    event = json.loads(message)
                    pid = event["PID"]
                    deadline = time.monotonic() + 1
                    while not self.process_getter() and time.monotonic() < deadline:
                        time.sleep(0.001)
                    if not self.descendant(pid):
                        raise ValueError("not a test descendant")
                    exposed = self.inspect(pid)
                    self.events.append(
                        {
                            "phase": event["Phase"],
                            "pid": pid,
                            "child": event.get("Child", 0),
                            "observed": bool(self.token),
                            "exposed": exposed,
                        }
                    )
                    if event["Phase"] == "sdk-initialized" and self.stall_after_init:
                        set_mode(self.control, "stall")
                    conn.sendall(b"\x01")
                except (OSError, ValueError, KeyError):
                    self.events.append({"phase": "observer-error", "observed": False})

    def close(self):
        self.closed = True
        self.listener.close()
        self.path.unlink(missing_ok=True)
