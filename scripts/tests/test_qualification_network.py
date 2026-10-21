# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Verify the qualification relay's hold/restore behavior with synthetic bytes."""

import importlib.util
from pathlib import Path
import select
import socket
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "qualification/network.py"
SPEC = importlib.util.spec_from_file_location("qualification_network", SOURCE)
NETWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NETWORK)


class RelayTest(unittest.TestCase):
    """A held reply must remain pending until forwarding is restored."""

    def test_hold_and_restore_without_payload_logging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "mode"
            NETWORK.set_mode(control, "stall")
            upstream, server = socket.socketpair()
            client = socket.socket(socket.AF_UNIX)
            relay = NETWORK.Relay(root / "relay", control, root / "stats")
            try:
                with mock.patch.object(
                    NETWORK.socket, "create_connection", return_value=upstream
                ):
                    client.connect(str(root / "relay"))
                    client.settimeout(2)
                    server.settimeout(2)
                    client.sendall(b"CONNECT test.1password.com:443 HTTP/1.1\r\n\r\n")
                    self.assertIn(b"200 Connection Established", client.recv(1024))
                    handshake = (
                        b"\x16\x03\x03\x00\x01h"
                        + b"\x14\x03\x03\x00\x01c"
                        + b"\x17\x03\x03\x00\x01f"
                    )
                    client.sendall(handshake)
                    self.assertEqual(
                        server.recv(len(handshake), socket.MSG_WAITALL), handshake
                    )
                    server.sendall(b"synthetic handshake reply")
                    self.assertEqual(client.recv(1024), b"synthetic handshake reply")
                    application = b"\x17\x03\x03\x00\x01a"
                    client.sendall(application)
                    self.assertEqual(
                        server.recv(len(application), socket.MSG_WAITALL), application
                    )
                    server.sendall(b"synthetic encrypted response")
                    deadline = time.monotonic() + 2
                    while (
                        relay.counters["held_replies"] == 0
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.01)
                    self.assertEqual(relay.counters["held_replies"], 1)
                    self.assertFalse(select.select([client], [], [], 0.05)[0])
                    NETWORK.set_mode(control, "pass")
                    self.assertEqual(client.recv(1024), b"synthetic encrypted response")
                    self.assertNotIn(
                        "synthetic", (root / "stats").read_text(encoding="utf-8")
                    )
            finally:
                relay.close()
                client.close()
                server.close()
            self.assertFalse((root / "relay").exists())

    def test_fragmented_tls13_finished_does_not_arm_stall(self):
        gate = NETWORK.TLSApplicationGate()
        for byte in b"\x16\x03\x03\x00\x01h\x14\x03\x03\x00\x01c\x17\x03\x03\x00\x01f":
            gate.feed(bytes([byte]))
            self.assertFalse(gate.application_started)
        gate.feed(b"\x17\x03\x03\x00\x01a")
        self.assertTrue(gate.application_started)

    def test_tls12_application_record_arms_stall(self):
        gate = NETWORK.TLSApplicationGate()
        gate.feed(b"\x16\x03\x03\x00\x01h\x14\x03\x03\x00\x01c\x16\x03\x03\x00\x01f")
        self.assertFalse(gate.application_started)
        gate.feed(b"\x17\x03\x03\x00\x01a")
        self.assertTrue(gate.application_started)

    def test_unapproved_destination_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "mode"
            control.write_text("pass", encoding="utf-8")
            relay = NETWORK.Relay(root / "relay", control, root / "stats")
            client = socket.socket(socket.AF_UNIX)
            try:
                with mock.patch.object(NETWORK.socket, "create_connection") as connect:
                    client.connect(str(root / "relay"))
                    client.settimeout(2)
                    client.sendall(b"CONNECT localhost:443 HTTP/1.1\r\n\r\n")
                    self.assertEqual(client.recv(1024), b"")
                    connect.assert_not_called()
            finally:
                relay.close()
                client.close()


if __name__ == "__main__":
    unittest.main()
