from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from media_evidence.broker_client import (
    BrokerClient,
    BrokerOutcomeUnknownError,
    BrokerRemoteError,
    BrokerUnavailableError,
)
from media_evidence.broker_protocol import (
    make_error_response,
    make_success_response,
    receive_request,
    send_response,
)


class SocketPairBroker:
    def __init__(self, handler):
        self.handler = handler
        self.connections = 0
        self.threads: list[threading.Thread] = []

    def connect(self, _path: Path, _timeout: float) -> socket.socket:
        client, server = socket.socketpair()
        self.connections += 1

        def run() -> None:
            try:
                self.handler(server)
            finally:
                server.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.threads.append(thread)
        return client

    def join(self) -> None:
        for thread in self.threads:
            thread.join(timeout=1)


class MediaEvidenceBrokerClientTests(unittest.TestCase):
    def client(self, broker: SocketPairBroker, *, timeout: float = 1.0) -> BrokerClient:
        return BrokerClient(
            socket_path="/unused/broker.sock",
            timeout=timeout,
            gateway_gid=os.getgid(),
            expected_socket_uid=os.geteuid(),
            socket_validator=lambda _path: (1, 2),
            connector=broker.connect,
            peer_credentials_reader=lambda _connection: (123, os.geteuid(), os.getgid()),
        )

    def test_public_methods_send_only_allowlisted_operations(self) -> None:
        requests: list[dict] = []

        def handler(connection: socket.socket) -> None:
            request = receive_request(connection)
            requests.append(request)
            send_response(
                connection,
                make_success_response(
                    request["request_id"],
                    {"ok": True, "operation": request["operation"]},
                ),
            )

        broker = SocketPairBroker(handler)
        client = self.client(broker)
        self.assertEqual(client.health()["operation"], "health")
        self.assertEqual(client.capabilities()["operation"], "capabilities")
        self.assertEqual(
            client.analyze(
                source_path="/data/workspace/input.pdf",
                rights_basis="user_provided",
                privacy="private",
                purpose="test",
            )["operation"],
            "analyze",
        )
        self.assertEqual(client.status("mev_" + "1" * 24)["operation"], "status")
        self.assertEqual(
            client.validate_claims(
                job_id="mev_" + "1" * 24,
                claims=[{"claim": "x", "evidence_ids": ["e1"]}],
            )["operation"],
            "validate_claims",
        )
        broker.join()
        self.assertEqual(
            [request["operation"] for request in requests],
            ["health", "capabilities", "analyze", "status", "validate_claims"],
        )

    def test_connect_failure_is_classified_before_send(self) -> None:
        def fail_connect(_path: Path, _timeout: float) -> socket.socket:
            raise FileNotFoundError("private path must not escape")

        broker = SocketPairBroker(lambda _connection: None)
        client = self.client(broker)
        client._connector = fail_connect
        with self.assertRaises(BrokerUnavailableError) as raised:
            client.health()
        self.assertEqual(raised.exception.code, "broker_unavailable")
        self.assertEqual(raised.exception.phase, "before_send")
        self.assertNotIn("private path", str(raised.exception))

    def test_timeout_after_send_is_outcome_unknown_and_analyze_is_not_retried(self) -> None:
        received = threading.Event()

        def handler(connection: socket.socket) -> None:
            receive_request(connection)
            received.set()
            time.sleep(0.2)

        broker = SocketPairBroker(handler)
        client = self.client(broker, timeout=0.05)
        with self.assertRaises(BrokerOutcomeUnknownError) as raised:
            client.analyze(
                source_path="/data/workspace/input.pdf",
                rights_basis="user_provided",
                privacy="private",
                purpose="test",
            )
        self.assertTrue(received.wait(1))
        self.assertEqual(raised.exception.code, "outcome_unknown")
        self.assertEqual(raised.exception.phase, "after_send")
        self.assertEqual(broker.connections, 1)
        broker.join()

    def test_mismatched_response_id_is_outcome_unknown(self) -> None:
        def handler(connection: socket.socket) -> None:
            receive_request(connection)
            send_response(connection, make_success_response("b" * 32, {"ok": True}))

        broker = SocketPairBroker(handler)
        client = self.client(broker)
        with self.assertRaises(BrokerOutcomeUnknownError) as raised:
            client.health()
        self.assertEqual(raised.exception.code, "outcome_unknown")
        broker.join()

    def test_correlated_remote_error_is_preserved_without_retry(self) -> None:
        def handler(connection: socket.socket) -> None:
            request = receive_request(connection)
            send_response(
                connection,
                make_error_response(
                    request["request_id"],
                    "job_not_found",
                    "Media evidence job was not found",
                ),
            )

        broker = SocketPairBroker(handler)
        client = self.client(broker)
        with self.assertRaises(BrokerRemoteError) as raised:
            client.status("mev_" + "1" * 24)
        self.assertEqual(raised.exception.code, "job_not_found")
        self.assertEqual(broker.connections, 1)
        broker.join()

    def test_malformed_response_after_send_is_outcome_unknown(self) -> None:
        def handler(connection: socket.socket) -> None:
            receive_request(connection)
            connection.sendall(b"\x00\x00\x00\x02{}")

        broker = SocketPairBroker(handler)
        client = self.client(broker)
        with self.assertRaises(BrokerOutcomeUnknownError):
            client.health()
        broker.join()

    def test_default_socket_validator_rejects_non_socket_and_unsafe_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "run"
            parent.mkdir(mode=0o750)
            os.chmod(parent, 0o750)
            path = parent / "broker.sock"
            path.write_text("not a socket", encoding="utf-8")
            client = BrokerClient(
                socket_path=path,
                gateway_gid=os.getgid(),
                expected_socket_uid=os.geteuid(),
            )
            with self.assertRaises(OSError):
                client._validate_socket_path(path)


if __name__ == "__main__":
    unittest.main()
