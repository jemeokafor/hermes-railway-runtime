from __future__ import annotations

import io
import json
import logging
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from media_evidence.broker import BrokerServer
from media_evidence.broker_client import BrokerClient, BrokerRemoteError
from media_evidence.broker_protocol import (
    MAX_REQUEST_BYTES,
    encode_request,
    make_request,
    receive_response,
)
from media_evidence.contracts import MediaEvidenceError


PRIVATE_PATH = "/data/media-evidence/runs/mev_secret/manifest.json"
JOB_ID = "mev_" + "1" * 24
TRACE_ID = "2" * 32
SHA256 = "3" * 64


def capability_result() -> dict:
    return {
        "ok": True,
        "schema": "media-evidence/v1",
        "tool_version": "1.0.0",
        "media_kinds": ["audio", "document", "image", "video"],
        "source_adapters": ["https", "local"],
        "cloud_egress": "denied",
        "sandbox": {
            "seccomp": True,
            "landlock_abi": 3,
            "dedicated_identity": True,
            "dedicated_acquisition_identity": True,
            "aggregate_resource_limits": True,
        },
        "malware_scanner": {
            "status": "current",
            "file": "daily.cvd",
            "files": 3,
            "bytes": 1024,
            "mtime_ns": 123,
            "sha256": SHA256,
        },
        "transcription_model": {
            "status": "available",
            "repository": "Systran/faster-whisper-base.en",
            "revision": "4" * 40,
            "model_sha256": "5" * 64,
            "bytes": 2048,
        },
        "binaries": {
            name: f"/usr/bin/{name}"
            for name in (
                "clamscan",
                "exiftool",
                "ffmpeg",
                "ffprobe",
                "file",
                "pdfinfo",
                "pdftoppm",
                "pdftotext",
                "qpdf",
                "tesseract",
            )
        },
        "manifest_path": PRIVATE_PATH,
        "text": "attacker-controlled extracted content",
    }


class FakePipeline:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.capabilities_entered: threading.Event | None = None
        self.capabilities_release: threading.Event | None = None
        self.capabilities_exception: Exception | None = None

    def capabilities(self) -> dict:
        self.calls.append(("capabilities", None))
        if self.capabilities_entered is not None:
            self.capabilities_entered.set()
        if self.capabilities_release is not None:
            self.capabilities_release.wait(2)
        if self.capabilities_exception is not None:
            raise self.capabilities_exception
        return capability_result()

    def analyze(self, **arguments) -> dict:
        self.calls.append(("analyze", arguments))
        return {
            "ok": True,
            "cached": False,
            "job_id": JOB_ID,
            "trace_id": TRACE_ID,
            "source_sha256": SHA256,
            "media_kind": "document",
            "quality_tier": "complete",
            "evidence_count": 2,
            "queue_wait_ms": 1,
            "duration_ms": 2,
            "manifest_path": PRIVATE_PATH,
            "text": "attacker-controlled extracted content",
        }

    def status(self, job_id: str) -> dict:
        self.calls.append(("status", job_id))
        return {
            "ok": True,
            "job_id": job_id,
            "state": "completed",
            "stage": "published",
            "trace_id": TRACE_ID,
            "created_at": "2026-08-28T12:00:00.000Z",
            "updated_at": "2026-08-28T12:00:01.000Z",
            "manifest_path": PRIVATE_PATH,
        }

    def validate_claims(self, *, job_id: str, claims: list[dict]) -> dict:
        self.calls.append(("validate_claims", (job_id, claims)))
        return {
            "ok": True,
            "job_id": job_id,
            "accepted": len(claims),
            "rejected": 0,
            "ledger_path": "/data/media-evidence/ledgers/private.jsonl",
            "ledger_sha256": "6" * 64,
            "text": "attacker-controlled extracted content",
        }


class MediaEvidenceBrokerServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.running: list[tuple[BrokerServer, threading.Thread]] = []

    def tearDown(self) -> None:
        for server, thread in reversed(self.running):
            server.shutdown()
            thread.join(timeout=2)
        self.temporary.cleanup()

    def server(self, name: str, pipeline: FakePipeline, **overrides) -> BrokerServer:
        return BrokerServer(
            socket_path=self.base / name / "broker.sock",
            pipeline=pipeline,
            gateway_uid=os.getuid(),
            gateway_gid=os.getgid(),
            require_root=False,
            socket_owner_uid=os.geteuid(),
            set_ownership=False,
            request_timeout=1.0,
            **overrides,
        )

    def start_server(self, server: BrokerServer) -> threading.Thread:
        server.start()
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"install_signal_handlers": False},
            daemon=True,
        )
        thread.start()
        self.running.append((server, thread))
        return thread

    @staticmethod
    def client(server: BrokerServer, *, timeout: float = 1.0) -> BrokerClient:
        return BrokerClient(
            socket_path=server.socket_path,
            timeout=timeout,
            gateway_gid=os.getgid(),
            expected_socket_uid=os.geteuid(),
        )

    def test_server_dispatches_only_fixed_operations_over_secured_socket(self) -> None:
        pipeline = FakePipeline()
        server = self.server("dispatch", pipeline)
        self.start_server(server)
        client = self.client(server)

        health = client.health()
        self.assertEqual(health["protocol"], "media-evidence-broker/v1")
        self.assertEqual(health["limits"]["active_handlers"], 8)
        capabilities = client.capabilities()
        self.assertTrue(capabilities["ok"])
        self.assertTrue(all(isinstance(value, bool) for value in capabilities["binaries"].values()))
        analysis = client.analyze(
            source_path="/data/workspace/input.pdf",
            rights_basis="user_provided",
            privacy="private",
            purpose="test",
        )
        status = client.status(JOB_ID)
        validated = client.validate_claims(
            job_id=JOB_ID,
            claims=[{"claim": "x", "evidence_ids": ["e1"]}],
        )
        self.assertTrue(analysis["ok"])
        self.assertTrue(status["ok"])
        self.assertEqual(validated["accepted"], 1)
        public_responses = json.dumps([capabilities, analysis, status, validated], sort_keys=True)
        self.assertNotIn(PRIVATE_PATH, public_responses)
        self.assertNotIn("manifest_path", public_responses)
        self.assertNotIn("ledger_path", public_responses)
        self.assertNotIn("attacker-controlled", public_responses)
        self.assertEqual(
            [call[0] for call in pipeline.calls],
            ["capabilities", "analyze", "status", "validate_claims"],
        )
        self.assertEqual(server.socket_path.parent.stat().st_mode & 0o7777, 0o750)
        self.assertEqual(server.socket_path.stat().st_mode & 0o7777, 0o660)
        self.assertEqual(server.socket_path.stat().st_gid, os.getgid())

    def test_malformed_duplicate_and_oversized_requests_never_reach_pipeline(self) -> None:
        pipeline = FakePipeline()
        server = self.server("malformed", pipeline)
        self.start_server(server)
        duplicate = (
            b'{"arguments":{},"operation":"health","protocol":"media-evidence-broker/v1",'
            b'"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
        )
        for content in (
            struct.pack("!I", len(duplicate)) + duplicate,
            struct.pack("!I", MAX_REQUEST_BYTES + 1),
        ):
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.settimeout(1)
                connection.connect(os.fspath(server.socket_path))
                connection.sendall(content)
                connection.shutdown(socket.SHUT_WR)
                response = receive_response(connection)
                self.assertFalse(response["ok"])
            finally:
                connection.close()
        self.assertEqual(pipeline.calls, [])

    def test_peer_is_rejected_before_handler_or_request_read(self) -> None:
        pipeline = FakePipeline()
        server = self.server(
            "peer-reject",
            pipeline,
            peer_credentials_reader=lambda _connection: (123, os.getuid() + 1, os.getgid()),
        )
        self.start_server(server)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(1)
            connection.connect(os.fspath(server.socket_path))
            self.assertEqual(connection.recv(1), b"")
        finally:
            connection.close()
        self.assertEqual(server.active_handlers, 0)
        self.assertEqual(pipeline.calls, [])

    def test_active_handlers_are_bounded_and_saturation_closes_new_connection(self) -> None:
        pipeline = FakePipeline()
        pipeline.capabilities_entered = threading.Event()
        pipeline.capabilities_release = threading.Event()
        server = self.server("saturation", pipeline, max_handlers=1)
        self.start_server(server)
        client = self.client(server, timeout=2)
        result: list[dict] = []

        first = threading.Thread(target=lambda: result.append(client.capabilities()), daemon=True)
        first.start()
        self.assertTrue(pipeline.capabilities_entered.wait(1))
        self.assertEqual(server.active_handlers, 1)

        second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            second.settimeout(1)
            second.connect(os.fspath(server.socket_path))
            second.sendall(encode_request(make_request("c" * 32, "health", {})))
            second.shutdown(socket.SHUT_WR)
            try:
                closed = second.recv(1)
            except ConnectionResetError:
                closed = b""
            self.assertEqual(closed, b"")
        finally:
            second.close()
        self.assertEqual(server.active_handlers, 1)
        pipeline.capabilities_release.set()
        first.join(timeout=2)
        self.assertEqual(result[0]["schema"], "media-evidence/v1")

    def test_stale_owned_socket_is_replaced_but_unsafe_path_is_preserved(self) -> None:
        parent = self.base / "stale"
        parent.mkdir(mode=0o750)
        os.chmod(parent, 0o750)
        path = parent / "broker.sock"
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(os.fspath(path))
        stale.close()

        server = self.server("stale", FakePipeline())
        server.start()
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(os.fspath(server.socket_path))
        finally:
            probe.close()
        server.shutdown()

        unsafe_parent = self.base / "unsafe"
        unsafe_parent.mkdir(mode=0o750)
        os.chmod(unsafe_parent, 0o750)
        unsafe_path = unsafe_parent / "broker.sock"
        unsafe_path.write_text("do not unlink", encoding="utf-8")
        unsafe_server = self.server("unsafe", FakePipeline())
        with self.assertRaises(MediaEvidenceError):
            unsafe_server.start()
        self.assertEqual(unsafe_path.read_text(encoding="utf-8"), "do not unlink")

    def test_stale_socket_with_unexpected_owner_is_not_unlinked(self) -> None:
        parent = self.base / "owner"
        parent.mkdir(mode=0o750)
        path = parent / "broker.sock"
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(os.fspath(path))
        stale.close()
        server = BrokerServer(
            socket_path=path,
            pipeline=FakePipeline(),
            gateway_uid=os.getuid(),
            gateway_gid=os.getgid(),
            require_root=False,
            socket_owner_uid=os.geteuid() + 1,
            set_ownership=False,
        )
        with self.assertRaises(MediaEvidenceError):
            server._remove_stale_socket()
        self.assertTrue(path.exists())
        path.unlink()

    def test_internal_exception_and_logs_are_sanitized(self) -> None:
        secret = "SUPER_SECRET_/private/source/path"
        pipeline = FakePipeline()
        pipeline.capabilities_exception = RuntimeError(secret)
        stream = io.StringIO()
        logger = logging.getLogger(f"broker-test-{id(self)}")
        logger.handlers.clear()
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.StreamHandler(stream))
        server = self.server("sanitized", pipeline, logger=logger)
        self.start_server(server)

        with self.assertRaises(BrokerRemoteError) as raised:
            self.client(server).capabilities()
        self.assertEqual(raised.exception.code, "internal_error")
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, stream.getvalue())

    def test_oversized_pipeline_response_is_replaced_with_bounded_error(self) -> None:
        pipeline = FakePipeline()
        server = self.server("oversized-response", pipeline)
        server._dispatch = lambda _operation, _arguments: {"value": "x" * (1024 * 1024)}
        self.start_server(server)
        with self.assertRaises(BrokerRemoteError) as raised:
            self.client(server).capabilities()
        self.assertEqual(raised.exception.code, "response_too_large")

    def test_invalid_public_field_is_rejected_without_echoing_it(self) -> None:
        secret = "/private/attacker-controlled-field"
        pipeline = FakePipeline()
        original = pipeline.analyze

        def invalid_analyze(**arguments) -> dict:
            return {**original(**arguments), "media_kind": secret}

        pipeline.analyze = invalid_analyze
        server = self.server("invalid-public-field", pipeline)
        self.start_server(server)
        with self.assertRaises(BrokerRemoteError) as raised:
            self.client(server).analyze(
                source_path="/data/workspace/input.pdf",
                rights_basis="user_provided",
                privacy="private",
                purpose="test",
            )
        self.assertEqual(raised.exception.code, "internal_error")
        self.assertNotIn(secret, str(raised.exception))

    def test_rejected_claims_return_only_opaque_validation_metadata(self) -> None:
        pipeline = FakePipeline()
        pipeline.validate_claims = lambda **arguments: {
            "ok": False,
            "job_id": arguments["job_id"],
            "accepted": 0,
            "rejected": 1,
            "ledger_path": "/data/media-evidence/ledgers/private.jsonl",
            "ledger_sha256": "6" * 64,
            "claim": "attacker-controlled claim",
        }
        server = self.server("rejected-claim", pipeline)
        self.start_server(server)
        result = self.client(server).validate_claims(
            job_id=JOB_ID,
            claims=[{"claim": "x", "evidence_ids": ["e1"]}],
        )
        self.assertEqual(
            result,
            {
                "ok": False,
                "job_id": JOB_ID,
                "accepted": 0,
                "rejected": 1,
                "ledger_sha256": "6" * 64,
            },
        )

    def test_pipeline_factory_runs_once_and_root_check_precedes_initialization(self) -> None:
        calls = 0

        def factory() -> FakePipeline:
            nonlocal calls
            calls += 1
            return FakePipeline()

        server = BrokerServer(
            socket_path=self.base / "factory" / "broker.sock",
            pipeline_factory=factory,
            gateway_uid=os.getuid(),
            gateway_gid=os.getgid(),
            require_root=False,
            socket_owner_uid=os.geteuid(),
            set_ownership=False,
        )
        server._dispatch("health", {})
        server._dispatch("health", {})
        self.assertEqual(calls, 1)

        with self.assertRaises(MediaEvidenceError):
            BrokerServer(
                socket_path=self.base / "root" / "broker.sock",
                pipeline_factory=factory,
                gateway_uid=123,
                gateway_gid=123,
                require_root=True,
                euid_getter=lambda: 1000,
            )
        self.assertEqual(calls, 1)

    def test_shutdown_removes_only_the_socket_created_by_this_server(self) -> None:
        server = self.server("shutdown", FakePipeline())
        self.start_server(server)
        self.assertTrue(server.socket_path.exists())
        server._handle_signal(15, None)
        deadline = time.monotonic() + 1
        while server.socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(server.socket_path.exists())


if __name__ == "__main__":
    unittest.main()
