from __future__ import annotations

import socket
import struct
import threading
import unittest

from media_evidence.broker_protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_ID,
    BrokerProtocolError,
    decode_canonical_json,
    encode_frame,
    encode_request,
    make_request,
    make_success_response,
    receive_frame,
    receive_request,
    receive_response,
    validate_request,
    validate_response,
)


class MediaEvidenceBrokerProtocolTests(unittest.TestCase):
    request_id = "a" * 32

    @staticmethod
    def framed(payload: bytes) -> bytes:
        return struct.pack("!I", len(payload)) + payload

    def test_fragmented_request_round_trip_is_canonical_and_bounded(self) -> None:
        request = make_request(self.request_id, "health", {})
        frame = encode_request(request)
        self.assertEqual(struct.unpack("!I", frame[:4])[0], len(frame) - 4)
        self.assertEqual(
            frame[4:],
            b'{"arguments":{},"operation":"health","protocol":"media-evidence-broker/v1",'
            b'"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
        )

        receiver, sender = socket.socketpair()
        try:
            def write_fragments() -> None:
                for offset in range(0, len(frame), 3):
                    sender.sendall(frame[offset : offset + 3])
                sender.shutdown(socket.SHUT_WR)

            thread = threading.Thread(target=write_fragments)
            thread.start()
            self.assertEqual(receive_request(receiver), request)
            thread.join()
        finally:
            receiver.close()
            sender.close()

    def test_framing_rejects_zero_oversized_truncated_and_multiple_frames(self) -> None:
        cases = (
            struct.pack("!I", 0),
            struct.pack("!I", MAX_REQUEST_BYTES + 1),
            b"\x00\x00",
            self.framed(b"{}") + self.framed(b"{}"),
        )
        for index, content in enumerate(cases):
            with self.subTest(index=index):
                receiver, sender = socket.socketpair()
                try:
                    sender.sendall(content)
                    sender.shutdown(socket.SHUT_WR)
                    with self.assertRaises(BrokerProtocolError):
                        receive_frame(
                            receiver,
                            max_payload_bytes=MAX_REQUEST_BYTES,
                            require_eof=True,
                        )
                finally:
                    receiver.close()
                    sender.close()

    def test_json_rejects_malformed_duplicate_noncanonical_and_nonfinite_values(self) -> None:
        payloads = (
            b"{",
            b'{"a":1,"a":2}',
            b'{"a": 1}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1e9999}',
            b'{"a":"\xff"}',
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(BrokerProtocolError):
                decode_canonical_json(payload)

    def test_request_requires_exact_envelope_operation_and_argument_fields(self) -> None:
        valid = make_request(self.request_id, "status", {"job_id": "mev_" + "1" * 24})
        mutations = (
            {**valid, "extra": True},
            {**valid, "protocol": "media-evidence-broker/v2"},
            {**valid, "request_id": "A" * 32},
            {**valid, "operation": "read_file"},
            {**valid, "arguments": {"job_id": "mev_" + "1" * 24, "sql": "SELECT 1"}},
            {**valid, "arguments": {}},
        )
        for request in mutations:
            with self.subTest(request=request), self.assertRaises(BrokerProtocolError):
                validate_request(request)

    def test_analyze_and_claim_nested_fields_are_allowlisted(self) -> None:
        base_analyze = {
            "source_path": "/data/workspace/input.pdf",
            "rights_basis": "user_provided",
            "privacy": "private",
            "purpose": "test",
        }
        make_request(self.request_id, "analyze", base_analyze)
        make_request(
            self.request_id,
            "analyze",
            {
                **base_analyze,
                "options": {
                    "ocr": False,
                    "transcribe": False,
                    "scan_policy": "required",
                    "require_qpdf": False,
                    "max_source_bytes": 1024 * 1024,
                    "max_output_bytes": 16 * 1024 * 1024,
                    "max_pixels": 4096,
                    "worker_timeout_seconds": 120.0,
                    "cpu_limit_seconds": 120,
                    "memory_limit_mb": 1024,
                    "file_limit_mb": 32,
                    "process_limit": 16,
                    "open_file_limit": 64,
                },
            },
        )
        with self.assertRaises(BrokerProtocolError):
            make_request(
                self.request_id,
                "analyze",
                {**base_analyze, "options": {"read_path": "/etc/shadow"}},
            )
        with self.assertRaises(BrokerProtocolError):
            make_request(
                self.request_id,
                "analyze",
                {**base_analyze, "options": {"max_source_bytes": 3 * 1024 * 1024 * 1024}},
            )
        with self.assertRaises(BrokerProtocolError):
            make_request(
                self.request_id,
                "validate_claims",
                {
                    "job_id": "mev_" + "1" * 24,
                    "claims": [{"claim": "x", "evidence_ids": ["e1"], "sql": "DELETE"}],
                },
            )

    def test_response_requires_exact_shape_and_correlation(self) -> None:
        response = make_success_response(self.request_id, {"ok": True})
        self.assertEqual(validate_response(response, expected_request_id=self.request_id), response)
        with self.assertRaises(BrokerProtocolError):
            validate_response({**response, "extra": True})
        with self.assertRaises(BrokerProtocolError):
            validate_response(response, expected_request_id="b" * 32)
        with self.assertRaises(BrokerProtocolError):
            validate_response({**response, "result": {"value": float("nan")}})

    def test_response_reader_rejects_trailing_data_and_response_limit(self) -> None:
        response = make_success_response(self.request_id, {"ok": True})
        frame = encode_frame(response, max_payload_bytes=MAX_RESPONSE_BYTES)
        receiver, sender = socket.socketpair()
        try:
            sender.sendall(frame + b"x")
            sender.shutdown(socket.SHUT_WR)
            with self.assertRaises(BrokerProtocolError):
                receive_response(receiver, expected_request_id=self.request_id)
        finally:
            receiver.close()
            sender.close()
        with self.assertRaises(BrokerProtocolError):
            encode_frame({"value": "x" * 20}, max_payload_bytes=10)

    def test_protocol_identifier_is_fixed(self) -> None:
        self.assertEqual(PROTOCOL_ID, "media-evidence-broker/v1")


if __name__ == "__main__":
    unittest.main()
