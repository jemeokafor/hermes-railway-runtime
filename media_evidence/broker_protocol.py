from __future__ import annotations

import json
import math
import re
import socket
import struct
from typing import Any, Callable

from .contracts import MediaEvidenceError, canonical_json_bytes, normalize_options


PROTOCOL_ID = "media-evidence-broker/v1"
PROTOCOL = PROTOCOL_ID
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
FRAME_HEADER_BYTES = 4
NULL_REQUEST_ID = "0" * 32

REQUEST_FIELDS = frozenset({"protocol", "request_id", "operation", "arguments"})
ALLOWED_OPERATIONS = frozenset(
    {"health", "capabilities", "analyze", "status", "validate_claims"}
)
ANALYZE_ARGUMENT_FIELDS = frozenset(
    {
        "source_path",
        "source_url",
        "allow_network_acquisition",
        "rights_basis",
        "privacy",
        "purpose",
        "options",
    }
)
ANALYZE_OPTION_FIELDS = frozenset(
    {
        "ocr",
        "transcribe",
        "scan_policy",
        "sample_interval_seconds",
        "scene_threshold",
        "max_frames",
        "max_scene_frames",
        "max_pages",
        "max_render_pages",
        "max_duration_seconds",
        "max_source_bytes",
        "max_output_bytes",
        "max_pixels",
        "worker_timeout_seconds",
        "cpu_limit_seconds",
        "memory_limit_mb",
        "file_limit_mb",
        "process_limit",
        "open_file_limit",
        "language",
        "whisper_model",
        "require_qpdf",
    }
)
OPERATION_ARGUMENT_FIELDS = {
    "health": frozenset(),
    "capabilities": frozenset(),
    "analyze": ANALYZE_ARGUMENT_FIELDS,
    "status": frozenset({"job_id"}),
    "validate_claims": frozenset({"job_id", "claims"}),
}

_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FRAME_HEADER = struct.Struct("!I")
_SUCCESS_RESPONSE_FIELDS = frozenset({"protocol", "request_id", "ok", "result"})
_ERROR_RESPONSE_FIELDS = frozenset({"protocol", "request_id", "ok", "error"})
_ERROR_FIELDS = frozenset({"code", "message"})
_CLAIM_FIELDS = frozenset({"claim", "evidence_ids", "quotations"})
_QUOTATION_FIELDS = frozenset({"evidence_id", "quote"})


class BrokerProtocolError(MediaEvidenceError):
    """A bounded protocol failure that never includes peer-controlled content."""

    def __init__(self, code: str, message: str, *, request_id: str | None = None):
        super().__init__(code, message)
        self.request_id = request_id


ProtocolError = BrokerProtocolError


def is_request_id(value: Any) -> bool:
    return isinstance(value, str) and _REQUEST_ID.fullmatch(value) is not None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerProtocolError(
                "duplicate_json_key",
                "The broker message contains a duplicate JSON key",
            )
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise BrokerProtocolError(
        "non_finite_json",
        "The broker message contains a non-finite number",
    )


def _has_non_finite_number(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, list):
        return any(_has_non_finite_number(item) for item in value)
    if isinstance(value, dict):
        return any(_has_non_finite_number(item) for item in value.values())
    return False


def decode_canonical_json(payload: bytes) -> Any:
    if not isinstance(payload, bytes):
        raise BrokerProtocolError("malformed_json", "The broker message is not valid JSON")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except BrokerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError) as exc:
        raise BrokerProtocolError(
            "malformed_json",
            "The broker message is not valid JSON",
        ) from exc
    if _has_non_finite_number(value):
        raise BrokerProtocolError(
            "non_finite_json",
            "The broker message contains a non-finite number",
        )
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise BrokerProtocolError(
            "malformed_json",
            "The broker message is not valid JSON",
        ) from exc
    if payload != canonical:
        raise BrokerProtocolError(
            "non_canonical_json",
            "The broker message is not canonical JSON",
        )
    return value


def encode_frame(value: Any, *, max_payload_bytes: int) -> bytes:
    if not isinstance(max_payload_bytes, int) or isinstance(max_payload_bytes, bool) or max_payload_bytes < 1:
        raise ValueError("max_payload_bytes must be a positive integer")
    try:
        payload = canonical_json_bytes(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise BrokerProtocolError(
            "invalid_json_value",
            "The broker message cannot be encoded as canonical JSON",
        ) from exc
    if not payload or len(payload) > max_payload_bytes:
        raise BrokerProtocolError(
            "frame_too_large",
            "The broker message exceeds its byte limit",
        )
    return _FRAME_HEADER.pack(len(payload)) + payload


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    content = bytearray()
    while len(content) < size:
        try:
            chunk = connection.recv(size - len(content))
        except InterruptedError:
            continue
        except TimeoutError as exc:
            raise BrokerProtocolError(
                "frame_timeout",
                "The broker message was not received in time",
            ) from exc
        if not chunk:
            raise BrokerProtocolError(
                "truncated_frame",
                "The broker connection ended before one complete message was received",
            )
        content.extend(chunk)
    return bytes(content)


def receive_frame(
    connection: socket.socket,
    *,
    max_payload_bytes: int,
    require_eof: bool = False,
) -> bytes:
    if not isinstance(max_payload_bytes, int) or isinstance(max_payload_bytes, bool) or max_payload_bytes < 1:
        raise ValueError("max_payload_bytes must be a positive integer")
    header = _recv_exact(connection, FRAME_HEADER_BYTES)
    (payload_size,) = _FRAME_HEADER.unpack(header)
    if payload_size == 0:
        raise BrokerProtocolError("empty_frame", "The broker message is empty")
    if payload_size > max_payload_bytes:
        raise BrokerProtocolError(
            "frame_too_large",
            "The broker message exceeds its byte limit",
        )
    payload = _recv_exact(connection, payload_size)
    if require_eof:
        try:
            trailing = connection.recv(1)
        except InterruptedError:
            trailing = connection.recv(1)
        except TimeoutError as exc:
            raise BrokerProtocolError(
                "frame_timeout",
                "The broker connection did not finish one message in time",
            ) from exc
        if trailing:
            raise BrokerProtocolError(
                "multiple_frames",
                "The broker connection contains more than one message",
            )
    return payload


def reject_buffered_trailing_data(connection: socket.socket) -> None:
    """Reject a pipelined second frame without requiring request half-close."""

    try:
        trailing = connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
    except (BlockingIOError, InterruptedError):
        return
    if trailing:
        raise BrokerProtocolError(
            "multiple_frames",
            "The broker connection contains more than one message",
        )


def send_frame(connection: socket.socket, value: Any, *, max_payload_bytes: int) -> None:
    connection.sendall(encode_frame(value, max_payload_bytes=max_payload_bytes))


def _request_error(code: str, message: str, request_id: str | None) -> BrokerProtocolError:
    return BrokerProtocolError(code, message, request_id=request_id)


def validate_request(value: Any) -> dict[str, Any]:
    request_id = value.get("request_id") if isinstance(value, dict) else None
    correlated_id = request_id if is_request_id(request_id) else None
    if _has_non_finite_number(value):
        raise _request_error(
            "non_finite_json",
            "The broker request contains a non-finite number",
            correlated_id,
        )
    if not isinstance(value, dict):
        raise _request_error("invalid_request", "The broker request must be an object", None)
    if set(value) != REQUEST_FIELDS:
        raise _request_error(
            "invalid_request",
            "The broker request fields are invalid",
            correlated_id,
        )
    if value["protocol"] != PROTOCOL_ID:
        raise _request_error(
            "unsupported_protocol",
            "The broker protocol is unsupported",
            correlated_id,
        )
    if not is_request_id(value["request_id"]):
        raise _request_error("invalid_request_id", "The broker request ID is invalid", None)
    operation = value["operation"]
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise _request_error(
            "unsupported_operation",
            "The broker operation is unsupported",
            correlated_id,
        )
    arguments = value["arguments"]
    if not isinstance(arguments, dict):
        raise _request_error(
            "invalid_arguments",
            "The broker operation arguments must be an object",
            correlated_id,
        )
    allowed_fields = OPERATION_ARGUMENT_FIELDS[operation]
    if not set(arguments).issubset(allowed_fields):
        raise _request_error(
            "invalid_arguments",
            "The broker operation arguments contain unsupported fields",
            correlated_id,
        )

    if operation in {"health", "capabilities"} and arguments:
        raise _request_error(
            "invalid_arguments",
            "The broker operation does not accept arguments",
            correlated_id,
        )
    if operation == "analyze":
        required = {"rights_basis", "privacy", "purpose"}
        if not required.issubset(arguments):
            raise _request_error(
                "invalid_arguments",
                "The analyze operation is missing required arguments",
                correlated_id,
            )
        sources = sum(arguments.get(name) is not None for name in ("source_path", "source_url"))
        if sources != 1:
            raise _request_error(
                "invalid_arguments",
                "The analyze operation requires exactly one source",
                correlated_id,
            )
        if "allow_network_acquisition" in arguments and not isinstance(
            arguments["allow_network_acquisition"], bool
        ):
            raise _request_error(
                "invalid_arguments",
                "The network acquisition flag must be a boolean",
                correlated_id,
            )
        options = arguments.get("options")
        if options is not None:
            if not isinstance(options, dict) or not set(options).issubset(ANALYZE_OPTION_FIELDS):
                raise _request_error(
                    "invalid_arguments",
                    "The analyze options contain unsupported fields",
                    correlated_id,
                )
            try:
                normalize_options(options)
            except MediaEvidenceError as exc:
                raise _request_error(
                    "invalid_arguments",
                    "The analyze options are invalid",
                    correlated_id,
                ) from exc
    if operation == "status" and set(arguments) != {"job_id"}:
        raise _request_error(
            "invalid_arguments",
            "The status operation requires exactly one job ID",
            correlated_id,
        )
    if operation == "validate_claims":
        if set(arguments) != {"job_id", "claims"}:
            raise _request_error(
                "invalid_arguments",
                "The claim validation operation fields are invalid",
                correlated_id,
            )
        claims = arguments["claims"]
        if not isinstance(claims, list):
            raise _request_error(
                "invalid_arguments",
                "Claims must be an array",
                correlated_id,
            )
        for claim in claims:
            if (
                not isinstance(claim, dict)
                or not {"claim", "evidence_ids"}.issubset(claim)
                or not set(claim).issubset(_CLAIM_FIELDS)
            ):
                raise _request_error(
                    "invalid_arguments",
                    "A claim contains unsupported fields",
                    correlated_id,
                )
            quotations = claim.get("quotations", [])
            if not isinstance(quotations, list):
                raise _request_error(
                    "invalid_arguments",
                    "Claim quotations must be an array",
                    correlated_id,
                )
            if any(
                not isinstance(quotation, dict)
                or set(quotation) != _QUOTATION_FIELDS
                for quotation in quotations
            ):
                raise _request_error(
                    "invalid_arguments",
                    "A claim quotation contains unsupported fields",
                    correlated_id,
                )
    return value


def make_request(request_id: str, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return validate_request(
        {
            "protocol": PROTOCOL_ID,
            "request_id": request_id,
            "operation": operation,
            "arguments": arguments,
        }
    )


def encode_request(request: dict[str, Any]) -> bytes:
    return encode_frame(validate_request(request), max_payload_bytes=MAX_REQUEST_BYTES)


def receive_request(connection: socket.socket) -> dict[str, Any]:
    payload = receive_frame(connection, max_payload_bytes=MAX_REQUEST_BYTES)
    return validate_request(decode_canonical_json(payload))


def make_success_response(request_id: str, result: dict[str, Any]) -> dict[str, Any]:
    response = {
        "protocol": PROTOCOL_ID,
        "request_id": request_id,
        "ok": True,
        "result": result,
    }
    return validate_response(response)


def make_error_response(request_id: str, code: str, message: str) -> dict[str, Any]:
    response = {
        "protocol": PROTOCOL_ID,
        "request_id": request_id,
        "ok": False,
        "error": {"code": code, "message": message},
    }
    return validate_response(response)


def validate_response(value: Any, *, expected_request_id: str | None = None) -> dict[str, Any]:
    if _has_non_finite_number(value):
        raise BrokerProtocolError(
            "non_finite_json",
            "The broker response contains a non-finite number",
        )
    if not isinstance(value, dict):
        raise BrokerProtocolError("invalid_response", "The broker response must be an object")
    if value.get("protocol") != PROTOCOL_ID:
        raise BrokerProtocolError("invalid_response", "The broker response protocol is invalid")
    request_id = value.get("request_id")
    if not is_request_id(request_id):
        raise BrokerProtocolError("invalid_response", "The broker response request ID is invalid")
    if expected_request_id is not None and request_id != expected_request_id:
        raise BrokerProtocolError(
            "response_correlation_failed",
            "The broker response does not match the request",
        )
    ok = value.get("ok")
    if ok is True:
        if set(value) != _SUCCESS_RESPONSE_FIELDS or not isinstance(value.get("result"), dict):
            raise BrokerProtocolError("invalid_response", "The broker success response is invalid")
    elif ok is False:
        if set(value) != _ERROR_RESPONSE_FIELDS or not isinstance(value.get("error"), dict):
            raise BrokerProtocolError("invalid_response", "The broker error response is invalid")
        error = value["error"]
        if set(error) != _ERROR_FIELDS:
            raise BrokerProtocolError("invalid_response", "The broker error response is invalid")
        code = error.get("code")
        message = error.get("message")
        if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
            raise BrokerProtocolError("invalid_response", "The broker error code is invalid")
        if (
            not isinstance(message, str)
            or not 1 <= len(message) <= 512
            or any(ord(character) < 32 or ord(character) == 127 for character in message)
        ):
            raise BrokerProtocolError("invalid_response", "The broker error message is invalid")
    else:
        raise BrokerProtocolError("invalid_response", "The broker response status is invalid")
    return value


def encode_response(response: dict[str, Any]) -> bytes:
    return encode_frame(validate_response(response), max_payload_bytes=MAX_RESPONSE_BYTES)


def receive_response(
    connection: socket.socket,
    *,
    expected_request_id: str | None = None,
) -> dict[str, Any]:
    payload = receive_frame(
        connection,
        max_payload_bytes=MAX_RESPONSE_BYTES,
        require_eof=True,
    )
    return validate_response(
        decode_canonical_json(payload),
        expected_request_id=expected_request_id,
    )


def send_response(connection: socket.socket, response: dict[str, Any]) -> None:
    connection.sendall(encode_response(response))


RequestIdFactory = Callable[[], str]
