from __future__ import annotations

import re
from typing import Any, NoReturn

from .contracts import SCHEMA_ID, TOOL_VERSION, MediaEvidenceError


_SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_JOB_ID = re.compile(r"^mev_[0-9a-f]{24}$")
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_PUBLIC_BINARIES = {
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
}


def public_pipeline_result(operation: str, result: Any) -> dict[str, Any]:
    """Project privileged pipeline output onto the model-facing opaque contract."""

    def invalid() -> NoReturn:
        raise MediaEvidenceError(
            "internal_error",
            "The media evidence response failed validation",
        )

    def require_object(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            invalid()
        return value

    def require_bool(value: Any) -> bool:
        if not isinstance(value, bool):
            invalid()
        return value

    def require_integer(value: Any, *, maximum: int = 2**63 - 1) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            invalid()
        return value

    def require_optional_integer(value: Any) -> int | None:
        if value is None:
            return None
        return require_integer(value)

    def require_pattern(value: Any, pattern: re.Pattern[str]) -> str:
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            invalid()
        return value

    result = require_object(result)
    if operation != "validate_claims" and result.get("ok") is not True:
        invalid()

    if operation == "capabilities":
        if (
            result.get("schema") != SCHEMA_ID
            or result.get("tool_version") != TOOL_VERSION
            or result.get("media_kinds") != ["audio", "document", "image", "video"]
            or result.get("source_adapters") != ["https", "local"]
            or result.get("cloud_egress") != "denied"
        ):
            invalid()
        sandbox = require_object(result.get("sandbox"))
        landlock_abi = sandbox.get("landlock_abi")
        if landlock_abi is not None:
            landlock_abi = require_integer(landlock_abi, maximum=64)

        scanner = require_object(result.get("malware_scanner"))
        scanner_status = scanner.get("status")
        if scanner_status not in {"missing", "invalid", "current", "stale", "future_dated"}:
            invalid()
        scanner_sha256 = scanner.get("sha256")
        if scanner_sha256 is not None:
            scanner_sha256 = require_pattern(scanner_sha256, _HEX_64)

        model = require_object(result.get("transcription_model"))
        model_status = model.get("status")
        if model_status not in {"invalid", "missing", "unprovenanced", "corrupt", "available"}:
            invalid()
        repository = model.get("repository")
        if repository not in {None, "Systran/faster-whisper-base.en"}:
            invalid()
        revision = model.get("revision")
        if revision is not None:
            revision = require_pattern(revision, _HEX_40)
        model_sha256 = model.get("model_sha256")
        if model_sha256 is not None:
            model_sha256 = require_pattern(model_sha256, _HEX_64)

        binaries = require_object(result.get("binaries"))
        if set(binaries) != set(_PUBLIC_BINARIES):
            invalid()
        public_binaries: dict[str, bool] = {}
        for name, expected_path in _PUBLIC_BINARIES.items():
            value = binaries[name]
            if value not in {None, expected_path}:
                invalid()
            public_binaries[name] = value == expected_path

        return {
            "ok": True,
            "schema": SCHEMA_ID,
            "tool_version": TOOL_VERSION,
            "media_kinds": list(result["media_kinds"]),
            "source_adapters": list(result["source_adapters"]),
            "cloud_egress": "denied",
            "sandbox": {
                "seccomp": require_bool(sandbox.get("seccomp")),
                "landlock_abi": landlock_abi,
                "dedicated_identity": require_bool(sandbox.get("dedicated_identity")),
                "dedicated_acquisition_identity": require_bool(
                    sandbox.get("dedicated_acquisition_identity")
                ),
                "aggregate_resource_limits": require_bool(
                    sandbox.get("aggregate_resource_limits")
                ),
            },
            "malware_scanner": {
                "status": scanner_status,
                "files": require_integer(scanner.get("files"), maximum=10_000),
                "bytes": require_optional_integer(scanner.get("bytes")),
                "mtime_ns": require_optional_integer(scanner.get("mtime_ns")),
                "sha256": scanner_sha256,
            },
            "transcription_model": {
                "status": model_status,
                "repository": repository,
                "revision": revision,
                "model_sha256": model_sha256,
                "bytes": require_optional_integer(model.get("bytes")),
            },
            "binaries": public_binaries,
        }

    if operation == "analyze":
        media_kind = result.get("media_kind")
        quality_tier = result.get("quality_tier")
        if media_kind not in {"audio", "document", "image", "video"}:
            invalid()
        if quality_tier not in {"complete", "partial"}:
            invalid()
        return {
            "ok": True,
            "cached": require_bool(result.get("cached")),
            "job_id": require_pattern(result.get("job_id"), _JOB_ID),
            "trace_id": require_pattern(result.get("trace_id"), _HEX_32),
            "source_sha256": require_pattern(result.get("source_sha256"), _HEX_64),
            "media_kind": media_kind,
            "quality_tier": quality_tier,
            "evidence_count": require_integer(result.get("evidence_count")),
            "queue_wait_ms": require_integer(result.get("queue_wait_ms")),
            "duration_ms": require_integer(result.get("duration_ms")),
        }

    if operation == "status":
        state = result.get("state")
        stage = result.get("stage")
        if state not in {"running", "completed", "failed"}:
            invalid()
        if stage not in {
            "queued",
            "recovering",
            "waiting_worker",
            "extracting",
            "validating",
            "failed",
            "recovered_published",
            "published",
        }:
            invalid()
        public_status: dict[str, Any] = {
            "ok": True,
            "job_id": require_pattern(result.get("job_id"), _JOB_ID),
            "state": state,
            "stage": stage,
            "trace_id": require_pattern(result.get("trace_id"), _HEX_32),
            "created_at": require_pattern(result.get("created_at"), _UTC_TIMESTAMP),
            "updated_at": require_pattern(result.get("updated_at"), _UTC_TIMESTAMP),
        }
        if "error_code" in result:
            public_status["error_code"] = require_pattern(result["error_code"], _SAFE_ERROR_CODE)
        return public_status

    if operation == "validate_claims":
        ok = require_bool(result.get("ok"))
        accepted = require_integer(result.get("accepted"), maximum=100)
        rejected = require_integer(result.get("rejected"), maximum=100)
        if accepted + rejected > 100 or ok != (rejected == 0):
            invalid()
        return {
            "ok": ok,
            "job_id": require_pattern(result.get("job_id"), _JOB_ID),
            "accepted": accepted,
            "rejected": rejected,
            "ledger_sha256": require_pattern(result.get("ledger_sha256"), _HEX_64),
        }

    invalid()
