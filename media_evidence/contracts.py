from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


SCHEMA_ID = "media-evidence/v1"
WORKER_SCHEMA_ID = "media-evidence-worker/v1"
TOOL_VERSION = "1.0.0"

RIGHTS_BASES = {
    "user_provided",
    "licensed",
    "public_domain",
    "fair_use",
    "other_documented",
}
PRIVACY_CLASSES = {"private", "sensitive", "internal", "public"}
SCAN_POLICIES = {"required", "best_effort"}

DEFAULT_OPTIONS: dict[str, Any] = {
    "ocr": True,
    "transcribe": True,
    "scan_policy": "best_effort",
    "sample_interval_seconds": 30.0,
    "scene_threshold": 0.35,
    "max_frames": 24,
    "max_scene_frames": 12,
    "max_pages": 200,
    "max_render_pages": 25,
    "max_duration_seconds": 7200.0,
    "max_source_bytes": 512 * 1024 * 1024,
    "max_output_bytes": 1024 * 1024 * 1024,
    "max_pixels": 100_000_000,
    "worker_timeout_seconds": 900.0,
    "cpu_limit_seconds": 600,
    "memory_limit_mb": 4096,
    "file_limit_mb": 1024,
    "process_limit": 48,
    "open_file_limit": 256,
    "whisper_model": "base.en",
    "language": None,
    "require_qpdf": True,
}

_INTEGER_BOUNDS = {
    "max_frames": (1, 60),
    "max_scene_frames": (0, 60),
    "max_pages": (1, 500),
    "max_render_pages": (1, 100),
    "max_source_bytes": (1, 2 * 1024 * 1024 * 1024),
    "max_output_bytes": (1, 4 * 1024 * 1024 * 1024),
    "max_pixels": (1, 100_000_000),
    "cpu_limit_seconds": (10, 1800),
    "memory_limit_mb": (512, 8192),
    "file_limit_mb": (32, 2048),
    "process_limit": (4, 64),
    "open_file_limit": (32, 512),
}
_FLOAT_BOUNDS = {
    "sample_interval_seconds": (1.0, 300.0),
    "scene_threshold": (0.05, 0.95),
    "max_duration_seconds": (1.0, 7200.0),
    "worker_timeout_seconds": (10.0, 1800.0),
}


class MediaEvidenceError(RuntimeError):
    """A bounded error safe to return through the Hermes tool surface."""

    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ok": False, "error": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def hash_file(path: Path, *, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def normalize_options(raw: dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise MediaEvidenceError("invalid_arguments", "options must be an object")
    unknown = sorted(set(raw) - set(DEFAULT_OPTIONS))
    if unknown:
        raise MediaEvidenceError(
            "invalid_arguments",
            "options contain unsupported fields",
            details={"fields": unknown},
        )

    options = copy.deepcopy(DEFAULT_OPTIONS)
    options.update(raw)
    for name in ("ocr", "transcribe", "require_qpdf"):
        if not isinstance(options[name], bool):
            raise MediaEvidenceError("invalid_arguments", f"{name} must be a boolean")
    if options["scan_policy"] not in SCAN_POLICIES:
        raise MediaEvidenceError(
            "invalid_arguments",
            "scan_policy must be required or best_effort",
        )
    for name, (minimum, maximum) in _INTEGER_BOUNDS.items():
        value = options[name]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise MediaEvidenceError(
                "invalid_arguments",
                f"{name} must be an integer between {minimum} and {maximum}",
            )
    for name, (minimum, maximum) in _FLOAT_BOUNDS.items():
        value = options[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise MediaEvidenceError("invalid_arguments", f"{name} must be a number")
        value = float(value)
        if not minimum <= value <= maximum:
            raise MediaEvidenceError(
                "invalid_arguments",
                f"{name} must be between {minimum} and {maximum}",
            )
        options[name] = value

    if options["whisper_model"] != "base.en":
        raise MediaEvidenceError("invalid_arguments", "whisper_model must be base.en")
    language = options["language"]
    if language is not None:
        if not isinstance(language, str) or not 1 <= len(language) <= 16:
            raise MediaEvidenceError("invalid_arguments", "language is invalid")
        if not all(character.isalnum() or character in {"-", "_"} for character in language):
            raise MediaEvidenceError("invalid_arguments", "language contains unsupported characters")
    return options


def media_kind_for_mime(actual_mime: str) -> str:
    value = (actual_mime or "").lower().strip()
    if value == "application/pdf":
        return "document"
    if value.startswith("image/"):
        return "image"
    if value.startswith("audio/"):
        return "audio"
    if value.startswith("video/"):
        return "video"
    raise MediaEvidenceError(
        "unsupported_media_type",
        "The detected media type is not supported",
        details={"actual_mime": value or "unknown"},
    )


def atomic_write_bytes(path: Path, content: bytes, *, mode: int = 0o440) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_json(path: Path, value: Any, *, mode: int = 0o440) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value) + b"\n", mode=mode)


def atomic_write_jsonl(path: Path, values: Iterable[Any], *, mode: int = 0o440) -> None:
    content = b"".join(canonical_json_bytes(value) + b"\n" for value in values)
    atomic_write_bytes(path, content, mode=mode)


def sign_manifest(manifest: dict[str, Any], key: bytes) -> dict[str, Any]:
    if "integrity" in manifest:
        raise MediaEvidenceError("integrity_failure", "Manifest is already signed")
    payload = canonical_json_bytes(manifest)
    signed = copy.deepcopy(manifest)
    signed["integrity"] = {
        "algorithm": "hmac-sha256",
        "key_id": hashlib.sha256(key).hexdigest()[:16],
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": hmac.new(key, payload, hashlib.sha256).hexdigest(),
    }
    return signed


def verify_manifest(manifest: dict[str, Any], key_path: Path) -> bool:
    descriptor: int | None = None
    try:
        integrity = manifest["integrity"]
        if not isinstance(integrity, dict):
            return False
        integrity_values = (
            integrity.get("algorithm"),
            integrity.get("key_id"),
            integrity.get("payload_sha256"),
            integrity.get("signature"),
        )
        if not all(isinstance(value, str) for value in integrity_values):
            return False
        unsigned = copy.deepcopy(manifest)
        del unsigned["integrity"]
        payload = canonical_json_bytes(unsigned)
        descriptor = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != 32
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or (os.geteuid() == 0 and metadata.st_uid != 0)
        ):
            return False
        key = os.read(descriptor, 33)
        if len(key) != 32:
            return False
        expected_payload = hashlib.sha256(payload).hexdigest()
        expected_key_id = hashlib.sha256(key).hexdigest()[:16]
        expected_signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return (
            integrity.get("algorithm") == "hmac-sha256"
            and hmac.compare_digest(integrity.get("payload_sha256", ""), expected_payload)
            and hmac.compare_digest(integrity.get("key_id", ""), expected_key_id)
            and hmac.compare_digest(integrity.get("signature", ""), expected_signature)
        )
    except (KeyError, OSError, TypeError, ValueError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


@lru_cache(maxsize=1)
def _manifest_schema() -> dict[str, Any]:
    path = Path(__file__).with_name("schemas") / "media-evidence-v1.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MediaEvidenceError("configuration_error", "The media evidence manifest schema is unavailable") from exc
    if not isinstance(schema, dict):
        raise MediaEvidenceError("configuration_error", "The media evidence manifest schema is invalid")
    return schema


def validate_manifest_schema(manifest: dict[str, Any]) -> None:
    """Validate manifests without adding a runtime JSON Schema dependency."""

    try:
        _validate_schema_value(manifest, _manifest_schema(), path="$")
    except MediaEvidenceError:
        raise
    except (TypeError, ValueError) as exc:
        raise MediaEvidenceError("manifest_contract_error", "Manifest failed schema validation") from exc


def _validate_schema_value(value: Any, schema: dict[str, Any], *, path: str) -> None:
    any_of = schema.get("anyOf")
    if any_of is not None:
        for candidate in any_of:
            try:
                _validate_schema_value(value, candidate, path=path)
            except MediaEvidenceError:
                continue
            break
        else:
            raise MediaEvidenceError(
                "manifest_contract_error",
                f"Manifest field {path} does not match any allowed schema",
            )

    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(_matches_json_type(value, item) for item in expected_types):
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has an invalid type")

    if "const" in schema and value != schema["const"]:
        raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has an invalid constant")
    if "enum" in schema and value not in schema["enum"]:
        raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has an invalid value")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} is missing required keys")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = set(value) - set(properties)
            if unexpected:
                raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has unexpected keys")
        for key, child in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _validate_schema_value(child, child_schema, path=f"{path}.{key}")
        return

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None and len(value) < minimum:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has too few items")
        if maximum is not None and len(value) > maximum:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has too many items")
        if schema.get("uniqueItems"):
            identities = [canonical_json_bytes(item) for item in value]
            if len(set(identities)) != len(identities):
                raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has duplicate items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema_value(item, item_schema, path=f"{path}[{index}]")
        return

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} is too long")
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, value) is None:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} has an invalid format")
        if schema.get("format") == "date-time":
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} is not a timestamp") from exc
            if parsed.tzinfo is None:
                raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} is not timezone-aware")
        return

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} is below its minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise MediaEvidenceError("manifest_contract_error", f"Manifest field {path} exceeds its maximum")


def _matches_json_type(value: Any, expected: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(expected, False)
