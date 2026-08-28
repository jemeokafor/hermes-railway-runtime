#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from PIL import Image

from media_evidence.broker_client import BrokerClient
from media_evidence.contracts import MediaEvidenceError


DEFAULT_BROKER_SOCKET = "/run/hermes-media/broker.sock"
DEFAULT_INPUT_ROOTS = "/data/workspace:/data/.hermes/cache"
REQUIRED_BINARIES = {
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
}
_SAFE_ERROR_CODE = re.compile(r"^[a-z0-9_]{1,80}$")


def _error_code(exc: MediaEvidenceError) -> str:
    return exc.code if _SAFE_ERROR_CODE.fullmatch(exc.code) else "broker_error"


def _base_record(checked_at: int) -> dict[str, Any]:
    return {
        "ok": False,
        "schema": None,
        "tool_version": None,
        "malware_scanner": None,
        "transcription_model": None,
        "canary_job_id": None,
        "checked_at_epoch": checked_at,
        "failures": [],
    }


def _safe_input_root(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
    )


def _probe_private_network_rejection(client: Any, *, purpose: str) -> str | None:
    try:
        response = client.analyze(
            source_url="https://localhost/media-evidence-readiness",
            allow_network_acquisition=True,
            rights_basis="user_provided",
            privacy="internal",
            purpose=purpose,
            options={
                "ocr": False,
                "transcribe": False,
                "scan_policy": "required",
                "require_qpdf": False,
                "max_source_bytes": 1024 * 1024,
            },
        )
    except MediaEvidenceError as exc:
        if exc.code == "remote_address_rejected":
            return None
        return f"acquisition_sandbox_failed:{_error_code(exc)}"
    except Exception:
        return "broker_request_failed"

    if isinstance(response, dict) and response.get("ok") is False:
        code = response.get("error")
        if code == "remote_address_rejected":
            return None
        if isinstance(code, str) and _SAFE_ERROR_CODE.fullmatch(code):
            return f"acquisition_sandbox_failed:{code}"
        return "acquisition_sandbox_failed:broker_error"
    return "acquisition_private_dns_accepted"


def _run_canary(client: Any, *, input_root: Path, purpose: str) -> tuple[str | None, str | None]:
    if not _safe_input_root(input_root):
        return None, "canary_input_root_unsafe"

    descriptor, temporary_name = tempfile.mkstemp(
        dir=input_root,
        prefix=".media-evidence-readiness-",
        suffix=".png",
    )
    canary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            Image.new("RGB", (8, 8), (20, 40, 60)).save(stream, format="PNG")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            response = client.analyze(
                source_path=str(canary_path),
                rights_basis="user_provided",
                privacy="internal",
                purpose=purpose,
                options={
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
            )
        except MediaEvidenceError as exc:
            return None, f"media_canary_failed:{_error_code(exc)}"
        except Exception:
            return None, "broker_request_failed"
    finally:
        canary_path.unlink(missing_ok=True)

    if not isinstance(response, dict) or response.get("ok") is not True:
        code = response.get("error") if isinstance(response, dict) else None
        if isinstance(code, str) and _SAFE_ERROR_CODE.fullmatch(code):
            return None, f"media_canary_failed:{code}"
        return None, "media_canary_failed:broker_error"
    job_id = response.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        return None, "media_canary_failed:broker_contract_error"
    return job_id, None


def check_readiness(
    client: Any,
    *,
    input_roots: list[Path],
    deployment_id: str,
    checked_at: int | None = None,
) -> dict[str, Any]:
    checked_at = int(time.time()) if checked_at is None else checked_at
    record = _base_record(checked_at)
    try:
        capabilities = client.capabilities()
    except MediaEvidenceError as exc:
        record["failures"] = [f"broker_capabilities_failed:{_error_code(exc)}"]
        return record
    except Exception:
        record["failures"] = ["broker_unavailable"]
        return record

    if not isinstance(capabilities, dict) or capabilities.get("ok") is not True:
        record["failures"] = ["broker_capabilities_invalid"]
        return record

    record.update(
        {
            "schema": capabilities.get("schema"),
            "tool_version": capabilities.get("tool_version"),
            "malware_scanner": capabilities.get("malware_scanner"),
            "transcription_model": capabilities.get("transcription_model"),
        }
    )
    sandbox = capabilities.get("sandbox") if isinstance(capabilities.get("sandbox"), dict) else {}
    binaries = capabilities.get("binaries") if isinstance(capabilities.get("binaries"), dict) else {}
    scanner = capabilities.get("malware_scanner")
    model = capabilities.get("transcription_model")
    failures: list[str] = []
    if not sandbox.get("seccomp"):
        failures.append("seccomp_unavailable")
    landlock_abi = sandbox.get("landlock_abi")
    if isinstance(landlock_abi, bool) or not isinstance(landlock_abi, int) or landlock_abi < 1:
        failures.append("landlock_unavailable")
    if not sandbox.get("dedicated_identity"):
        failures.append("worker_identity_unavailable")
    if not sandbox.get("dedicated_acquisition_identity"):
        failures.append("acquisition_identity_unavailable")
    if not sandbox.get("aggregate_resource_limits"):
        failures.append("aggregate_resource_limits_unavailable")
    if not isinstance(scanner, dict) or scanner.get("status") != "current":
        failures.append("clamav_definitions_not_current")
    if not isinstance(model, dict) or model.get("status") != "available":
        failures.append("whisper_model_unavailable")
    for name in sorted(REQUIRED_BINARIES):
        if not binaries.get(name):
            failures.append(f"binary_missing:{name}")

    purpose_suffix = f"{deployment_id[:160]} {checked_at // 21600}"
    if not failures:
        failure = _probe_private_network_rejection(
            client,
            purpose=f"runtime readiness acquisition probe {purpose_suffix}",
        )
        if failure:
            failures.append(failure)
    if not failures:
        if not input_roots:
            failures.append("canary_input_root_missing")
        else:
            job_id, failure = _run_canary(
                client,
                input_root=input_roots[0],
                purpose=f"runtime readiness canary {purpose_suffix}",
            )
            record["canary_job_id"] = job_id
            if failure:
                failures.append(failure)

    record["failures"] = failures
    record["ok"] = not failures
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--socket",
        default=os.getenv("MEDIA_EVIDENCE_BROKER_SOCKET", DEFAULT_BROKER_SOCKET),
    )
    parser.add_argument(
        "--input-roots",
        default=os.getenv("MEDIA_EVIDENCE_INPUT_ROOTS", DEFAULT_INPUT_ROOTS),
    )
    parser.add_argument(
        "--deployment-id",
        default=os.getenv("RAILWAY_DEPLOYMENT_ID", "local"),
    )
    args = parser.parse_args()

    client = BrokerClient(socket_path=args.socket)
    try:
        record = check_readiness(
            client,
            input_roots=[Path(value) for value in args.input_roots.split(":") if value][:8],
            deployment_id=args.deployment_id,
        )
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    print(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0 if record["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
