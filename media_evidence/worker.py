from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .contracts import MediaEvidenceError, canonical_json_bytes, normalize_options
from .extractors import extract_media
from .sandbox import (
    apply_resource_limits,
    disable_process_inspection,
    install_seccomp,
    restrict_filesystem,
    validated_whisper_model_path,
)


_MAX_RESULT_BYTES = 72 * 1024 * 1024

_WORKER_READ_ONLY_PATHS = (
    Path("/usr"),
    Path("/lib"),
    Path("/lib64"),
    Path("/opt/hermes-venv"),
    Path("/opt/hermes-agent"),
    Path("/var/lib/clamav"),
    Path("/etc/clamav/certs"),
    Path("/etc/ld.so.cache"),
    Path("/etc/localtime"),
    Path("/etc/fonts"),
    Path("/dev/urandom"),
)


def _read_only_paths(source: Path, options_path: Path, options: dict) -> list[Path]:
    candidates = [
        source,
        options_path,
        *_WORKER_READ_ONLY_PATHS,
    ]
    model_path = os.getenv("MEDIA_EVIDENCE_WHISPER_MODEL_PATH", "").strip()
    if model_path:
        validated = validated_whisper_model_path(model_path)
        if validated is not None:
            candidates.append(validated)
    else:
        repository = Path("/data/.cache/huggingface/hub") / f"models--Systran--faster-whisper-{options['whisper_model']}"
        candidates.append(repository)
    return [path for path in candidates if path.exists()]


def execute(source: Path, output: Path, options_path: Path) -> dict:
    try:
        options = normalize_options(json.loads(options_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise MediaEvidenceError("invalid_arguments", "Worker options are invalid") from exc
    temporary = output / "tmp"
    temporary.mkdir(exist_ok=True, mode=0o700)
    os.environ["TMPDIR"] = str(temporary)
    apply_resource_limits(options)
    install_seccomp(required=True)
    restrict_filesystem(
        read_only=_read_only_paths(source, options_path, options),
        read_write=[output, Path("/dev/null")],
        required=True,
    )
    return extract_media(source, output, options)


def _write_result(descriptor: int, payload: dict) -> None:
    content = canonical_json_bytes(payload) + b"\n"
    if len(content) > _MAX_RESULT_BYTES:
        raise MediaEvidenceError("worker_failed", "The media worker result exceeded its budget")
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    view = memoryview(content)
    while view:
        view = view[os.write(descriptor, view) :]
    os.fsync(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--options", required=True)
    parser.add_argument("--result-fd", type=int, required=True)
    args = parser.parse_args(argv)
    source = Path(args.source)
    output = Path(args.output)
    options_path = Path(args.options)
    if args.result_fd < 3:
        return 3
    try:
        disable_process_inspection()
        result = execute(source, output, options_path)
        _write_result(args.result_fd, {"ok": True, "result": result})
        return 0
    except MediaEvidenceError as exc:
        _write_result(args.result_fd, {"ok": False, "error": exc.code, "message": exc.message})
        return 2
    except BaseException:
        _write_result(args.result_fd, {"ok": False, "error": "worker_failed", "message": "The media worker failed"})
        return 3


if __name__ == "__main__":
    sys.exit(main())
