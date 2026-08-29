#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import errno
import fcntl
import grp
import hashlib
import json
import math
import os
import pwd
import re
import socket
import stat
import subprocess
import struct
import sys
import threading
import wave
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any


REPORT_SCHEMA = "p4-image-certification/v1"
WORK_ROOT = Path("/p4-work")
CORPUS_ROOT = WORK_ROOT / "corpus"
STORE_ROOT = WORK_ROOT / "store"
MALWARE_ROOT = WORK_ROOT / "malware-canary"
FONT_PATH = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
HARNESS_ENTRYPOINT = "/opt/hermes-venv/bin/python -I /p4/p4_image_certification.py"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
HEX_16 = re.compile(r"^[0-9a-f]{16}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
JOB_ID = re.compile(r"^mev_[0-9a-f]{24}$")
ARTIFACT_ID = re.compile(r"^artifact:sha256:[0-9a-f]{64}$")
NORMALIZED_WORD = re.compile(r"[a-z0-9]+")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

P4_OPTIONS: dict[str, Any] = {
    "ocr": True,
    "transcribe": True,
    "scan_policy": "required",
    "sample_interval_seconds": 1.0,
    "scene_threshold": 0.35,
    "max_frames": 8,
    "max_scene_frames": 2,
    "max_pages": 4,
    "max_render_pages": 4,
    "max_duration_seconds": 15.0,
    "max_source_bytes": 16 * 1024 * 1024,
    "max_output_bytes": 128 * 1024 * 1024,
    "max_pixels": 20_000_000,
    "worker_timeout_seconds": 300.0,
    "cpu_limit_seconds": 240,
    "memory_limit_mb": 2048,
    "file_limit_mb": 256,
    "process_limit": 32,
    "open_file_limit": 256,
    "whisper_model": "base.en",
    "language": None,
    "require_qpdf": True,
}

LANE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "image",
        "filename": "p4-image.png",
        "expected_mime": "image/png",
        "media_kind": "image",
        "artifact_kinds": {
            "evidence_index": "application/x-ndjson",
            "ocr_text": "application/x-ndjson",
            "sanitized_image": "image/png",
        },
        "evidence_kinds": {"image_region", "ocr_text"},
        "source_payload_contract": "png",
        "required_ocr_words": {"crimson", "orbit"},
        "required_transcript_words": set(),
        "expected_quality_tier": "complete",
        "warnings": set(),
    },
    {
        "name": "pdf",
        "filename": "p4-document.pdf",
        "expected_mime": "application/pdf",
        "media_kind": "document",
        "artifact_kinds": {
            "document_probe": "application/json",
            "evidence_index": "application/x-ndjson",
            "native_text": "application/x-ndjson",
            "ocr_text": "application/x-ndjson",
            "page_image": "image/png",
        },
        "evidence_kinds": {"ocr_text", "page_image"},
        "source_payload_contract": "pdf",
        "required_ocr_words": {"sapphire", "compass"},
        "required_transcript_words": set(),
        "expected_quality_tier": "complete",
        "warnings": set(),
    },
    {
        "name": "mp3",
        "filename": "p4-audio.mp3",
        "expected_mime": "audio/mpeg",
        "media_kind": "audio",
        "artifact_kinds": {
            "audio_waveform": "image/png",
            "evidence_index": "application/x-ndjson",
            "media_probe": "application/json",
            "normalized_audio": "audio/wav",
            "structured_transcript": "application/x-ndjson",
            "transcription_metadata": "application/json",
        },
        "evidence_kinds": {"audio_waveform", "transcript_segment"},
        "source_payload_contract": "mp3",
        "required_ocr_words": set(),
        "required_transcript_words": {"silver", "rocket", "garden"},
        "expected_quality_tier": "partial",
        "probe_contract": {
            "format_names": {"mp3"},
            "duration_seconds": 6.0,
            "duration_tolerance_seconds": 0.1,
            "streams": (
                {
                    "codec_type": "audio",
                    "codec_name": "mp3",
                    "sample_rate": "16000",
                    "channels": 1,
                },
            ),
        },
        "warnings": {"diarization_unavailable"},
    },
    {
        "name": "mp4",
        "filename": "p4-video.mp4",
        "expected_mime": "video/mp4",
        "media_kind": "video",
        "artifact_kinds": {
            "audio_waveform": "image/png",
            "contact_sheet": "image/jpeg",
            "evidence_index": "application/x-ndjson",
            "frame_ocr": "application/x-ndjson",
            "media_probe": "application/json",
            "normalized_audio": "audio/wav",
            "sampled_frame": "image/jpeg",
            "structured_transcript": "application/x-ndjson",
            "transcription_metadata": "application/json",
        },
        "evidence_kinds": {"audio_waveform", "frame_ocr", "transcript_segment", "video_frame"},
        "source_payload_contract": "mp4",
        "required_ocr_words": {"amber", "harbor"},
        "required_transcript_words": {"golden", "lantern", "river"},
        "expected_quality_tier": "partial",
        "probe_contract": {
            "format_names": {"3g2", "3gp", "m4a", "mj2", "mov", "mp4"},
            "duration_seconds": 6.0,
            "duration_tolerance_seconds": 0.01,
            "streams": (
                {
                    "codec_type": "video",
                    "codec_name": "mpeg4",
                    "width": 1280,
                    "height": 720,
                    "pix_fmt": "yuv420p",
                    "r_frame_rate": "2/1",
                },
                {
                    "codec_type": "audio",
                    "codec_name": "aac",
                    "sample_rate": "16000",
                    "channels": 1,
                },
            ),
        },
        "warnings": {"diarization_unavailable"},
    },
)

CORPUS_DEFINITION: dict[str, Any] = {
    "schema": "p4-corpus/v1",
    "font": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "image": {
        "canvas": [1280, 720],
        "format": "PNG",
        "text": ["P4 IMAGE", "CRIMSON ORBIT"],
    },
    "pdf": {
        "canvas": [612, 792],
        "format": "PDF-1.4 image XObject with deterministic xref",
        "text": ["P4 PDF", "SAPPHIRE COMPASS"],
    },
    "video_frame": {
        "canvas": [1280, 720],
        "format": "PNG input to MP4 encoder",
        "text": ["P4 VIDEO", "AMBER HARBOR"],
    },
    "speech": {
        "engine": "/usr/bin/espeak-ng",
        "voice": "en-us",
        "speed": 120,
        "pitch": 45,
        "amplitude": 160,
        "mp3_text": "Silver rocket garden. Silver rocket garden. Silver rocket garden.",
        "mp4_text": "Golden lantern river. Golden lantern river. Golden lantern river.",
    },
    "mp3": {
        "encoder": "/usr/bin/ffmpeg",
        "codec": "libmp3lame",
        "bit_rate": "64k",
        "sample_rate": 16000,
        "channels": 1,
        "duration_seconds": 6,
        "audio_padding": "silence_to_duration",
        "xing_header": False,
        "id3v2": False,
        "metadata": "removed",
    },
    "mp4": {
        "encoder": "/usr/bin/ffmpeg",
        "video_codec": "mpeg4",
        "audio_codec": "aac",
        "sample_rate": 16000,
        "channels": 1,
        "duration_seconds": 6,
        "frame_rate": 2,
        "pixel_format": "yuv420p",
        "audio_padding": "silence_to_duration",
        "metadata": "removed",
    },
}


class CertificationFailure(RuntimeError):
    pass


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


def hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificationFailure(message)


def bounded_error(stage: str, exc: BaseException) -> dict[str, str]:
    message = " ".join(str(exc).split())[:2000] or "unspecified certification failure"
    return {"stage": stage, "type": type(exc).__name__, "message": message}


def corpus_definition_sha256() -> str:
    return sha256_bytes(canonical_json_bytes(CORPUS_DEFINITION))


def new_report(image_id: str, image_reference: str, source_commit: str, harness_sha256: str) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "candidate": {
            "image_id": image_id,
            "requested_reference": image_reference,
            "source_commit": source_commit,
        },
        "harness": {
            "entrypoint": HARNESS_ENTRYPOINT,
            "sha256": harness_sha256,
        },
        "policy": {
            "deployment": "none",
            "network": "none",
            "options": copy.deepcopy(P4_OPTIONS),
            "required_lanes": [spec["name"] for spec in LANE_SPECS],
            "skips": "forbidden",
            "fallbacks": "forbidden",
            "worker_identity": "hermes-media",
            "acquisition_identity": "hermes-acquire",
        },
        "corpus": {
            "schema": CORPUS_DEFINITION["schema"],
            "definition_sha256": corpus_definition_sha256(),
            "inputs": [],
        },
        "preflight": {},
        "lanes": [],
        "errors": [],
    }


def finalize_report(report: dict[str, Any]) -> dict[str, Any]:
    finalized = copy.deepcopy(report)
    finalized.pop("binding", None)
    finalized["binding"] = {
        "algorithm": "sha256",
        "payload_sha256": sha256_bytes(canonical_json_bytes(finalized)),
    }
    return finalized


def verify_report_binding(report: dict[str, Any]) -> bool:
    try:
        binding = report["binding"]
        unsigned = copy.deepcopy(report)
        del unsigned["binding"]
        return (
            binding["algorithm"] == "sha256"
            and binding["payload_sha256"] == sha256_bytes(canonical_json_bytes(unsigned))
        )
    except (KeyError, TypeError):
        return False


def is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and HEX_64.fullmatch(value) is not None and value != "0" * 64


def require_nonempty_string(value: Any, label: str, *, maximum: int = 1024) -> str:
    require(isinstance(value, str) and 1 <= len(value) <= maximum and "\x00" not in value, f"{label} is invalid")
    return value


def payload_contract_for_media_type(media_type: str) -> str:
    contracts = {
        "application/json": "json-object",
        "application/x-ndjson": "ndjson-objects",
        "audio/wav": "wav-pcm-s16le-16000-mono",
        "image/jpeg": "jpeg",
        "image/png": "png",
    }
    require(media_type in contracts, f"unsupported artifact media type: {media_type}")
    return contracts[media_type]


def validate_model_identity(model: Any, label: str) -> dict[str, Any]:
    require(isinstance(model, dict), f"{label} is invalid")
    require(
        set(model) == {"status", "repository", "revision", "model_sha256", "bytes"},
        f"{label} fields are incomplete",
    )
    require(model.get("status") == "available", f"{label} status is invalid")
    require(model.get("repository") == "Systran/faster-whisper-base.en", f"{label} repository is invalid")
    require(
        HEX_40.fullmatch(str(model.get("revision", ""))) is not None and model["revision"] != "0" * 40,
        f"{label} revision is invalid",
    )
    require(is_sha256(model.get("model_sha256")), f"{label} hash is invalid")
    require(is_positive_int(model.get("bytes")), f"{label} size is invalid")
    return model


def validate_scanner_definitions(definitions: Any, label: str, *, include_file_count: bool) -> dict[str, Any]:
    require(isinstance(definitions, dict), f"{label} is invalid")
    expected = {"status", "file", "bytes", "mtime_ns", "sha256"}
    if include_file_count:
        expected.add("files")
    require(set(definitions) == expected, f"{label} fields are incomplete")
    require(definitions.get("status") == "current", f"{label} status is invalid")
    require_nonempty_string(definitions.get("file"), f"{label} file", maximum=64)
    if include_file_count:
        require(is_positive_int(definitions.get("files")), f"{label} file count is invalid")
    require(is_positive_int(definitions.get("bytes")), f"{label} size is invalid")
    require(
        is_positive_int(definitions.get("mtime_ns")),
        f"{label} timestamp is invalid",
    )
    require(is_sha256(definitions.get("sha256")), f"{label} hash is invalid")
    return definitions


def validate_candidate_identity(candidate: Any, *, complete: bool) -> dict[str, Any]:
    require(isinstance(candidate, dict), "candidate identity is invalid")
    base_fields = {"image_id", "requested_reference", "source_commit"}
    complete_fields = base_fields | {"hermes_commit", "sbom"}
    require(set(candidate) == (complete_fields if complete else base_fields), "candidate identity fields are invalid")
    require(
        IMAGE_ID.fullmatch(str(candidate.get("image_id", ""))) is not None
        and candidate["image_id"] != "sha256:" + "0" * 64,
        "image ID is invalid",
    )
    require_nonempty_string(candidate.get("requested_reference"), "candidate reference", maximum=512)
    require(
        HEX_40.fullmatch(str(candidate.get("source_commit", ""))) is not None
        and candidate["source_commit"] != "0" * 40,
        "source commit is invalid",
    )
    if not complete:
        return candidate
    require(
        HEX_40.fullmatch(str(candidate.get("hermes_commit", ""))) is not None
        and candidate["hermes_commit"] != "0" * 40,
        "embedded Hermes commit is invalid",
    )
    sbom = candidate.get("sbom")
    require(isinstance(sbom, dict), "candidate SBOM identity is invalid")
    require(
        set(sbom) == {"path", "declared_sha256_path", "sha256", "bytes", "format", "spec_version"},
        "candidate SBOM identity is incomplete",
    )
    require(sbom.get("path") == "/opt/hermes-runtime.cdx.json", "candidate SBOM path is invalid")
    require(
        sbom.get("declared_sha256_path") == "/opt/hermes-runtime.cdx.sha256",
        "candidate SBOM declaration path is invalid",
    )
    require(is_sha256(sbom.get("sha256")), "candidate SBOM hash is invalid")
    require(is_positive_int(sbom.get("bytes")), "candidate SBOM size is invalid")
    require(sbom.get("format") == "CycloneDX" and sbom.get("spec_version") == "1.5", "candidate SBOM format is invalid")
    return candidate


def validate_preflight(preflight: Any) -> dict[str, Any]:
    require(isinstance(preflight, dict), "preflight evidence is invalid")
    require(
        set(preflight)
        == {
            "orchestrator_uid",
            "worker_identity",
            "acquisition_identity",
            "gateway_identity",
            "traverse_group",
            "broker_isolation",
            "sandbox",
            "scanner",
            "model",
            "malware_canary",
            "harness_mount_read_only",
            "image_root_read_only",
            "network_interfaces",
        },
        "preflight evidence is incomplete",
    )
    require(
        isinstance(preflight.get("orchestrator_uid"), int)
        and not isinstance(preflight["orchestrator_uid"], bool)
        and preflight["orchestrator_uid"] == 0,
        "preflight orchestrator identity is invalid",
    )
    identities = []
    for field, expected_name in (
        ("worker_identity", "hermes-media"),
        ("acquisition_identity", "hermes-acquire"),
        ("gateway_identity", "hermes-gateway"),
    ):
        identity = preflight.get(field)
        require(isinstance(identity, dict) and set(identity) == {"name", "uid", "gid"}, f"{field} is invalid")
        require(identity.get("name") == expected_name, f"{field} name is invalid")
        require(is_positive_int(identity.get("uid")) and is_positive_int(identity.get("gid")), f"{field} is not non-root")
        identities.append(identity)
    require(
        len({identity["uid"] for identity in identities}) == 3
        and len({identity["gid"] for identity in identities}) == 3,
        "preflight identities are not distinct",
    )
    traverse = preflight.get("traverse_group")
    require(
        isinstance(traverse, dict)
        and set(traverse) == {"name", "gid"}
        and traverse.get("name") == "hermes-evidence"
        and is_positive_int(traverse.get("gid"))
        and traverse["gid"] not in {identity["gid"] for identity in identities},
        "preflight evidence traverse group is invalid",
    )

    broker_isolation = preflight.get("broker_isolation")
    require(
        isinstance(broker_isolation, dict)
        and set(broker_isolation)
        == {
            "uid",
            "gid",
            "supplementary_groups",
            "store_uid",
            "store_gid",
            "store_mode",
            "store_open_denied",
            "store_list_denied",
            "key_metadata_denied",
            "key_read_denied",
            "database_read_denied",
            "store_write_denied",
            "broker_health",
            "broker_capabilities",
            "broker_response_opaque",
        },
        "broker isolation preflight is incomplete",
    )
    require(
        broker_isolation.get("uid") == identities[2]["uid"]
        and broker_isolation.get("gid") == identities[2]["gid"]
        and broker_isolation.get("supplementary_groups") == [],
        "broker isolation gateway identity is invalid",
    )
    require(
        broker_isolation.get("store_uid") == 0
        and broker_isolation.get("store_gid") == traverse["gid"]
        and broker_isolation.get("store_mode") == 0o710,
        "broker isolation store policy is invalid",
    )
    require(
        all(
            broker_isolation.get(field) is True
            for field in (
                "store_open_denied",
                "store_list_denied",
                "key_metadata_denied",
                "key_read_denied",
                "database_read_denied",
                "store_write_denied",
                "broker_health",
                "broker_capabilities",
                "broker_response_opaque",
            )
        ),
        "broker isolation controls were not enforced",
    )

    sandbox = preflight.get("sandbox")
    require(
        isinstance(sandbox, dict)
        and set(sandbox)
        == {
            "seccomp",
            "landlock_abi",
            "aggregate_resource_limits",
            "aggregate_resource_probe",
            "identity_probe",
        },
        "sandbox preflight is incomplete",
    )
    require(sandbox.get("seccomp") is True, "sandbox seccomp preflight is invalid")
    require(is_positive_int(sandbox.get("landlock_abi")), "sandbox Landlock preflight is invalid")
    require(
        sandbox.get("aggregate_resource_limits") is True,
        "sandbox aggregate resource limit preflight is invalid",
    )
    aggregate_probe = sandbox.get("aggregate_resource_probe")
    require(
        isinstance(aggregate_probe, dict)
        and set(aggregate_probe)
        == {
            "cpu_max",
            "memory_max_bytes",
            "pids_max",
            "pids_limit_enforced",
            "violation",
            "removed_after_probe",
        },
        "sandbox aggregate resource probe is incomplete",
    )
    require(
        aggregate_probe.get("cpu_max") == "100000 100000"
        and aggregate_probe.get("memory_max_bytes") == 512 * 1024 * 1024
        and aggregate_probe.get("pids_max") == 4
        and aggregate_probe.get("pids_limit_enforced") is True
        and aggregate_probe.get("violation") == "pids"
        and aggregate_probe.get("removed_after_probe") is True,
        "sandbox aggregate resource controls were not enforced",
    )
    probe = sandbox.get("identity_probe")
    require(
        isinstance(probe, dict)
        and set(probe)
        == {
            "uid",
            "gid",
            "seccomp_network_denied",
            "landlock_outside_read_denied",
            "landlock_allowed_read",
            "landlock_allowed_write",
        },
        "sandbox identity probe is incomplete",
    )
    require(probe.get("uid") == identities[0]["uid"] and probe.get("gid") == identities[0]["gid"], "sandbox probe identity changed")
    require(
        all(
            probe.get(field) is True
            for field in (
                "seccomp_network_denied",
                "landlock_outside_read_denied",
                "landlock_allowed_read",
                "landlock_allowed_write",
            )
        ),
        "sandbox identity probe did not enforce all controls",
    )

    scanner = preflight.get("scanner")
    require(isinstance(scanner, dict) and set(scanner) == {"package", "version", "sbom_purl", "definitions"}, "scanner preflight is incomplete")
    require(str(scanner.get("package", "")).split(":", 1)[0] == "clamav", "scanner SBOM package is invalid")
    require_nonempty_string(scanner.get("version"), "scanner SBOM version", maximum=256)
    require(
        isinstance(scanner.get("sbom_purl"), str) and scanner["sbom_purl"].startswith("pkg:deb/debian/clamav"),
        "scanner SBOM purl is invalid",
    )
    validate_scanner_definitions(scanner.get("definitions"), "scanner definitions", include_file_count=True)
    validate_model_identity(preflight.get("model"), "preflight model")

    canary = preflight.get("malware_canary")
    require(
        isinstance(canary, dict)
        and set(canary) == {"sha256", "bytes", "observed_error", "published_run"},
        "malware canary evidence is incomplete",
    )
    require(canary.get("sha256") == EICAR_SHA256 and canary.get("bytes") == 68, "malware canary identity is invalid")
    require(canary.get("observed_error") == "malware_detected", "malware canary was not detected")
    require(canary.get("published_run") is False, "malware canary published a run")
    require(preflight.get("harness_mount_read_only") is True, "harness mount preflight is invalid")
    require(preflight.get("image_root_read_only") is True, "image root preflight is invalid")
    require(preflight.get("network_interfaces") == ["lo"], "preflight network interfaces are invalid")
    return preflight


def validate_corpus(corpus: Any, *, complete: bool) -> dict[str, dict[str, Any]]:
    require(isinstance(corpus, dict) and set(corpus) == {"schema", "definition_sha256", "inputs"}, "corpus record is invalid")
    require(corpus.get("schema") == CORPUS_DEFINITION["schema"], "corpus schema is invalid")
    require(corpus.get("definition_sha256") == corpus_definition_sha256(), "corpus definition hash is invalid")
    inputs = corpus.get("inputs")
    require(isinstance(inputs, list), "corpus input inventory is invalid")
    require(len(inputs) == len(LANE_SPECS) if complete else len(inputs) in {0, len(LANE_SPECS)}, "corpus input set is incomplete")
    by_lane: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(inputs):
        require(isinstance(item, dict), "corpus input record is invalid")
        require(
            set(item) == {"lane", "path", "sha256", "bytes", "expected_mime", "payload_contract"},
            "corpus input record is incomplete",
        )
        spec = LANE_SPECS[index]
        require(item.get("lane") == spec["name"], "corpus lane order is invalid")
        require(item.get("path") == f"corpus/{spec['filename']}", "corpus input path is invalid")
        require(item.get("expected_mime") == spec["expected_mime"], "corpus input MIME is invalid")
        require(item.get("payload_contract") == spec["source_payload_contract"], "corpus payload contract is invalid")
        require(is_sha256(item.get("sha256")), "corpus input hash is invalid")
        require(is_positive_int(item.get("bytes")), "corpus input size is invalid")
        by_lane[spec["name"]] = item
    require(len({item["sha256"] for item in inputs}) == len(inputs), "corpus inputs are not content-distinct")
    return by_lane


def validate_media_contract(record: Any, spec: dict[str, Any]) -> None:
    require(isinstance(record, dict) and set(record) == {"source", "normalized_audio"}, "lane media contract is incomplete")
    contract = spec["probe_contract"]
    expected_duration_ms = int(contract["duration_seconds"] * 1000)
    tolerance_ms = math.ceil(contract["duration_tolerance_seconds"] * 1000)
    for field, expected_formats, expected_streams in (
        ("source", sorted(contract["format_names"]), [dict(stream) for stream in contract["streams"]]),
        (
            "normalized_audio",
            ["wav"],
            [{"codec_type": "audio", "codec_name": "pcm_s16le", "sample_rate": "16000", "channels": 1}],
        ),
    ):
        probe = record.get(field)
        require(
            isinstance(probe, dict) and set(probe) == {"format_names", "duration_ms", "streams"},
            f"lane {field} probe contract is invalid",
        )
        require(probe.get("format_names") == expected_formats, f"lane {field} format contract is invalid")
        require(probe.get("streams") == expected_streams, f"lane {field} stream contract is invalid")
        require(
            isinstance(probe.get("duration_ms"), int)
            and not isinstance(probe["duration_ms"], bool)
            and abs(probe["duration_ms"] - expected_duration_ms) <= max(tolerance_ms, 100 if field == "normalized_audio" else 0),
            f"lane {field} duration contract is invalid",
        )
    require(
        abs(record["source"]["duration_ms"] - record["normalized_audio"]["duration_ms"]) <= 100,
        "normalized audio duration differs from its source",
    )


def validate_quality_coverage(coverage: Any, spec: dict[str, Any]) -> None:
    require(isinstance(coverage, dict), "lane quality coverage is invalid")
    if spec["name"] == "image":
        require(set(coverage) == {"width", "height", "tiles", "ocr_lines"}, "image coverage fields are invalid")
        require(
            is_positive_int(coverage.get("width"))
            and coverage["width"] == 1280
            and is_positive_int(coverage.get("height"))
            and coverage["height"] == 720,
            "image coverage dimensions are invalid",
        )
        require(
            is_nonnegative_int(coverage.get("tiles"))
            and coverage["tiles"] == 0
            and is_positive_int(coverage.get("ocr_lines")),
            "image OCR coverage is invalid",
        )
    elif spec["name"] == "pdf":
        require(
            is_positive_int(coverage.get("pages_total"))
            and coverage["pages_total"] == 1
            and is_nonnegative_int(coverage.get("pages_native_text"))
            and coverage["pages_native_text"] == 0
            and is_positive_int(coverage.get("pages_rendered"))
            and coverage["pages_rendered"] == 1
            and is_positive_int(coverage.get("ocr_lines"))
            and set(coverage) == {"pages_total", "pages_native_text", "pages_rendered", "ocr_lines"},
            "PDF coverage is invalid",
        )
    else:
        expected = {"duration_ms", "transcript_segments"}
        if spec["name"] == "mp4":
            expected |= {"sampled_frames", "scene_frames"}
        require(set(coverage) == expected, "timed-media coverage fields are invalid")
        contract = spec["probe_contract"]
        tolerance_ms = max(100, math.ceil(contract["duration_tolerance_seconds"] * 1000))
        require(
            isinstance(coverage.get("duration_ms"), int)
            and not isinstance(coverage["duration_ms"], bool)
            and abs(coverage["duration_ms"] - int(contract["duration_seconds"] * 1000)) <= tolerance_ms,
            "timed-media coverage duration is invalid",
        )
        require(is_positive_int(coverage.get("transcript_segments")), "timed-media transcript coverage is empty")
        if spec["name"] == "mp4":
            require(
                is_positive_int(coverage.get("sampled_frames")) and coverage["sampled_frames"] == 6,
                "video sampled-frame coverage is invalid",
            )
            require(
                is_nonnegative_int(coverage.get("scene_frames"))
                and 0 <= coverage["scene_frames"] <= P4_OPTIONS["max_scene_frames"],
                "video scene-frame coverage is invalid",
            )


def validate_passed_lane(
    lane: Any,
    spec: dict[str, Any],
    corpus_input: dict[str, Any],
    candidate: dict[str, Any],
    preflight: dict[str, Any],
) -> None:
    require(isinstance(lane, dict), "passed lane record is invalid")
    expected_fields = {
        "name",
        "status",
        "source",
        "job_id",
        "manifest",
        "artifacts",
        "evidence",
        "quality",
        "scanner_revision",
        "model_provenance",
        "sandbox",
        "runtime_provenance",
    }
    if "probe_contract" in spec:
        expected_fields.add("media_contract")
    require(set(lane) == expected_fields, f"{spec['name']} lane fields are incomplete")
    require(lane.get("name") == spec["name"] and lane.get("status") == "passed", "passed lane identity is invalid")

    source = lane.get("source")
    require(
        isinstance(source, dict)
        and set(source) == {"path", "sha256", "bytes", "actual_mime", "media_kind", "payload_contract"},
        f"{spec['name']} lane source is incomplete",
    )
    require(source.get("path") == corpus_input["path"], "lane source path differs from corpus")
    require(source.get("sha256") == corpus_input["sha256"] and source.get("bytes") == corpus_input["bytes"], "lane source identity differs from corpus")
    require(source.get("actual_mime") == spec["expected_mime"], "lane source MIME is invalid")
    require(source.get("media_kind") == spec["media_kind"], "lane source media kind is invalid")
    require(source.get("payload_contract") == spec["source_payload_contract"], "lane source payload contract is invalid")
    require(JOB_ID.fullmatch(str(lane.get("job_id", ""))) is not None, "lane job ID is invalid")

    manifest = lane.get("manifest")
    require(
        isinstance(manifest, dict)
        and set(manifest) == {"sha256", "bytes", "payload_sha256", "signature_algorithm", "signature_key_id", "signature"},
        "lane manifest identity is incomplete",
    )
    require(is_sha256(manifest.get("sha256")) and is_positive_int(manifest.get("bytes")), "lane manifest file identity is invalid")
    require(is_sha256(manifest.get("payload_sha256")), "lane manifest payload hash is invalid")
    require(manifest.get("signature_algorithm") == "hmac-sha256", "lane manifest signature algorithm is invalid")
    require(HEX_16.fullmatch(str(manifest.get("signature_key_id", ""))) is not None, "lane manifest key ID is invalid")
    require(is_sha256(manifest.get("signature")), "lane manifest signature is invalid")

    artifacts = lane.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "lane artifact inventory is empty")
    require(all(isinstance(item, dict) for item in artifacts), "lane artifact record is invalid")
    artifact_order = [item.get("path") for item in artifacts]
    require(all(isinstance(path, str) for path in artifact_order) and artifact_order == sorted(artifact_order), "lane artifacts are not ordered")
    artifact_ids: set[str] = set()
    artifact_paths: set[str] = set()
    actual_artifacts: dict[str, set[str]] = {}
    for artifact in artifacts:
        require(
            set(artifact) == {"id", "kind", "path", "media_type", "sha256", "bytes", "payload_contract"},
            "lane artifact record is incomplete",
        )
        digest = str(artifact.get("sha256", ""))
        require(
            is_sha256(digest)
            and ARTIFACT_ID.fullmatch(str(artifact.get("id", ""))) is not None
            and artifact.get("id") == f"artifact:sha256:{digest}",
            "lane artifact identity is invalid",
        )
        require(is_positive_int(artifact.get("bytes")), "lane artifact size is invalid")
        kind = require_nonempty_string(artifact.get("kind"), "lane artifact kind", maximum=128)
        path = require_nonempty_string(artifact.get("path"), "lane artifact path")
        pure = PurePosixPath(path)
        require(
            "\\" not in path
            and "\x00" not in path
            and not pure.is_absolute()
            and all(part not in {"", ".", ".."} for part in pure.parts),
            "lane artifact path is unsafe",
        )
        media_type = require_nonempty_string(artifact.get("media_type"), "lane artifact media type", maximum=128)
        require(artifact.get("payload_contract") == payload_contract_for_media_type(media_type), "lane artifact payload validation is invalid")
        require(path not in artifact_paths, "lane artifact inventory contains a duplicate path")
        artifact_ids.add(artifact["id"])
        artifact_paths.add(path)
        actual_artifacts.setdefault(kind, set()).add(media_type)
    for kind, media_type in spec["artifact_kinds"].items():
        require(media_type in actual_artifacts.get(kind, set()), f"lane is missing expected artifact {kind}:{media_type}")

    evidence = lane.get("evidence")
    require(
        isinstance(evidence, dict) and set(evidence) == {"count", "kinds", "index_artifact_id", "text_checks"},
        "lane evidence summary is incomplete",
    )
    require(
        is_positive_int(evidence.get("count")) and evidence["count"] >= len(spec["evidence_kinds"]),
        "lane evidence count is invalid",
    )
    kinds = evidence.get("kinds")
    require(
        isinstance(kinds, list)
        and all(isinstance(kind, str) and kind for kind in kinds)
        and kinds == sorted(set(kinds)),
        "lane evidence kind inventory is invalid",
    )
    require(spec["evidence_kinds"].issubset(set(kinds)), "lane evidence kind inventory is incomplete")
    require(evidence.get("index_artifact_id") in artifact_ids, "lane evidence index identity is invalid")
    index_matches = [item for item in artifacts if item["id"] == evidence["index_artifact_id"]]
    require(len(index_matches) == 1 and index_matches[0]["kind"] == "evidence_index", "lane evidence index artifact is invalid")
    text_checks = evidence.get("text_checks")
    require(isinstance(text_checks, dict), "lane text checks are invalid")
    expected_checks = {}
    if spec["required_ocr_words"]:
        expected_checks["ocr"] = sorted(spec["required_ocr_words"])
    if spec["required_transcript_words"]:
        expected_checks["transcript"] = sorted(spec["required_transcript_words"])
    require(set(text_checks) == set(expected_checks), "lane text checks are incomplete")
    for field, expected_words in expected_checks.items():
        check = text_checks.get(field)
        require(
            isinstance(check, dict)
            and set(check) == {"expected_words", "matched_words"}
            and check.get("expected_words") == expected_words
            and check.get("matched_words") == expected_words,
            f"lane {field} expected-word check is invalid",
        )

    quality = lane.get("quality")
    require(
        isinstance(quality, dict) and set(quality) == {"tier", "warnings", "disagreements", "coverage"},
        "lane quality record is incomplete",
    )
    require(quality.get("tier") == spec["expected_quality_tier"], "lane quality tier is invalid")
    require(quality.get("warnings") == sorted(spec["warnings"]), "lane warning inventory is invalid")
    require(quality.get("disagreements") == [], "lane contains extraction disagreements")
    validate_quality_coverage(quality.get("coverage"), spec)

    lane_scanner = validate_scanner_definitions(lane.get("scanner_revision"), "lane scanner revision", include_file_count=False)
    preflight_scanner = preflight["scanner"]["definitions"]
    require(
        lane_scanner == {key: preflight_scanner[key] for key in ("status", "file", "bytes", "mtime_ns", "sha256")},
        "lane scanner provenance differs from preflight",
    )
    lane_model = validate_model_identity(lane.get("model_provenance"), "lane model provenance")
    require(lane_model == preflight["model"], "lane model provenance differs from preflight")
    require(
        lane.get("sandbox") == "seccomp+landlock+uid+cgroupv2",
        "lane sandbox provenance is invalid",
    )
    require(
        lane.get("runtime_provenance")
        == {
            "image_id": candidate["image_id"],
            "source_commit": candidate["source_commit"],
            "sbom_sha256": candidate["sbom"]["sha256"],
            "deployment_id": "unknown",
        },
        "lane runtime provenance differs from the candidate",
    )
    if "probe_contract" in spec:
        validate_media_contract(lane.get("media_contract"), spec)


def validate_report_shape(report: dict[str, Any]) -> None:
    require(isinstance(report, dict), "certification report is not an object")
    require(
        set(report)
        == {"schema", "status", "candidate", "harness", "policy", "corpus", "preflight", "lanes", "errors", "binding"},
        "certification report fields are invalid",
    )
    require(report.get("schema") == REPORT_SCHEMA, "certification report schema is invalid")
    require(report.get("status") in {"passed", "failed"}, "certification status is invalid")
    passed = report["status"] == "passed"
    candidate_value = report.get("candidate")
    candidate_complete = passed or (isinstance(candidate_value, dict) and "sbom" in candidate_value)
    candidate = validate_candidate_identity(candidate_value, complete=candidate_complete)

    harness = report.get("harness")
    require(isinstance(harness, dict) and set(harness) == {"entrypoint", "sha256"}, "harness identity is invalid")
    require(harness.get("entrypoint") == HARNESS_ENTRYPOINT, "harness entrypoint is invalid")
    current_harness_sha256, _ = hash_file(Path(__file__))
    require(
        is_sha256(harness.get("sha256"))
        and harness["sha256"] == current_harness_sha256,
        "harness hash does not identify the validator in use",
    )

    policy = report.get("policy")
    require(isinstance(policy, dict), "certification policy is invalid")
    require(
        set(policy)
        == {
            "deployment",
            "network",
            "options",
            "required_lanes",
            "skips",
            "fallbacks",
            "worker_identity",
            "acquisition_identity",
        },
        "certification policy fields are incomplete",
    )
    require(policy.get("network") == "none", "certification network policy is invalid")
    require(policy.get("deployment") == "none", "certification deployment policy is invalid")
    require(policy.get("options") == P4_OPTIONS, "certification options changed")
    require(policy.get("required_lanes") == [spec["name"] for spec in LANE_SPECS], "required lane policy is invalid")
    require(policy.get("skips") == "forbidden", "skip policy is invalid")
    require(policy.get("fallbacks") == "forbidden", "fallback policy is invalid")
    require(policy.get("worker_identity") == "hermes-media", "worker identity policy is invalid")
    require(policy.get("acquisition_identity") == "hermes-acquire", "acquisition identity policy is invalid")

    corpus = validate_corpus(report.get("corpus"), complete=passed)
    preflight_value = report.get("preflight")
    require(isinstance(preflight_value, dict), "preflight record is invalid")
    preflight = validate_preflight(preflight_value) if passed or preflight_value else {}

    errors = report.get("errors")
    require(isinstance(errors, list), "certification error inventory is invalid")
    for error in errors:
        require(isinstance(error, dict) and set(error) == {"stage", "type", "message"}, "certification error record is invalid")
        require_nonempty_string(error.get("stage"), "certification error stage", maximum=128)
        require_nonempty_string(error.get("type"), "certification error type", maximum=128)
        require_nonempty_string(error.get("message"), "certification error message", maximum=2000)
    require(not errors if passed else bool(errors), "certification error inventory contradicts status")

    lanes = report.get("lanes")
    require(isinstance(lanes, list) and len(lanes) == len(LANE_SPECS), "lane set is invalid")
    require([lane.get("name") if isinstance(lane, dict) else None for lane in lanes] == [spec["name"] for spec in LANE_SPECS], "lane order is invalid")
    failed_lanes = 0
    for lane, spec in zip(lanes, LANE_SPECS):
        require(isinstance(lane, dict) and lane.get("status") in {"passed", "failed"}, "lane status is invalid")
        if lane["status"] == "passed":
            require(candidate_complete and preflight and spec["name"] in corpus, "passed lane lacks certification provenance")
            validate_passed_lane(lane, spec, corpus[spec["name"]], candidate, preflight)
        else:
            failed_lanes += 1
            require(set(lane) == {"name", "status", "error"}, "failed lane record is invalid")
            error = lane.get("error")
            require(isinstance(error, dict) and set(error) in ({"stage", "message"}, {"stage", "type", "message"}), "failed lane error is invalid")
            require_nonempty_string(error.get("stage"), "failed lane stage", maximum=128)
            require_nonempty_string(error.get("message"), "failed lane message", maximum=2000)
            if "type" in error:
                require_nonempty_string(error.get("type"), "failed lane error type", maximum=128)
    require(failed_lanes == 0 if passed else failed_lanes > 0, "lane statuses contradict certification status")
    binding = report.get("binding")
    require(
        isinstance(binding, dict)
        and set(binding) == {"algorithm", "payload_sha256"}
        and binding.get("algorithm") == "sha256"
        and is_sha256(binding.get("payload_sha256")),
        "certification report binding fields are invalid",
    )
    require(verify_report_binding(report), "certification report binding is invalid")


def write_report(path: Path, report: dict[str, Any]) -> None:
    validate_report_shape(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    content = canonical_json_bytes(report) + b"\n"
    with temporary.open("wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_checked(argv: list[str], *, timeout: int = 60) -> None:
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip()[-1000:]
        raise CertificationFailure(f"fixture command failed ({Path(argv[0]).name}): {diagnostic}")


def ffprobe_json(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "/usr/bin/ffprobe",
            "-v",
            "error",
            "-show_format",
            "-show_streams",
            "-of",
            "json",
            str(path),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    require(result.returncode == 0, f"independent ffprobe failed: {(result.stderr or result.stdout).strip()[-1000:]}")
    try:
        payload = strict_json_loads(result.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        raise CertificationFailure("independent ffprobe returned invalid JSON") from exc
    require(isinstance(payload, dict), "independent ffprobe payload is invalid")
    return payload


def strict_json_loads(content: str | bytes) -> Any:
    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    return json.loads(content, parse_constant=reject_nonfinite)


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CertificationFailure(f"{label} is not valid JSON") from exc
    require(isinstance(payload, dict) and payload, f"{label} is not a nonempty JSON object")
    return payload


def read_ndjson_objects(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        content = path.read_bytes()
        text = content.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise CertificationFailure(f"{label} is not valid UTF-8 NDJSON") from exc
    require(content.endswith(b"\n") and content.count(b"\n") >= 1, f"{label} is not newline-terminated NDJSON")
    lines = text.splitlines()
    require(lines and all(line for line in lines), f"{label} contains an empty NDJSON record")
    records = []
    for line in lines:
        try:
            record = strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise CertificationFailure(f"{label} contains invalid NDJSON") from exc
        require(isinstance(record, dict), f"{label} contains a non-object NDJSON record")
        records.append(record)
    return records


def validate_png(path: Path, label: str) -> None:
    require(path.stat().st_size >= 36, f"{label} is too short to be a PNG")
    with path.open("rb") as handle:
        header = handle.read(24)
        handle.seek(-12, os.SEEK_END)
        trailer = handle.read(12)
    require(
        len(header) == 24
        and header[:8] == b"\x89PNG\r\n\x1a\n"
        and header[12:16] == b"IHDR"
        and int.from_bytes(header[16:20], "big") > 0
        and int.from_bytes(header[20:24], "big") > 0
        and trailer == b"\x00\x00\x00\x00IEND\xaeB`\x82",
        f"{label} is not a structurally identified PNG",
    )


def validate_jpeg(path: Path, label: str) -> None:
    with path.open("rb") as handle:
        prefix = handle.read(3)
        handle.seek(max(0, path.stat().st_size - 2))
        suffix = handle.read(2)
    require(len(prefix) == 3 and prefix[:2] == b"\xff\xd8" and prefix[2] == 0xFF and suffix == b"\xff\xd9", f"{label} is not a complete JPEG")


def validate_wav(path: Path, label: str) -> None:
    with path.open("rb") as handle:
        header = handle.read(12)
    require(header[:4] == b"RIFF" and header[8:12] == b"WAVE", f"{label} does not have WAV magic")
    try:
        with wave.open(str(path), "rb") as opened:
            require(opened.getcomptype() == "NONE", f"{label} is not uncompressed PCM")
            require(opened.getnchannels() == 1, f"{label} is not mono")
            require(opened.getframerate() == 16000, f"{label} does not use 16 kHz audio")
            require(opened.getsampwidth() == 2, f"{label} does not use signed 16-bit samples")
            require(opened.getnframes() > 0, f"{label} contains no audio frames")
    except wave.Error as exc:
        raise CertificationFailure(f"{label} is not a valid WAV") from exc


def validate_artifact_payload(path: Path, media_type: str, label: str) -> str:
    contract = payload_contract_for_media_type(media_type)
    if contract == "png":
        validate_png(path, label)
    elif contract == "jpeg":
        validate_jpeg(path, label)
    elif contract == "wav-pcm-s16le-16000-mono":
        validate_wav(path, label)
    elif contract == "json-object":
        read_json_object(path, label)
    elif contract == "ndjson-objects":
        read_ndjson_objects(path, label)
    return contract


def validate_source_payload(path: Path, contract: str) -> None:
    if contract == "png":
        validate_png(path, "PNG corpus source")
        return
    with path.open("rb") as handle:
        prefix = handle.read(16)
        handle.seek(max(0, path.stat().st_size - 32))
        suffix = handle.read(32)
    if contract == "pdf":
        require(prefix.startswith(b"%PDF-1.") and b"%%EOF" in suffix, "PDF corpus source has an invalid byte contract")
    elif contract == "mp3":
        require(
            prefix.startswith(b"ID3") or (len(prefix) >= 2 and prefix[0] == 0xFF and prefix[1] & 0xE0 == 0xE0),
            "MP3 corpus source has an invalid byte contract",
        )
    elif contract == "mp4":
        require(len(prefix) >= 12 and prefix[4:8] == b"ftyp" and int.from_bytes(prefix[:4], "big") >= 8, "MP4 corpus source has an invalid byte contract")
    else:
        raise CertificationFailure(f"unknown source payload contract: {contract}")


def probe_duration_ms(probe: dict[str, Any]) -> int:
    raw_format = probe.get("format") if isinstance(probe.get("format"), dict) else {}
    streams = probe.get("streams") if isinstance(probe.get("streams"), list) else []
    values = []
    for candidate in [raw_format.get("duration"), *[stream.get("duration") for stream in streams if isinstance(stream, dict)]]:
        try:
            value = float(candidate)
        except (TypeError, ValueError):
            continue
        if math.isfinite(value) and value > 0:
            values.append(value)
    require(values, "ffprobe duration is unavailable")
    return int(round(max(values) * 1000))


def validate_probe_contract(probe: dict[str, Any], contract: dict[str, Any], label: str) -> dict[str, Any]:
    raw_format = probe.get("format")
    streams = probe.get("streams")
    require(isinstance(raw_format, dict) and isinstance(streams, list), f"{label} ffprobe structure is invalid")
    format_names = sorted(set(str(raw_format.get("format_name", "")).split(",")) - {""})
    require(format_names == sorted(contract["format_names"]), f"{label} container format is invalid")
    expected_streams = [dict(item) for item in contract["streams"]]
    require(len(streams) == len(expected_streams) and all(isinstance(item, dict) for item in streams), f"{label} stream inventory is invalid")
    normalized_streams = []
    for expected in expected_streams:
        matches = [stream for stream in streams if stream.get("codec_type") == expected["codec_type"]]
        require(len(matches) == 1, f"{label} {expected['codec_type']} stream inventory is invalid")
        normalized = {key: matches[0].get(key) for key in expected}
        require(normalized == expected, f"{label} {expected['codec_type']} stream contract is invalid")
        normalized_streams.append(normalized)
    duration_ms = probe_duration_ms(probe)
    tolerance_ms = math.ceil(contract["duration_tolerance_seconds"] * 1000)
    require(
        abs(duration_ms - int(contract["duration_seconds"] * 1000)) <= tolerance_ms,
        f"{label} duration contract is invalid",
    )
    return {"format_names": format_names, "duration_ms": duration_ms, "streams": normalized_streams}


def draw_fixture_image(path: Path, *, size: tuple[int, int], lines: tuple[str, str], font_size: int) -> Any:
    from PIL import Image, ImageDraw, ImageFont

    require(FONT_PATH.is_file(), f"required deterministic font is missing: {FONT_PATH}")
    image = Image.new("RGB", size, "white")
    drawing = ImageDraw.Draw(image)
    font = ImageFont.truetype(str(FONT_PATH), font_size)
    line_gap = font_size // 2
    boxes = [drawing.textbbox((0, 0), line, font=font) for line in lines]
    heights = [box[3] - box[1] for box in boxes]
    total_height = sum(heights) + line_gap
    y = (size[1] - total_height) // 2
    for line, box, height in zip(lines, boxes, heights):
        width = box[2] - box[0]
        drawing.text(((size[0] - width) // 2, y), line, fill="black", font=font)
        y += height + line_gap
    if path.suffix == ".png":
        image.save(path, format="PNG", optimize=False, compress_level=9)
    return image


def deterministic_pdf(image: Any) -> bytes:
    encoded = BytesIO()
    image.save(
        encoded,
        format="JPEG",
        quality=95,
        subsampling=0,
        optimize=False,
        progressive=False,
    )
    jpeg = encoded.getvalue()
    width, height = image.size
    content = b"q\n612 0 0 792 0 0 cm\n/Im0 Do\nQ\n"
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>",
        f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"endstream",
        (
            f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {len(jpeg)} >>\nstream\n"
        ).encode("ascii")
        + jpeg
        + b"\nendstream",
    )
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def generate_corpus() -> list[dict[str, Any]]:
    if CORPUS_ROOT.exists():
        raise CertificationFailure("P4 corpus directory already exists")
    CORPUS_ROOT.mkdir(parents=True, mode=0o755)
    image_path = CORPUS_ROOT / "p4-image.png"
    draw_fixture_image(
        image_path,
        size=tuple(CORPUS_DEFINITION["image"]["canvas"]),
        lines=tuple(CORPUS_DEFINITION["image"]["text"]),
        font_size=96,
    )

    pdf_image = draw_fixture_image(
        CORPUS_ROOT / ".unused",
        size=tuple(CORPUS_DEFINITION["pdf"]["canvas"]),
        lines=tuple(CORPUS_DEFINITION["pdf"]["text"]),
        font_size=48,
    )
    pdf_path = CORPUS_ROOT / "p4-document.pdf"
    pdf_path.write_bytes(deterministic_pdf(pdf_image))

    def generate_speech(path: Path, text: str) -> None:
        speech = CORPUS_DEFINITION["speech"]
        run_checked(
            [
                speech["engine"],
                "-v",
                speech["voice"],
                "-s",
                str(speech["speed"]),
                "-p",
                str(speech["pitch"]),
                "-a",
                str(speech["amplitude"]),
                "-w",
                str(path),
                text,
            ]
        )

    mp3_speech_path = CORPUS_ROOT / ".mp3-speech.wav"
    mp4_speech_path = CORPUS_ROOT / ".mp4-speech.wav"
    generate_speech(mp3_speech_path, CORPUS_DEFINITION["speech"]["mp3_text"])
    generate_speech(mp4_speech_path, CORPUS_DEFINITION["speech"]["mp4_text"])

    mp3_path = CORPUS_ROOT / "p4-audio.mp3"
    run_checked(
        [
            "/usr/bin/ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-fflags",
            "+bitexact",
            "-i",
            str(mp3_speech_path),
            "-map",
            "0:a:0",
            "-af",
            "apad",
            "-t",
            str(CORPUS_DEFINITION["mp3"]["duration_seconds"]),
            "-c:a",
            "libmp3lame",
            "-b:a",
            "64k",
            "-ar",
            "16000",
            "-ac",
            "1",
            "-map_metadata",
            "-1",
            "-write_xing",
            "0",
            "-id3v2_version",
            "0",
            "-threads",
            "1",
            "-y",
            str(mp3_path),
        ]
    )

    video_frame_path = CORPUS_ROOT / ".video-frame.png"
    draw_fixture_image(
        video_frame_path,
        size=tuple(CORPUS_DEFINITION["video_frame"]["canvas"]),
        lines=tuple(CORPUS_DEFINITION["video_frame"]["text"]),
        font_size=96,
    )
    mp4_path = CORPUS_ROOT / "p4-video.mp4"
    run_checked(
        [
            "/usr/bin/ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-fflags",
            "+bitexact",
            "-loop",
            "1",
            "-framerate",
            "2",
            "-i",
            str(video_frame_path),
            "-i",
            str(mp4_speech_path),
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-af",
            "apad",
            "-t",
            str(CORPUS_DEFINITION["mp4"]["duration_seconds"]),
            "-c:v",
            "mpeg4",
            "-q:v",
            "4",
            "-pix_fmt",
            "yuv420p",
            "-r",
            "2",
            "-c:a",
            "aac",
            "-b:a",
            "64k",
            "-ar",
            "16000",
            "-ac",
            "1",
            "-map_metadata",
            "-1",
            "-metadata",
            "creation_time=1970-01-01T00:00:00Z",
            "-movflags",
            "+faststart",
            "-threads",
            "1",
            "-y",
            str(mp4_path),
        ],
        timeout=120,
    )
    mp3_speech_path.unlink()
    mp4_speech_path.unlink()
    video_frame_path.unlink()

    inputs = []
    specs = {spec["filename"]: spec for spec in LANE_SPECS}
    for path in sorted(CORPUS_ROOT.iterdir(), key=lambda item: item.name):
        require(path.name in specs and path.is_file() and not path.is_symlink(), "corpus contains an unexpected entry")
        os.chmod(path, 0o444)
        spec = specs[path.name]
        validate_source_payload(path, spec["source_payload_contract"])
        digest, size = hash_file(path)
        require(size > 0, f"fixture is empty: {path.name}")
        inputs.append(
            {
                "lane": spec["name"],
                "path": f"corpus/{path.name}",
                "sha256": digest,
                "bytes": size,
                "expected_mime": spec["expected_mime"],
                "payload_contract": spec["source_payload_contract"],
            }
        )
    require(len(inputs) == len(LANE_SPECS), "corpus is incomplete")
    os.chmod(CORPUS_ROOT, 0o555)
    return sorted(inputs, key=lambda item: [spec["name"] for spec in LANE_SPECS].index(item["lane"]))


def eicar_canary_bytes() -> bytes:
    fragments = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI",
        b"CAR-STANDARD-ANTIVIRUS-TEST-",
        b"FILE!$H+H*",
    )
    payload = b"".join(fragments)
    require(len(payload) == 68 and sha256_bytes(payload) == EICAR_SHA256, "malware canary construction is invalid")
    return payload


def generate_malware_canary() -> dict[str, Any]:
    require(not MALWARE_ROOT.exists() and not MALWARE_ROOT.is_symlink(), "malware canary directory already exists")
    MALWARE_ROOT.mkdir(mode=0o755)
    path = MALWARE_ROOT / "scanner-negative.com"
    payload = eicar_canary_bytes()
    path.write_bytes(payload)
    os.chmod(path, 0o444)
    os.chmod(MALWARE_ROOT, 0o555)
    digest, size = hash_file(path)
    require(digest == EICAR_SHA256 and size == 68, "malware canary file identity is invalid")
    return {"path": path, "sha256": digest, "bytes": size}


def assert_write_denied(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as exc:
        require(exc.errno in {errno.EROFS, errno.EACCES, errno.EPERM}, f"unexpected write denial for {path}: {exc}")
        return
    else:
        os.close(descriptor)
        path.unlink(missing_ok=True)
    raise CertificationFailure(f"required read-only path was writable: {path}")


def require_regular_file(path: Path, label: str) -> os.stat_result:
    metadata = path.lstat()
    require(
        not path.is_symlink() and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size > 0,
        f"{label} is not a safe regular file",
    )
    return metadata


def verify_candidate(image_id: str, image_reference: str, source_commit: str) -> tuple[dict[str, Any], dict[str, Any]]:
    require(IMAGE_ID.fullmatch(image_id) is not None, "P4_IMAGE_ID must be an immutable sha256 image ID")
    require(HEX_40.fullmatch(source_commit) is not None and source_commit != "0" * 40, "source commit is unknown")
    require(1 <= len(image_reference) <= 512 and "\x00" not in image_reference, "image reference is invalid")

    embedded_source_path = Path("/opt/hermes-source.commit")
    require_regular_file(embedded_source_path, "embedded source commit")
    embedded_source = embedded_source_path.read_text(encoding="utf-8").strip()
    require(embedded_source == source_commit, "embedded source commit does not match the image label")

    sbom_path = Path("/opt/hermes-runtime.cdx.json")
    declared_path = Path("/opt/hermes-runtime.cdx.sha256")
    require_regular_file(sbom_path, "embedded SBOM")
    require_regular_file(declared_path, "embedded SBOM hash declaration")
    sbom_sha256, sbom_bytes = hash_file(sbom_path)
    declared_fields = declared_path.read_text(encoding="utf-8").split()
    require(
        declared_fields == [sbom_sha256, "/opt/hermes-runtime.cdx.json"]
        and HEX_64.fullmatch(declared_fields[0]) is not None,
        "embedded SBOM hash declaration is invalid",
    )
    require(declared_fields[0] == sbom_sha256, "embedded SBOM hash does not match the SBOM")
    sbom = read_json_object(sbom_path, "embedded SBOM")
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.5", "SBOM contract is invalid")
    application = sbom.get("metadata", {}).get("component", {})
    require(
        application.get("type") == "application"
        and application.get("name") == "hermes-railway-runtime"
        and application.get("version") == source_commit,
        "SBOM application identity is invalid",
    )

    components = sbom.get("components")
    require(isinstance(components, list), "SBOM component inventory is invalid")
    model_components = [item for item in components if isinstance(item, dict) and item.get("type") == "machine-learning-model"]
    require(len(model_components) == 1, "SBOM must contain exactly one transcription model")
    scanner_components = [
        item
        for item in components
        if isinstance(item, dict)
        and item.get("group") == "debian"
        and str(item.get("name", "")).split(":", 1)[0] == "clamav"
    ]
    require(len(scanner_components) == 1, "SBOM does not contain the ClamAV scanner")

    provenance_path = Path("/opt/media-models/base.en/provenance.json")
    model_path = Path("/opt/media-models/base.en/model.bin")
    require_regular_file(provenance_path, "embedded model provenance")
    require_regular_file(model_path, "embedded model")
    provenance = read_json_object(provenance_path, "embedded model provenance")
    model_sha256, model_bytes = hash_file(model_path)
    require(
        provenance.get("repository") == "Systran/faster-whisper-base.en"
        and HEX_40.fullmatch(str(provenance.get("revision", ""))) is not None
        and provenance.get("revision") != "0" * 40
        and HEX_64.fullmatch(str(provenance.get("model_sha256", ""))) is not None,
        "embedded model provenance identity is invalid",
    )
    require(provenance.get("model_sha256") == model_sha256, "embedded model provenance hash is invalid")
    model_component = model_components[0]
    require(model_component.get("name") == provenance.get("repository"), "SBOM model repository is invalid")
    require(model_component.get("version") == provenance.get("revision"), "SBOM model revision is invalid")
    require(
        model_component.get("hashes") == [{"alg": "SHA-256", "content": model_sha256}],
        "SBOM model hash is invalid",
    )
    require(
        isinstance(model_component.get("purl"), str)
        and model_component["purl"].startswith("pkg:huggingface/Systran/faster-whisper-base.en@"),
        "SBOM model purl is invalid",
    )

    hermes_commit_path = Path("/opt/hermes-agent.commit")
    require_regular_file(hermes_commit_path, "embedded Hermes source commit")
    hermes_commit = hermes_commit_path.read_text(encoding="utf-8").strip()
    require(HEX_40.fullmatch(hermes_commit) is not None and hermes_commit != "0" * 40, "embedded Hermes source commit is invalid")
    scanner_component = scanner_components[0]
    require_nonempty_string(scanner_component.get("version"), "SBOM scanner version", maximum=256)
    require(
        isinstance(scanner_component.get("purl"), str)
        and scanner_component["purl"].startswith("pkg:deb/debian/clamav"),
        "SBOM scanner purl is invalid",
    )
    candidate = {
        "image_id": image_id,
        "requested_reference": image_reference,
        "source_commit": source_commit,
        "hermes_commit": hermes_commit,
        "sbom": {
            "path": "/opt/hermes-runtime.cdx.json",
            "declared_sha256_path": "/opt/hermes-runtime.cdx.sha256",
            "sha256": sbom_sha256,
            "bytes": sbom_bytes,
            "format": "CycloneDX",
            "spec_version": "1.5",
        },
    }
    embedded = {
        "model": {
            "repository": provenance.get("repository"),
            "revision": provenance.get("revision"),
            "model_sha256": model_sha256,
            "bytes": model_bytes,
            "sbom_purl": model_component.get("purl"),
        },
        "scanner": {
            "package": scanner_component.get("name"),
            "version": scanner_component.get("version"),
            "sbom_purl": scanner_component.get("purl"),
        },
    }
    return candidate, embedded


def sandbox_probe(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--allowed", required=True, type=Path)
    parser.add_argument("--writable", required=True, type=Path)
    parser.add_argument("--denied", required=True, type=Path)
    args = parser.parse_args(argv)

    from media_evidence.sandbox import install_seccomp, restrict_filesystem

    require(os.geteuid() == args.uid and os.getegid() == args.gid and args.uid != 0, "sandbox probe identity is invalid")
    install_seccomp(required=True)
    read_only = [
        args.allowed,
        Path("/p4"),
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/opt/hermes-venv"),
        Path("/opt/hermes-agent"),
        Path("/etc/ld.so.cache"),
        Path("/dev/urandom"),
    ]
    restrict_filesystem(read_only=read_only, read_write=[args.writable, Path("/dev/null")], required=True)

    network_denied = False
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        network_denied = exc.errno in {errno.EPERM, errno.EACCES}
    require(network_denied, "seccomp did not deny network socket creation")

    outside_read_denied = False
    try:
        args.denied.read_bytes()
    except OSError as exc:
        outside_read_denied = exc.errno in {errno.EPERM, errno.EACCES}
    require(outside_read_denied, "Landlock did not deny an outside read")
    require(args.allowed.read_text(encoding="utf-8") == "allowed\n", "Landlock denied the allowed read")
    output = args.writable / "probe.txt"
    output.write_text("sandboxed\n", encoding="utf-8")
    print(
        canonical_json_bytes(
            {
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "seccomp_network_denied": network_denied,
                "landlock_outside_read_denied": outside_read_denied,
                "landlock_allowed_read": True,
                "landlock_allowed_write": True,
            }
        ).decode("ascii")
    )
    return 0


def gateway_isolation_probe(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--store", required=True, type=Path)
    args = parser.parse_args(argv)

    from media_evidence.broker_client import BrokerClient

    require(
        os.geteuid() == args.uid
        and os.getegid() == args.gid
        and args.uid != 0
        and os.getgroups() == [],
        "gateway isolation probe identity is invalid",
    )

    def denied(callback) -> bool:
        try:
            callback()
        except OSError as exc:
            return exc.errno in {errno.EACCES, errno.EPERM}
        return False

    metadata = args.store.lstat()
    client = BrokerClient(socket_path=args.socket, gateway_gid=args.gid, timeout=30)
    health = client.health()
    capabilities = client.capabilities()

    def opaque(value: Any) -> bool:
        if isinstance(value, dict):
            forbidden = {"text", "manifest_path", "ledger_path", "artifact_path", "store_path"}
            return not forbidden.intersection(value) and all(opaque(item) for item in value.values())
        if isinstance(value, list):
            return all(opaque(item) for item in value)
        return not isinstance(value, str) or not value.startswith("/")

    print(
        canonical_json_bytes(
            {
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "supplementary_groups": os.getgroups(),
                "store_uid": metadata.st_uid,
                "store_gid": metadata.st_gid,
                "store_mode": stat.S_IMODE(metadata.st_mode),
                "store_open_denied": denied(lambda: os.open(args.store, os.O_RDONLY | os.O_DIRECTORY)),
                "store_list_denied": denied(lambda: list(args.store.iterdir())),
                "key_metadata_denied": denied(lambda: (args.store / "keys").lstat()),
                "key_read_denied": denied(lambda: (args.store / "keys" / "manifest-hmac-v1.key").read_bytes()),
                "database_read_denied": denied(lambda: (args.store / "jobs.sqlite3").read_bytes()),
                "store_write_denied": denied(lambda: (args.store / "gateway-write-probe").write_bytes(b"denied")),
                "broker_health": health.get("ok") is True and health.get("status") == "ready",
                "broker_capabilities": capabilities.get("ok") is True,
                "broker_response_opaque": opaque(health) and opaque(capabilities),
            }
        ).decode("ascii")
    )
    return 0


def run_sandbox_probe(worker: pwd.struct_passwd) -> dict[str, Any]:
    probe_root = WORK_ROOT / "sandbox-probe"
    probe_root.mkdir(mode=0o755)
    allowed = probe_root / "allowed.txt"
    allowed.write_text("allowed\n", encoding="utf-8")
    os.chmod(allowed, 0o444)
    writable = probe_root / "writable"
    writable.mkdir(mode=0o700)
    os.chown(writable, worker.pw_uid, worker.pw_gid)
    command = [
        "/usr/bin/setpriv",
        f"--reuid={worker.pw_uid}",
        f"--regid={worker.pw_gid}",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "/opt/hermes-venv/bin/python",
        "-I",
        "/p4/p4_image_certification.py",
        "--sandbox-probe",
        "--uid",
        str(worker.pw_uid),
        "--gid",
        str(worker.pw_gid),
        "--allowed",
        str(allowed),
        "--writable",
        str(writable),
        "--denied",
        "/opt/hermes-source.commit",
    ]
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1"},
    )
    require(result.returncode == 0, f"dedicated sandbox probe failed: {(result.stderr or result.stdout).strip()[-1000:]}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CertificationFailure("dedicated sandbox probe returned invalid JSON") from exc
    probe_output = writable / "probe.txt"
    metadata = probe_output.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == worker.pw_uid
        and metadata.st_gid == worker.pw_gid
        and probe_output.read_text(encoding="utf-8") == "sandboxed\n",
        "dedicated sandbox probe output identity is invalid",
    )
    require(
        payload.get("seccomp_network_denied") is True
        and payload.get("landlock_outside_read_denied") is True
        and payload.get("landlock_allowed_read") is True
        and payload.get("landlock_allowed_write") is True,
        "dedicated sandbox controls were not enforced",
    )
    return payload


def run_aggregate_resource_probe() -> dict[str, Any]:
    from media_evidence.cgroup import CgroupV2Manager

    manager = CgroupV2Manager()
    job = manager.create(
        {
            "cpu_limit_seconds": 10,
            "memory_limit_mb": 512,
            "process_limit": 4,
        }
    )
    ready = WORK_ROOT / f"cgroup-pids-probe-{os.getpid()}.ready"
    go = WORK_ROOT / f"cgroup-pids-probe-{os.getpid()}.go"
    process: subprocess.Popen[str] | None = None
    closed = False
    try:
        child = """
import os
import subprocess
import sys
import time
from pathlib import Path

ready = Path(sys.argv[1])
go = Path(sys.argv[2])
ready.write_text(str(os.getpid()), encoding="ascii")
deadline = time.monotonic() + 5
while not go.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if not go.exists():
    raise SystemExit(4)
children = []
spawn_denied = False
for _ in range(16):
    try:
        children.append(
            subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
    except OSError:
        spawn_denied = True
        break
time.sleep(0.1)
for candidate in children:
    try:
        candidate.kill()
    except ProcessLookupError:
        pass
for candidate in children:
    try:
        candidate.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
raise SystemExit(0 if spawn_denied else 3)
"""
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", child, str(ready), str(go)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1"},
        )
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                break
            time.sleep(0.02)
        require(ready.exists(), "aggregate resource probe child did not start")
        (job.path / "cgroup.procs").write_text(str(process.pid), encoding="ascii")
        members = {int(value) for value in (job.path / "cgroup.procs").read_text(encoding="ascii").split()}
        require(process.pid in members, "aggregate resource probe child did not enter its cgroup")
        go.write_text("go", encoding="ascii")
        returncode = process.wait(timeout=10)
        violation = job.limit_violation()
        require(returncode == 0 and violation == "pids", "aggregate pids limit was not enforced")
        result = {
            "cpu_max": (job.path / "cpu.max").read_text(encoding="ascii").strip(),
            "memory_max_bytes": int((job.path / "memory.max").read_text(encoding="ascii").strip()),
            "pids_max": int((job.path / "pids.max").read_text(encoding="ascii").strip()),
            "pids_limit_enforced": True,
            "violation": violation,
            "removed_after_probe": False,
        }
        cgroup_path = job.path
        job.close()
        closed = True
        result["removed_after_probe"] = not cgroup_path.exists()
        require(result["removed_after_probe"], "aggregate resource probe cgroup was not removed")
        return result
    finally:
        ready.unlink(missing_ok=True)
        go.unlink(missing_ok=True)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if not closed:
            job.close()


def run_gateway_isolation_probe(
    pipeline: Any,
    gateway: pwd.struct_passwd,
) -> dict[str, Any]:
    from media_evidence.broker import BrokerServer

    socket_path = WORK_ROOT / "broker" / "broker.sock"
    server = BrokerServer(
        socket_path=socket_path,
        pipeline=pipeline,
        gateway_uid=gateway.pw_uid,
        gateway_gid=gateway.pw_gid,
        request_timeout=30,
    )
    server.start()
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"install_signal_handlers": False},
        daemon=True,
    )
    thread.start()
    try:
        result = subprocess.run(
            [
                "/usr/bin/setpriv",
                f"--reuid={gateway.pw_uid}",
                f"--regid={gateway.pw_gid}",
                "--clear-groups",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--pdeathsig=SIGKILL",
                "/opt/hermes-venv/bin/python",
                "-I",
                "/p4/p4_image_certification.py",
                "--gateway-isolation-probe",
                "--uid",
                str(gateway.pw_uid),
                "--gid",
                str(gateway.pw_gid),
                "--socket",
                str(socket_path),
                "--store",
                str(STORE_ROOT),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1"},
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
    require(not thread.is_alive(), "media evidence broker did not stop after the isolation probe")
    require(
        result.returncode == 0,
        f"gateway broker isolation probe failed: {(result.stderr or result.stdout).strip()[-1000:]}",
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CertificationFailure("gateway broker isolation probe returned invalid JSON") from exc
    return payload


def run_malware_canary(pipeline: Any, canary: dict[str, Any]) -> dict[str, Any]:
    from media_evidence.contracts import MediaEvidenceError

    runs_root = STORE_ROOT / "runs"
    require(not any(runs_root.iterdir()), "evidence store contained a run before the malware canary")
    observed_error = None
    try:
        pipeline.analyze(
            source_path=str(canary["path"]),
            rights_basis="user_provided",
            privacy="public",
            purpose="P4 required scanner negative canary",
            options=copy.deepcopy(P4_OPTIONS),
        )
    except MediaEvidenceError as exc:
        observed_error = exc.code
    require(observed_error == "malware_detected", "canonical malware canary did not fail with malware_detected")
    published = list(runs_root.iterdir())
    require(not published, "malware canary left a staged or published run")
    with pipeline.store.connect() as connection:
        jobs = connection.execute(
            "SELECT state, stage, manifest_path, manifest_sha256, error_code FROM jobs WHERE source_sha256 = ?",
            (canary["sha256"],),
        ).fetchall()
    require(
        len(jobs) == 1
        and jobs[0]["state"] == "failed"
        and jobs[0]["stage"] == "failed"
        and jobs[0]["manifest_path"] is None
        and jobs[0]["manifest_sha256"] is None
        and jobs[0]["error_code"] == "malware_detected",
        "malware canary job state is not a clean unpublished failure",
    )
    return {
        "sha256": canary["sha256"],
        "bytes": canary["bytes"],
        "observed_error": observed_error,
        "published_run": False,
    }


def build_pipeline_preflight(embedded: dict[str, Any]) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    from media_evidence.pipeline import MediaEvidencePipeline

    require(os.geteuid() == 0, "P4 orchestrator must run as root")
    worker = pwd.getpwnam("hermes-media")
    acquisition = pwd.getpwnam("hermes-acquire")
    gateway = pwd.getpwnam("hermes-gateway")
    traverse = grp.getgrnam("hermes-evidence")
    require(
        worker.pw_uid != 0
        and worker.pw_gid != 0
        and acquisition.pw_uid != 0
        and acquisition.pw_gid != 0
        and worker.pw_uid != acquisition.pw_uid
        and worker.pw_gid != acquisition.pw_gid,
        "production media identities are not distinct non-root accounts",
    )
    require(
        gateway.pw_uid != 0
        and gateway.pw_gid != 0
        and len({worker.pw_uid, acquisition.pw_uid, gateway.pw_uid}) == 3
        and len({worker.pw_gid, acquisition.pw_gid, gateway.pw_gid, traverse.gr_gid}) == 4
        and gateway.pw_name not in traverse.gr_mem,
        "gateway identity is not isolated from the evidence traverse group",
    )

    pipeline = MediaEvidencePipeline(
        root=STORE_ROOT,
        allowed_roots=[CORPUS_ROOT, MALWARE_ROOT],
        require_worker_identity=True,
    )
    capabilities = pipeline.capabilities()
    require(capabilities.get("ok") is True, "media evidence capabilities failed")
    sandbox = capabilities.get("sandbox", {})
    require(sandbox.get("seccomp") is True, "seccomp is unavailable")
    require(isinstance(sandbox.get("landlock_abi"), int) and sandbox["landlock_abi"] >= 1, "Landlock is unavailable")
    require(sandbox.get("dedicated_identity") is True, "dedicated worker identity is unavailable")
    require(sandbox.get("dedicated_acquisition_identity") is True, "dedicated acquisition identity is unavailable")
    require(sandbox.get("aggregate_resource_limits") is True, "aggregate resource limits are unavailable")
    require(all(capabilities.get("binaries", {}).values()), "one or more production media binaries are unavailable")

    scanner_status = capabilities.get("malware_scanner", {})
    require(
        scanner_status.get("status") == "current"
        and isinstance(scanner_status.get("bytes"), int)
        and scanner_status["bytes"] > 0
        and HEX_64.fullmatch(str(scanner_status.get("sha256", ""))) is not None,
        "ClamAV definition provenance is unavailable or stale",
    )
    scanner = {
        key: scanner_status.get(key)
        for key in ("status", "file", "files", "bytes", "mtime_ns", "sha256")
    }
    model = capabilities.get("transcription_model", {})
    require(model.get("status") == "available", "offline transcription model is unavailable")
    for field, pattern in (("revision", HEX_40), ("model_sha256", HEX_64)):
        require(pattern.fullmatch(str(model.get(field, ""))) is not None, f"transcription model {field} is invalid")
    require(model.get("repository") == embedded["model"]["repository"], "model repository differs from SBOM")
    require(model.get("revision") == embedded["model"]["revision"], "model revision differs from SBOM")
    require(model.get("model_sha256") == embedded["model"]["model_sha256"], "model hash differs from SBOM")

    probe = run_sandbox_probe(worker)
    aggregate_probe = run_aggregate_resource_probe()
    broker_isolation = run_gateway_isolation_probe(pipeline, gateway)
    preflight = {
        "orchestrator_uid": os.geteuid(),
        "worker_identity": {"name": worker.pw_name, "uid": worker.pw_uid, "gid": worker.pw_gid},
        "acquisition_identity": {
            "name": acquisition.pw_name,
            "uid": acquisition.pw_uid,
            "gid": acquisition.pw_gid,
        },
        "gateway_identity": {"name": gateway.pw_name, "uid": gateway.pw_uid, "gid": gateway.pw_gid},
        "traverse_group": {"name": traverse.gr_name, "gid": traverse.gr_gid},
        "broker_isolation": broker_isolation,
        "sandbox": {
            "seccomp": True,
            "landlock_abi": sandbox["landlock_abi"],
            "aggregate_resource_limits": True,
            "aggregate_resource_probe": aggregate_probe,
            "identity_probe": probe,
        },
        "scanner": {**embedded["scanner"], "definitions": scanner},
        "model": model,
        "harness_mount_read_only": True,
        "image_root_read_only": True,
        "network_interfaces": [name for _, name in socket.if_nameindex()],
    }
    return pipeline, preflight, scanner, model


def artifact_path(run_root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative and "\\" not in relative and "\x00" not in relative, "artifact path is invalid")
    pure = PurePosixPath(relative)
    require(not pure.is_absolute() and all(part not in {"", ".", ".."} for part in pure.parts), "artifact path escapes run")
    path = run_root.joinpath(*pure.parts)
    current = run_root
    for part in pure.parts:
        current = current / part
        metadata = current.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "artifact path contains a link")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "artifact is not a regular file")
    return path


def verify_artifacts(manifest_path: Path, manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "manifest artifact inventory is empty")
    verified = []
    by_id = {}
    paths = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "manifest artifact entry is invalid")
        path = artifact_path(manifest_path.parent, artifact.get("path"))
        digest, size = hash_file(path)
        require(size > 0 and digest == artifact.get("sha256") and size == artifact.get("bytes"), "artifact integrity mismatch")
        require(artifact.get("id") == f"artifact:sha256:{digest}", "artifact ID is not content addressed")
        require(artifact.get("path") not in paths, "artifact inventory contains a duplicate path")
        paths.add(artifact["path"])
        media_type = str(artifact.get("media_type", ""))
        payload_contract = validate_artifact_payload(path, media_type, f"{artifact.get('kind')} artifact")
        existing = by_id.get(artifact["id"])
        if existing is not None:
            require(
                existing.get("kind") == artifact.get("kind") and existing.get("media_type") == media_type,
                "content-identical artifacts have contradictory metadata",
            )
        else:
            by_id[artifact["id"]] = artifact
        verified.append(
            {
                "id": artifact["id"],
                "kind": artifact.get("kind"),
                "path": artifact.get("path"),
                "media_type": media_type,
                "sha256": digest,
                "bytes": size,
                "payload_contract": payload_contract,
            }
        )

    index_id = manifest.get("evidence", {}).get("index_artifact_id")
    index = by_id.get(index_id)
    require(index is not None and index.get("kind") == "evidence_index", "evidence index artifact is invalid")
    index_path = artifact_path(manifest_path.parent, index["path"])
    evidence = []
    evidence_ids = set()
    job_id = manifest.get("job", {}).get("id")
    for record in read_ndjson_objects(index_path, "evidence index artifact"):
        require(record.get("artifact_id") in by_id, "evidence references an unknown artifact")
        require(record.get("trust") == "untrusted", "evidence trust marker is invalid")
        require(record.get("instructional_text") is False, "evidence instruction marker is invalid")
        content = record.get("text")
        expected_hash = sha256_bytes(content.encode("utf-8")) if isinstance(content, str) else by_id[record["artifact_id"]]["sha256"]
        require(record.get("content_sha256") == expected_hash, "evidence content hash is invalid")
        identity = {
            "job_id": job_id,
            "kind": record.get("kind"),
            "artifact_id": record.get("artifact_id"),
            "anchor": record.get("anchor"),
            "content_sha256": expected_hash,
        }
        expected_id = f"ev:{record.get('kind')}:{sha256_bytes(canonical_json_bytes(identity))[:24]}"
        require(record.get("evidence_id") == expected_id, "evidence ID is invalid")
        require(expected_id not in evidence_ids, "evidence index contains a duplicate ID")
        evidence_ids.add(expected_id)
        evidence.append(record)
    require(len(evidence) == manifest.get("evidence", {}).get("count"), "evidence count is invalid")
    require(
        sorted({record.get("kind") for record in evidence}) == manifest.get("evidence", {}).get("kinds"),
        "evidence kind inventory is invalid",
    )
    return sorted(verified, key=lambda item: item["path"]), evidence


def read_json_artifact(manifest_path: Path, manifest: dict[str, Any], kind: str) -> dict[str, Any]:
    matches = [artifact for artifact in manifest["artifacts"] if artifact.get("kind") == kind]
    require(len(matches) == 1, f"expected one {kind} artifact")
    return read_json_object(artifact_path(manifest_path.parent, matches[0]["path"]), f"{kind} artifact")


def normalized_words(text: str) -> set[str]:
    return set(NORMALIZED_WORD.findall(text.lower()))


def single_artifact_path(manifest_path: Path, manifest: dict[str, Any], kind: str) -> Path:
    matches = [artifact for artifact in manifest["artifacts"] if artifact.get("kind") == kind]
    require(len(matches) == 1, f"expected one {kind} artifact")
    return artifact_path(manifest_path.parent, matches[0]["path"])


def verify_lane(
    pipeline: Any,
    spec: dict[str, Any],
    corpus_input: dict[str, Any],
    scanner: dict[str, Any],
    model: dict[str, Any],
    image_id: str,
    source_commit: str,
    sbom_sha256: str,
) -> dict[str, Any]:
    from media_evidence.contracts import canonical_json_bytes as manifest_json_bytes
    from media_evidence.contracts import validate_manifest_schema, verify_manifest

    source = CORPUS_ROOT / spec["filename"]
    source_sha256, source_bytes = hash_file(source)
    require(source_sha256 == corpus_input["sha256"] and source_bytes == corpus_input["bytes"], "corpus input changed")
    validate_source_payload(source, spec["source_payload_contract"])

    result = pipeline.analyze(
        source_path=str(source),
        rights_basis="user_provided",
        privacy="public",
        purpose=f"P4 candidate image certification: {spec['name']} lane",
        options=copy.deepcopy(P4_OPTIONS),
    )
    require(result.get("ok") is True and result.get("cached") is False, "lane did not execute as a new production job")
    require(result.get("media_kind") == spec["media_kind"], "lane returned the wrong media kind")
    manifest_path = Path(result["manifest_path"])
    status = pipeline.status(result["job_id"])
    require(status.get("state") == "completed" and Path(status["manifest_path"]) == manifest_path, "published job status is invalid")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_manifest_schema(manifest)
    require(verify_manifest(manifest, pipeline.store.key_path), "manifest signature verification failed")
    unsigned = copy.deepcopy(manifest)
    integrity = unsigned.pop("integrity")
    payload_sha256 = sha256_bytes(manifest_json_bytes(unsigned))
    require(payload_sha256 == integrity.get("payload_sha256"), "manifest signed payload hash is invalid")
    manifest_sha256, manifest_bytes = hash_file(manifest_path)

    source_record = manifest.get("source", {})
    require(source_record.get("sha256") == source_sha256, "manifest source hash is invalid")
    require(source_record.get("bytes") == source_bytes, "manifest source size is invalid")
    require(source_record.get("actual_mime") == spec["expected_mime"], "manifest MIME is invalid")
    require(source_record.get("media_kind") == spec["media_kind"], "manifest media kind is invalid")
    require(manifest.get("acquisition", {}).get("adapter") == "local", "lane did not use local acquisition")
    require(manifest.get("acquisition", {}).get("network_used") is False, "lane acquisition used network")

    execution = manifest.get("execution", {})
    require(execution.get("network") == "denied", "manifest network policy is invalid")
    require(
        execution.get("sandbox") == "seccomp+landlock+uid+cgroupv2",
        "manifest sandbox identity is invalid",
    )
    require(execution.get("parameters") == P4_OPTIONS, "manifest execution options are not P4 strict")
    runtime = execution.get("runtime", {})
    require(runtime.get("runtime_commit") == source_commit, "manifest source commit is not embedded")
    require(runtime.get("sbom_sha256") == sbom_sha256, "manifest SBOM hash is not embedded")
    require(runtime.get("image_digest") == image_id, "manifest image ID is not embedded")
    require(runtime.get("deployment_id") == "unknown", "certification unexpectedly has a deployment identity")

    scanner_subset = {key: scanner.get(key) for key in ("status", "file", "bytes", "mtime_ns", "sha256")}
    require(execution.get("scanner_revision") == scanner_subset, "manifest scanner provenance changed")
    dependencies = execution.get("dependencies", {})
    worker_scanner = dependencies.get("clamav_definitions", {})
    worker_scanner = {
        key: worker_scanner.get(key)
        for key in ("status", "file", "files", "bytes", "mtime_ns", "sha256")
    }
    require(worker_scanner == scanner, "worker scanner provenance changed")
    require(dependencies.get("whisper_model") == model, "worker model provenance changed")
    require(dependencies.get("qpdf") is True, "qpdf was unavailable to the worker")

    quality = manifest.get("quality", {})
    warnings = set(quality.get("warnings", []))
    require(warnings == spec["warnings"], f"lane used an unavailable, disabled, or unexpected fallback: {sorted(warnings)}")
    require(quality.get("tier") == spec["expected_quality_tier"], "lane quality tier is not the expected complete/partial tier")
    require(quality.get("disagreements") == [], "lane contains extraction disagreements")
    validate_quality_coverage(quality.get("coverage"), spec)
    artifacts, evidence = verify_artifacts(manifest_path, manifest)
    actual_artifacts: dict[str, set[str]] = {}
    for artifact in artifacts:
        actual_artifacts.setdefault(str(artifact["kind"]), set()).add(str(artifact["media_type"]))
    for kind, media_type in spec["artifact_kinds"].items():
        require(media_type in actual_artifacts.get(kind, set()), f"lane is missing expected artifact {kind}:{media_type}")
    actual_evidence = {str(record.get("kind")) for record in evidence}
    require(spec["evidence_kinds"].issubset(actual_evidence), "lane is missing expected evidence kinds")

    text_checks: dict[str, dict[str, list[str]]] = {}
    expected_ocr = set(spec["required_ocr_words"])
    if expected_ocr:
        extracted = " ".join(
            str(record.get("text", "")) for record in evidence if record.get("kind") in {"ocr_text", "frame_ocr"}
        )
        matched = expected_ocr & normalized_words(extracted)
        require(matched == expected_ocr, f"lane OCR did not recover expected words: {sorted(expected_ocr - matched)}")
        text_checks["ocr"] = {"expected_words": sorted(expected_ocr), "matched_words": sorted(matched)}

    expected_transcript = set(spec["required_transcript_words"])
    if expected_transcript:
        transcripts = [record for record in evidence if record.get("kind") == "transcript_segment"]
        require(transcripts and all(str(record.get("text", "")).strip() for record in transcripts), "lane transcription is empty")
        transcript_text = " ".join(str(record["text"]) for record in transcripts)
        matched = expected_transcript & normalized_words(transcript_text)
        require(
            matched == expected_transcript,
            f"lane transcription did not recover expected words: {sorted(expected_transcript - matched)}",
        )
        text_checks["transcript"] = {
            "expected_words": sorted(expected_transcript),
            "matched_words": sorted(matched),
        }
        metadata = read_json_artifact(manifest_path, manifest, "transcription_metadata")
        require(metadata.get("provider") == "faster_whisper_local", "transcription used the wrong provider")
        require(metadata.get("model") == "base.en", "transcription used the wrong model")
        require(metadata.get("model_provenance") == model, "transcription metadata provenance is invalid")

    media_contract = None
    if "probe_contract" in spec:
        probe = read_json_artifact(manifest_path, manifest, "media_probe")
        artifact_probe = validate_probe_contract(probe, spec["probe_contract"], f"{spec['name']} media_probe artifact")
        direct_probe = validate_probe_contract(ffprobe_json(source), spec["probe_contract"], f"{spec['name']} source")
        require(artifact_probe == direct_probe, "media_probe artifact differs from independent ffprobe")
        normalized_contract = {
            "format_names": {"wav"},
            "duration_seconds": spec["probe_contract"]["duration_seconds"],
            "duration_tolerance_seconds": max(0.1, spec["probe_contract"]["duration_tolerance_seconds"]),
            "streams": (
                {"codec_type": "audio", "codec_name": "pcm_s16le", "sample_rate": "16000", "channels": 1},
            ),
        }
        normalized_audio = single_artifact_path(manifest_path, manifest, "normalized_audio")
        normalized_probe = validate_probe_contract(
            ffprobe_json(normalized_audio),
            normalized_contract,
            f"{spec['name']} normalized audio artifact",
        )
        require(
            abs(direct_probe["duration_ms"] - normalized_probe["duration_ms"]) <= 100,
            "normalized audio duration differs from its source",
        )
        media_contract = {"source": direct_probe, "normalized_audio": normalized_probe}

    lane_result = {
        "name": spec["name"],
        "status": "passed",
        "source": {
            "path": corpus_input["path"],
            "sha256": source_sha256,
            "bytes": source_bytes,
            "actual_mime": source_record["actual_mime"],
            "media_kind": source_record["media_kind"],
            "payload_contract": spec["source_payload_contract"],
        },
        "job_id": result["job_id"],
        "manifest": {
            "sha256": manifest_sha256,
            "bytes": manifest_bytes,
            "payload_sha256": integrity["payload_sha256"],
            "signature_algorithm": integrity["algorithm"],
            "signature_key_id": integrity["key_id"],
            "signature": integrity["signature"],
        },
        "artifacts": artifacts,
        "evidence": {
            "count": len(evidence),
            "kinds": sorted(actual_evidence),
            "index_artifact_id": manifest["evidence"]["index_artifact_id"],
            "text_checks": text_checks,
        },
        "quality": {
            "tier": manifest["quality"]["tier"],
            "warnings": sorted(warnings),
            "coverage": manifest["quality"]["coverage"],
            "disagreements": manifest["quality"]["disagreements"],
        },
        "scanner_revision": execution["scanner_revision"],
        "model_provenance": model,
        "sandbox": execution["sandbox"],
        "runtime_provenance": {
            "image_id": runtime["image_digest"],
            "source_commit": runtime["runtime_commit"],
            "sbom_sha256": runtime["sbom_sha256"],
            "deployment_id": runtime["deployment_id"],
        },
    }
    if media_contract is not None:
        lane_result["media_contract"] = media_contract
    return lane_result


def validated_final_report(report: dict[str, Any]) -> dict[str, Any]:
    finalized = finalize_report(report)
    try:
        validate_report_shape(finalized)
    except BaseException as exc:
        if report.get("status") != "passed":
            raise CertificationFailure("refusing to write malformed failed certification report") from exc
        downgraded = copy.deepcopy(report)
        downgraded["status"] = "failed"
        error = bounded_error("report", exc)
        downgraded["errors"].append(error)
        downgraded["lanes"] = [
            {
                "name": spec["name"],
                "status": "failed",
                "error": {"stage": "report", "type": error["type"], "message": error["message"]},
            }
            for spec in LANE_SPECS
        ]
        finalized = finalize_report(downgraded)
        validate_report_shape(finalized)
    return finalized


def validate_report_file(path: Path) -> dict[str, Any]:
    metadata = require_regular_file(path, "certification report")
    require(metadata.st_size <= 16 * 1024 * 1024, "certification report exceeds its size limit")
    content = path.read_bytes()
    try:
        report = strict_json_loads(content)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CertificationFailure("certification report is not valid JSON") from exc
    require(isinstance(report, dict), "certification report is not a JSON object")
    require(content == canonical_json_bytes(report) + b"\n", "certification report is not canonical newline-terminated JSON")
    validate_report_shape(report)
    return report


def assert_network_isolated() -> None:
    interface_names = [name for _, name in socket.if_nameindex()]
    require("lo" in interface_names, "container has no loopback network interface")

    for name in interface_names:
        if name == "lo":
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                fcntl.ioctl(probe.fileno(), 0x8915, struct.pack("256s", name.encode("ascii")))
            except OSError as exc:
                require(exc.errno in {errno.EADDRNOTAVAIL, errno.ENODEV}, "network interface address probe failed")
            else:
                raise CertificationFailure("container has a configured non-loopback IPv4 interface")

    ipv6_interfaces = {
        fields[-1]
        for line in Path("/proc/net/if_inet6").read_text(encoding="ascii").splitlines()
        if (fields := line.split())
    }
    require(ipv6_interfaces <= {"lo"}, "container has a configured non-loopback IPv6 interface")

    ipv4_routes = [
        fields
        for line in Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
        if (fields := line.split()) and fields[0] != "lo"
    ]
    require(not ipv4_routes, "container has a non-loopback IPv4 route")

    ipv6_routes = [
        fields
        for line in Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
        if (fields := line.split()) and fields[-1] != "lo"
    ]
    require(not ipv6_routes, "container has a non-loopback IPv6 route")


def certification_main(report_path: Path) -> int:
    image_id = os.getenv("P4_IMAGE_ID", "")
    image_reference = os.getenv("P4_IMAGE_REFERENCE", "")
    source_commit = os.getenv("P4_SOURCE_COMMIT", "")
    harness_sha256, _ = hash_file(Path(__file__))
    report = new_report(image_id, image_reference, source_commit, harness_sha256)
    if report_path.exists() or report_path.is_symlink():
        report_path.unlink()

    try:
        require(os.getenv("P4_NETWORK_MODE") == "none", "wrapper did not declare network=none")
        require(not os.getenv("RAILWAY_DEPLOYMENT_ID"), "deployment identity must be empty during certification")
        assert_network_isolated()
        assert_write_denied(Path("/p4/.p4-write-probe"))
        assert_write_denied(Path("/.p4-image-write-probe"))
        candidate, embedded = verify_candidate(image_id, image_reference, source_commit)
        report["candidate"] = candidate
        report["corpus"]["inputs"] = generate_corpus()
        malware_canary = generate_malware_canary()
        pipeline, preflight, scanner, model = build_pipeline_preflight(embedded)
        preflight["malware_canary"] = run_malware_canary(pipeline, malware_canary)
        report["preflight"] = preflight
    except BaseException as exc:
        error = bounded_error("preflight", exc)
        report["errors"].append(error)
        report["lanes"] = [
            {"name": spec["name"], "status": "failed", "error": {"stage": "preflight", "message": error["message"]}}
            for spec in LANE_SPECS
        ]
    else:
        inputs = {item["lane"]: item for item in report["corpus"]["inputs"]}
        for spec in LANE_SPECS:
            try:
                lane = verify_lane(
                    pipeline,
                    spec,
                    inputs[spec["name"]],
                    scanner,
                    model,
                    image_id,
                    source_commit,
                    report["candidate"]["sbom"]["sha256"],
                )
            except BaseException as exc:
                error = bounded_error(f"lane:{spec['name']}", exc)
                report["errors"].append(error)
                lane = {"name": spec["name"], "status": "failed", "error": error}
            report["lanes"].append(lane)

    report["status"] = "passed" if not report["errors"] and all(lane["status"] == "passed" for lane in report["lanes"]) else "failed"
    finalized = validated_final_report(report)
    write_report(report_path, finalized)
    print(canonical_json_bytes({"report": str(report_path), "status": finalized["status"]}).decode("ascii"))
    return 0 if finalized["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "--sandbox-probe":
        return sandbox_probe(arguments[1:])
    if arguments and arguments[0] == "--gateway-isolation-probe":
        return gateway_isolation_probe(arguments[1:])
    parser = argparse.ArgumentParser(description="Certify P4 media evidence lanes in an immutable candidate image")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--report", type=Path)
    destination.add_argument("--validate-report", type=Path)
    args = parser.parse_args(arguments)
    if args.validate_report is not None:
        report = validate_report_file(args.validate_report)
        print(report["status"])
        return 0
    assert args.report is not None
    return certification_main(args.report)


if __name__ == "__main__":
    raise SystemExit(main())
