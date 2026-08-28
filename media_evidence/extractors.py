from __future__ import annotations

import csv
import difflib
import functools
import hashlib
import importlib.metadata
import json
import math
import os
import re
import stat
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .contracts import (
    WORKER_SCHEMA_ID,
    MediaEvidenceError,
    atomic_write_json,
    atomic_write_jsonl,
    media_kind_for_mime,
)
from .sandbox import run_command, validated_whisper_model_path


_BINARIES = {
    "clamscan": Path("/usr/bin/clamscan"),
    "exiftool": Path("/usr/bin/exiftool"),
    "ffmpeg": Path("/usr/bin/ffmpeg"),
    "ffprobe": Path("/usr/bin/ffprobe"),
    "file": Path("/usr/bin/file"),
    "pdfinfo": Path("/usr/bin/pdfinfo"),
    "pdftoppm": Path("/usr/bin/pdftoppm"),
    "pdftotext": Path("/usr/bin/pdftotext"),
    "qpdf": Path("/usr/bin/qpdf"),
    "tesseract": Path("/usr/bin/tesseract"),
}

_SCENE_TIME = re.compile(r"pts_time:([0-9]+(?:\.[0-9]+)?)")
_CLAMAV_MAX_AGE_SECONDS = 14 * 24 * 60 * 60
_CLAMAV_DEFINITION_SUFFIXES = {
    ".cbc",
    ".cat",
    ".cdb",
    ".cfg",
    ".cld",
    ".crb",
    ".cud",
    ".cvd",
    ".db",
    ".fp",
    ".ftm",
    ".gdb",
    ".hdb",
    ".hdu",
    ".hsb",
    ".hsu",
    ".idb",
    ".ign",
    ".ign2",
    ".ldb",
    ".ldu",
    ".mdb",
    ".mdu",
    ".msb",
    ".msu",
    ".ndb",
    ".ndu",
    ".pdb",
    ".pwdb",
    ".rmd",
    ".sdb",
    ".sfp",
    ".sign",
    ".wdb",
    ".yar",
    ".yara",
    ".zmd",
}


class Extraction:
    def __init__(self, output: Path):
        self.output = output
        self.artifacts: list[dict[str, str]] = []
        self.evidence: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.disagreements: list[dict[str, Any]] = []
        self.coverage: dict[str, Any] = {}
        self.quality_tier = "complete"
        self.scanner_definitions: dict[str, Any] | None = None

    def path(self, relative: str) -> Path:
        path = self.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def artifact(self, relative: str, kind: str, media_type: str) -> None:
        self.artifacts.append({"path": relative, "kind": kind, "media_type": media_type})

    def add_evidence(
        self,
        kind: str,
        artifact_path: str,
        anchor: dict[str, Any],
        text: str | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "kind": kind,
            "artifact_path": artifact_path,
            "anchor": anchor,
        }
        if text is not None:
            record["text"] = text
        self.evidence.append(record)

    def warn(self, code: str) -> None:
        if code not in self.warnings:
            self.warnings.append(code)
        if self.quality_tier == "complete":
            self.quality_tier = "partial"


def extract_media(source: Path, output: Path, options: dict[str, Any]) -> dict[str, Any]:
    extraction = Extraction(output)
    _scan_source(source, options, extraction)
    actual_mime = _detect_mime(source)
    media_kind = media_kind_for_mime(actual_mime)
    if media_kind == "image":
        _extract_image(source, extraction, options)
    elif media_kind == "document":
        _extract_pdf(source, extraction, options)
    elif media_kind == "audio":
        _extract_audio(source, extraction, options)
    elif media_kind == "video":
        _extract_video(source, extraction, options)
    if not extraction.evidence:
        raise MediaEvidenceError("insufficient_evidence", "Extraction produced no anchored evidence")
    return {
        "schema": WORKER_SCHEMA_ID,
        "actual_mime": actual_mime,
        "media_kind": media_kind,
        "artifacts": extraction.artifacts,
        "evidence": extraction.evidence,
        "warnings": extraction.warnings,
        "disagreements": extraction.disagreements,
        "coverage": extraction.coverage,
        "quality_tier": extraction.quality_tier,
        "dependencies": _dependency_versions(extraction.scanner_definitions),
    }


def _binary(name: str, *, required: bool = True) -> Path | None:
    path = _BINARIES[name]
    if path.is_file() and os.access(path, os.X_OK):
        return path
    if required:
        raise MediaEvidenceError("dependency_unavailable", f"Required media dependency is unavailable: {name}")
    return None


def _dependency_versions(scanner_definitions: dict[str, Any] | None) -> dict[str, Any]:
    versions: dict[str, Any] = {
        name: bool(path.is_file() and os.access(path, os.X_OK))
        for name, path in _BINARIES.items()
    }
    for distribution in ("faster-whisper", "Pillow"):
        key = distribution.lower().replace("-", "_")
        try:
            versions[key] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            versions[key] = "missing"
    versions["clamav_definitions"] = scanner_definitions or {"status": "not_used"}
    versions["whisper_model"] = whisper_model_status("base.en")
    return versions


def whisper_model_status(model: str) -> dict[str, Any]:
    if model != "base.en":
        return {"status": "invalid", "repository": None, "revision": None, "model_sha256": None}
    try:
        model_path = _resolve_whisper_model(model)
    except MediaEvidenceError:
        return {"status": "invalid", "repository": None, "revision": None, "model_sha256": None}
    if model_path is None:
        return {"status": "missing", "repository": None, "revision": None, "model_sha256": None}
    provenance_path = model_path / "provenance.json"
    try:
        provenance_metadata = provenance_path.lstat()
        if (
            provenance_path.is_symlink()
            or not provenance_path.is_file()
            or provenance_metadata.st_nlink != 1
            or provenance_metadata.st_size > 16 * 1024
        ):
            raise OSError
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "unprovenanced", "repository": None, "revision": None, "model_sha256": None}
    values = {key: provenance.get(key) for key in ("repository", "revision", "model_sha256")}
    if (
        values["repository"] != "Systran/faster-whisper-base.en"
        or not isinstance(values["revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", values["revision"]) is None
        or not isinstance(values["model_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", values["model_sha256"]) is None
    ):
        return {"status": "invalid", "repository": None, "revision": None, "model_sha256": None}
    try:
        model_pathname = model_path / "model.bin"
        model_sha256, model_bytes = _stable_file_identity(model_pathname)
    except OSError:
        return {"status": "invalid", **values}
    if model_sha256 != values["model_sha256"]:
        return {"status": "corrupt", **values, "bytes": model_bytes}
    return {"status": "available", **values, "bytes": model_bytes}


@functools.lru_cache(maxsize=32)
def _hash_stable_file(
    path: str,
    device: int,
    inode: int,
    size: int,
    mtime_ns: int,
    ctime_ns: int,
) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        expected = (device, inode, size, mtime_ns, ctime_ns)
        observed = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or observed != expected:
            raise OSError("unsafe or changing file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        final = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if final != expected:
            raise OSError("file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _stable_file_identity(path: Path) -> tuple[str, int]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise OSError("unsafe file")
    digest = _hash_stable_file(
        str(path),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    return digest, metadata.st_size


def clamav_definition_status(
    database: Path = Path("/var/lib/clamav"),
    *,
    now: float | None = None,
) -> dict[str, Any]:
    missing = {
        "status": "missing",
        "age_seconds": None,
        "file": None,
        "files": 0,
        "bytes": None,
        "mtime_ns": None,
        "sha256": None,
    }
    try:
        database_metadata = database.lstat()
        if database.is_symlink() or not stat.S_ISDIR(database_metadata.st_mode):
            return {**missing, "status": "invalid"}
        paths = sorted(
            (path for path in database.iterdir() if path.suffix.lower() in _CLAMAV_DEFINITION_SUFFIXES),
            key=lambda path: path.name,
        )
    except OSError:
        return missing
    definitions: list[tuple[Path, os.stat_result]] = []
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError:
            return {**missing, "status": "invalid", "file": path.name}
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size <= 0:
            return {**missing, "status": "invalid", "file": path.name}
        definitions.append((path, metadata))
    daily_candidates = [item for item in definitions if item[0].name in {"daily.cvd", "daily.cld"}]
    if not daily_candidates:
        return missing
    current, metadata = max(daily_candidates, key=lambda item: item[1].st_mtime_ns)
    age = int((time.time() if now is None else now) - metadata.st_mtime)
    definition_digest = hashlib.sha256()
    total_bytes = 0
    try:
        for path, expected in definitions:
            file_sha256, file_bytes = _stable_file_identity(path)
            identity = path.lstat()
            if (
                identity.st_dev,
                identity.st_ino,
                identity.st_size,
                identity.st_mtime_ns,
                identity.st_ctime_ns,
            ) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_size,
                expected.st_mtime_ns,
                expected.st_ctime_ns,
            ):
                raise OSError("definition changed while hashing")
            definition_digest.update(
                json.dumps(
                    {"bytes": file_bytes, "name": path.name, "sha256": file_sha256},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            definition_digest.update(b"\n")
            total_bytes += file_bytes
        current_names = sorted(
            path.name for path in database.iterdir() if path.suffix.lower() in _CLAMAV_DEFINITION_SUFFIXES
        )
        if current_names != [path.name for path, _ in definitions]:
            raise OSError("definition set changed while hashing")
        for path, expected in definitions:
            observed = path.lstat()
            if (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
                observed.st_mtime_ns,
                observed.st_ctime_ns,
            ) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_size,
                expected.st_mtime_ns,
                expected.st_ctime_ns,
            ):
                raise OSError("definition changed after hashing")
    except OSError:
        return {
            "status": "invalid",
            "age_seconds": max(0, age),
            "file": current.name,
            "files": len(definitions),
            "bytes": None,
            "mtime_ns": metadata.st_mtime_ns,
            "sha256": None,
        }
    revision = {
        "age_seconds": max(0, age),
        "file": current.name,
        "files": len(definitions),
        "bytes": total_bytes,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": definition_digest.hexdigest(),
    }
    if age < -5 * 60:
        return {**revision, "status": "future_dated", "age_seconds": age}
    if age > _CLAMAV_MAX_AGE_SECONDS:
        return {**revision, "status": "stale"}
    return {**revision, "status": "current"}


def _scan_source(source: Path, options: dict[str, Any], extraction: Extraction) -> None:
    clamscan = _binary("clamscan", required=False)
    if clamscan is None:
        extraction.scanner_definitions = {"status": "unavailable"}
        if options["scan_policy"] == "required":
            raise MediaEvidenceError("scanner_unavailable", "Required malware scanner is unavailable")
        extraction.warn("malware_scanner_unavailable")
        return
    definitions = clamav_definition_status()
    extraction.scanner_definitions = definitions
    if definitions["status"] != "current":
        if options["scan_policy"] == "required":
            raise MediaEvidenceError(
                "scanner_definitions_invalid",
                "Required malware definitions are missing, stale, or invalid",
            )
        extraction.warn(f"malware_definitions_{definitions['status']}")
    scan_limit = options["max_source_bytes"]
    result = run_command(
        [
            str(clamscan),
            "--no-summary",
            "--infected",
            "--stdout",
            "--cross-fs=no",
            f"--max-filesize={scan_limit}",
            f"--max-scansize={scan_limit}",
            "--alert-exceeds-max=yes",
            str(source),
        ],
        timeout=180,
        max_output_bytes=1024 * 1024,
        accepted_returncodes={0, 1, 2},
    )
    definitions_after = clamav_definition_status()
    revision_keys = ("status", "file", "bytes", "mtime_ns", "sha256")
    if any(definitions.get(key) != definitions_after.get(key) for key in revision_keys):
        extraction.scanner_definitions = {
            "status": "changed_during_scan",
            "before": {key: definitions.get(key) for key in revision_keys},
            "after": {key: definitions_after.get(key) for key in revision_keys},
        }
        if options["scan_policy"] == "required":
            raise MediaEvidenceError(
                "scanner_definitions_changed",
                "Malware definitions changed during required screening",
            )
        extraction.warn("malware_definitions_changed_during_scan")
    if result.returncode == 1:
        raise MediaEvidenceError("malware_detected", "The source failed malware screening")
    if result.returncode == 2:
        if options["scan_policy"] == "required":
            raise MediaEvidenceError("scanner_failed", "Required malware screening failed closed")
        extraction.warn("malware_scanner_failed")


def _detect_mime(source: Path) -> str:
    executable = _binary("file")
    result = run_command(
        [str(executable), "--brief", "--mime-type", "--", str(source)],
        timeout=30,
        max_output_bytes=4096,
    )
    actual_mime = result.stdout.strip().lower()
    if not actual_mime or len(actual_mime) > 160:
        raise MediaEvidenceError("mime_probe_failed", "The source MIME type could not be determined")
    return actual_mime


def _write_probe(extraction: Extraction, probe: dict[str, Any]) -> str:
    relative = "metadata/probe.json"
    atomic_write_json(extraction.path(relative), probe)
    extraction.artifact(relative, "media_probe", "application/json")
    return relative


def _sanitize_probe(raw: dict[str, Any]) -> dict[str, Any]:
    streams = []
    for stream in raw.get("streams", []):
        if not isinstance(stream, dict):
            continue
        streams.append(
            {
                key: stream.get(key)
                for key in (
                    "index",
                    "codec_name",
                    "codec_type",
                    "width",
                    "height",
                    "pix_fmt",
                    "sample_rate",
                    "channels",
                    "channel_layout",
                    "duration",
                    "bit_rate",
                    "r_frame_rate",
                )
                if stream.get(key) is not None
            }
        )
    raw_format = raw.get("format") if isinstance(raw.get("format"), dict) else {}
    format_record = {
        key: raw_format.get(key)
        for key in ("format_name", "duration", "size", "bit_rate")
        if raw_format.get(key) is not None
    }
    return {"streams": streams, "format": format_record}


def _probe_av(source: Path) -> dict[str, Any]:
    ffprobe = _binary("ffprobe")
    result = run_command(
        [
            str(ffprobe),
            "-v",
            "error",
            "-show_format",
            "-show_streams",
            "-of",
            "json",
            str(source),
        ],
        timeout=60,
        max_output_bytes=4 * 1024 * 1024,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise MediaEvidenceError("malformed_media", "FFprobe returned invalid metadata") from exc


def _duration_seconds(probe: dict[str, Any]) -> float:
    values: list[float] = []
    raw_format = probe.get("format") if isinstance(probe.get("format"), dict) else {}
    for candidate in [raw_format.get("duration"), *[stream.get("duration") for stream in probe.get("streams", []) if isinstance(stream, dict)]]:
        try:
            value = float(candidate)
        except (TypeError, ValueError):
            continue
        if math.isfinite(value) and value > 0:
            values.append(value)
    if not values:
        raise MediaEvidenceError("malformed_media", "Media duration is unavailable")
    return max(values)


def _extract_image(source: Path, extraction: Extraction, options: dict[str, Any]) -> None:
    try:
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise MediaEvidenceError("dependency_unavailable", "Pillow is unavailable") from exc

    Image.MAX_IMAGE_PIXELS = options["max_pixels"]
    try:
        with Image.open(source) as opened:
            source_width, source_height = opened.size
            if source_width <= 0 or source_height <= 0 or source_width * source_height > options["max_pixels"]:
                raise MediaEvidenceError("pixel_budget_exceeded", "Image exceeds the pixel budget")
            if int(getattr(opened, "n_frames", 1)) != 1:
                raise MediaEvidenceError("unsupported_media_type", "Animated and multi-frame images are not accepted")
            image = ImageOps.exif_transpose(opened)
            image.load()
            width, height = image.size
            sanitized = image.convert("RGB")
    except Image.DecompressionBombError as exc:
        raise MediaEvidenceError("pixel_budget_exceeded", "Image exceeds the pixel budget") from exc
    except MediaEvidenceError:
        raise
    except Exception as exc:
        raise MediaEvidenceError("malformed_media", "Image decoding failed") from exc

    relative = "image/sanitized.png"
    target = extraction.path(relative)
    sanitized.save(target, format="PNG", optimize=False, compress_level=6)
    exiftool = _binary("exiftool", required=False)
    if exiftool:
        run_command(
            [str(exiftool), "-all=", "-overwrite_original", str(target)],
            timeout=60,
            max_output_bytes=1024 * 1024,
        )
    else:
        extraction.warn("metadata_verifier_unavailable")
    extraction.artifact(relative, "sanitized_image", "image/png")
    extraction.add_evidence(
        "image_region",
        relative,
        {"x": 0, "y": 0, "width": width, "height": height},
    )

    tile_count = 0
    if max(width, height) > 2048:
        x_edges = [0, width // 2, width]
        y_edges = [0, height // 2, height]
        for row in range(2):
            for column in range(2):
                box = (x_edges[column], y_edges[row], x_edges[column + 1], y_edges[row + 1])
                tile = sanitized.crop(box)
                tile_relative = f"image/tiles/tile-{row + 1}-{column + 1}.png"
                tile.save(extraction.path(tile_relative), format="PNG", optimize=False, compress_level=6)
                extraction.artifact(tile_relative, "image_tile", "image/png")
                extraction.add_evidence(
                    "image_region",
                    tile_relative,
                    {"x": box[0], "y": box[1], "width": box[2] - box[0], "height": box[3] - box[1]},
                )
                tile_count += 1

    ocr_lines = _tesseract_lines(target, extraction, options)
    if ocr_lines:
        ocr_relative = "image/ocr.jsonl"
        atomic_write_jsonl(extraction.path(ocr_relative), ocr_lines)
        extraction.artifact(ocr_relative, "ocr_text", "application/x-ndjson")
        for line in ocr_lines:
            extraction.add_evidence(
                "ocr_text",
                ocr_relative,
                {"page": 1, "region": line["region"], "line": line["line"]},
                line["text"],
            )
    extraction.coverage = {
        "width": width,
        "height": height,
        "tiles": tile_count,
        "ocr_lines": len(ocr_lines),
    }


def _tesseract_lines(image: Path, extraction: Extraction, options: dict[str, Any]) -> list[dict[str, Any]]:
    if not options["ocr"]:
        extraction.warn("ocr_disabled")
        return []
    tesseract = _binary("tesseract", required=False)
    if tesseract is None:
        extraction.warn("ocr_unavailable")
        return []
    language = options["language"] or "eng"
    result = run_command(
        [str(tesseract), str(image), "stdout", "-l", language, "tsv"],
        timeout=180,
        max_output_bytes=32 * 1024 * 1024,
    )
    groups: dict[tuple[int, int, int, int], list[dict[str, Any]]] = defaultdict(list)
    reader = csv.DictReader(result.stdout.splitlines(), delimiter="\t")
    for row in reader:
        text = (row.get("text") or "").strip()
        if not text:
            continue
        try:
            key = tuple(int(row[name]) for name in ("page_num", "block_num", "par_num", "line_num"))
            word = {
                "text": text,
                "left": int(row["left"]),
                "top": int(row["top"]),
                "width": int(row["width"]),
                "height": int(row["height"]),
            }
        except (KeyError, TypeError, ValueError):
            continue
        groups[key].append(word)
    lines: list[dict[str, Any]] = []
    for index, key in enumerate(sorted(groups), start=1):
        words = groups[key]
        left = min(word["left"] for word in words)
        top = min(word["top"] for word in words)
        right = max(word["left"] + word["width"] for word in words)
        bottom = max(word["top"] + word["height"] for word in words)
        lines.append(
            {
                "line": index,
                "text": " ".join(word["text"] for word in words),
                "region": {"x": left, "y": top, "width": right - left, "height": bottom - top},
            }
        )
    return lines


def _extract_pdf(source: Path, extraction: Extraction, options: dict[str, Any]) -> None:
    qpdf = _binary("qpdf", required=options["require_qpdf"])
    if qpdf is None:
        extraction.warn("qpdf_unavailable")
    else:
        checked = run_command(
            [str(qpdf), "--check", "--password=", str(source)],
            timeout=120,
            max_output_bytes=2 * 1024 * 1024,
            accepted_returncodes={0, 2, 3},
        )
        if checked.returncode != 0:
            diagnostic = f"{checked.stdout}\n{checked.stderr}".lower()
            if "password" in diagnostic or "encrypt" in diagnostic:
                raise MediaEvidenceError("encrypted_pdf", "Encrypted PDFs are not accepted")
            raise MediaEvidenceError("malformed_media", "PDF structural validation failed")

    pdfinfo = _binary("pdfinfo")
    info_result = run_command(
        [str(pdfinfo), str(source)],
        timeout=60,
        max_output_bytes=2 * 1024 * 1024,
    )
    info: dict[str, str] = {}
    for line in info_result.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            info[key.strip().lower().replace(" ", "_")] = value.strip()
    if info.get("encrypted", "no").lower().startswith("yes"):
        raise MediaEvidenceError("encrypted_pdf", "Encrypted PDFs are not accepted")
    try:
        pages = int(info["pages"])
    except (KeyError, ValueError) as exc:
        raise MediaEvidenceError("malformed_media", "PDF page count is unavailable") from exc
    if pages < 1 or pages > options["max_pages"]:
        raise MediaEvidenceError("page_budget_exceeded", "PDF exceeds the page budget")

    probe_relative = "metadata/pdf.json"
    atomic_write_json(
        extraction.path(probe_relative),
        {"pages": pages, "encrypted": False, "page_size": info.get("page_size", "unknown")},
    )
    extraction.artifact(probe_relative, "document_probe", "application/json")

    pdftotext = _binary("pdftotext")
    native_pages: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        result = run_command(
            [str(pdftotext), "-f", str(page), "-l", str(page), "-layout", str(source), "-"],
            timeout=60,
            max_output_bytes=4 * 1024 * 1024,
        )
        native_pages.append({"page": page, "text": result.stdout.strip()})
    native_relative = "document/native-pages.jsonl"
    atomic_write_jsonl(extraction.path(native_relative), native_pages)
    extraction.artifact(native_relative, "native_text", "application/x-ndjson")
    for page in native_pages:
        _add_text_chunks(
            extraction,
            kind="page_text",
            artifact_path=native_relative,
            text=page["text"],
            base_anchor={"page": page["page"], "extractor": "pdftotext"},
        )

    rendered = min(pages, options["max_render_pages"])
    if rendered < pages:
        extraction.warn("page_rendering_truncated")
    pdftoppm = _binary("pdftoppm")
    ocr_records: list[dict[str, Any]] = []
    native_by_page = {record["page"]: record["text"] for record in native_pages}
    for page in range(1, rendered + 1):
        prefix = extraction.path(f"document/pages/page-{page:04d}").with_suffix("")
        run_command(
            [
                str(pdftoppm),
                "-f",
                str(page),
                "-l",
                str(page),
                "-singlefile",
                "-r",
                "144",
                "-png",
                str(source),
                str(prefix),
            ],
            timeout=120,
            max_output_bytes=2 * 1024 * 1024,
        )
        image_path = prefix.with_suffix(".png")
        if not image_path.is_file():
            raise MediaEvidenceError("parser_failed", "PDF renderer produced no page image")
        image_relative = image_path.relative_to(extraction.output).as_posix()
        extraction.artifact(image_relative, "page_image", "image/png")
        extraction.add_evidence("page_image", image_relative, {"page": page, "dpi": 144})

        if options["ocr"] and len(native_by_page[page].strip()) < 80:
            lines = _tesseract_lines(image_path, extraction, options)
            page_text = " ".join(line["text"] for line in lines)
            for line in lines:
                record = {"page": page, **line}
                ocr_records.append(record)
            if page_text and native_by_page[page].strip():
                similarity = difflib.SequenceMatcher(
                    None,
                    " ".join(native_by_page[page].split()),
                    " ".join(page_text.split()),
                ).ratio()
                if similarity < 0.7:
                    extraction.disagreements.append(
                        {"kind": "native_ocr_text", "page": page, "similarity": round(similarity, 4)}
                    )

    if ocr_records:
        ocr_relative = "document/ocr.jsonl"
        atomic_write_jsonl(extraction.path(ocr_relative), ocr_records)
        extraction.artifact(ocr_relative, "ocr_text", "application/x-ndjson")
        for record in ocr_records:
            extraction.add_evidence(
                "ocr_text",
                ocr_relative,
                {"page": record["page"], "region": record["region"], "line": record["line"]},
                record["text"],
            )
    extraction.coverage = {
        "pages_total": pages,
        "pages_native_text": sum(bool(record["text"]) for record in native_pages),
        "pages_rendered": rendered,
        "ocr_lines": len(ocr_records),
    }


def _add_text_chunks(
    extraction: Extraction,
    *,
    kind: str,
    artifact_path: str,
    text: str,
    base_anchor: dict[str, Any],
    chunk_size: int = 100_000,
) -> None:
    if not text:
        return
    for start in range(0, len(text), chunk_size):
        chunk = text[start : start + chunk_size]
        extraction.add_evidence(
            kind,
            artifact_path,
            {**base_anchor, "char_start": start, "char_end": start + len(chunk)},
            chunk,
        )


def _extract_audio(source: Path, extraction: Extraction, options: dict[str, Any]) -> None:
    probe = _probe_av(source)
    sanitized_probe = _sanitize_probe(probe)
    _write_probe(extraction, sanitized_probe)
    if not any(stream.get("codec_type") == "audio" for stream in sanitized_probe["streams"]):
        raise MediaEvidenceError("malformed_media", "No audio stream was found")
    duration = _duration_seconds(probe)
    if duration > options["max_duration_seconds"]:
        raise MediaEvidenceError("duration_budget_exceeded", "Audio exceeds the duration budget")
    transcript_count = _extract_audio_bundle(
        source,
        extraction,
        options,
        prefix="audio",
        duration=duration,
    )
    extraction.coverage = {
        "duration_ms": int(duration * 1000),
        "transcript_segments": transcript_count,
    }


def _extract_audio_bundle(
    source: Path,
    extraction: Extraction,
    options: dict[str, Any],
    *,
    prefix: str,
    duration: float,
) -> int:
    ffmpeg = _binary("ffmpeg")
    wav_relative = f"{prefix}/audio.wav"
    wav = extraction.path(wav_relative)
    run_command(
        [
            str(ffmpeg),
            "-v",
            "error",
            "-i",
            str(source),
            "-map",
            "0:a:0",
            "-vn",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-c:a",
            "pcm_s16le",
            "-map_metadata",
            "-1",
            "-y",
            str(wav),
        ],
        timeout=min(600, max(60, duration * 2)),
        max_output_bytes=2 * 1024 * 1024,
    )
    extraction.artifact(wav_relative, "normalized_audio", "audio/wav")

    waveform_relative = f"{prefix}/waveform.png"
    waveform = extraction.path(waveform_relative)
    try:
        run_command(
            [
                str(ffmpeg),
                "-v",
                "error",
                "-i",
                str(wav),
                "-filter_complex",
                "showwavespic=s=1200x240:colors=white",
                "-frames:v",
                "1",
                "-y",
                str(waveform),
            ],
            timeout=120,
            max_output_bytes=2 * 1024 * 1024,
        )
        extraction.artifact(waveform_relative, "audio_waveform", "image/png")
        extraction.add_evidence(
            "audio_waveform",
            waveform_relative,
            {"start_ms": 0, "end_ms": int(duration * 1000)},
        )
    except MediaEvidenceError:
        waveform.unlink(missing_ok=True)
        extraction.warn("waveform_unavailable")

    if not options["transcribe"]:
        extraction.warn("transcription_disabled")
        return 0
    transcript, transcription_metadata = _transcribe_local(wav, options)
    if transcript is None:
        extraction.warn("transcription_unavailable")
        return 0
    transcript_relative = f"{prefix}/transcript.jsonl"
    atomic_write_jsonl(extraction.path(transcript_relative), transcript)
    extraction.artifact(transcript_relative, "structured_transcript", "application/x-ndjson")
    for segment in transcript:
        extraction.add_evidence(
            "transcript_segment",
            transcript_relative,
            {
                "segment": segment["segment"],
                "start_ms": segment["start_ms"],
                "end_ms": segment["end_ms"],
            },
            segment["text"],
        )
    metadata_relative = f"{prefix}/transcription.json"
    atomic_write_json(extraction.path(metadata_relative), transcription_metadata)
    extraction.artifact(metadata_relative, "transcription_metadata", "application/json")
    extraction.warn("diarization_unavailable")
    return len(transcript)


def _resolve_whisper_model(model: str) -> Path | None:
    configured = os.getenv("MEDIA_EVIDENCE_WHISPER_MODEL_PATH", "").strip()
    if configured:
        return validated_whisper_model_path(configured)
    repository = Path("/data/.cache/huggingface/hub") / f"models--Systran--faster-whisper-{model}"
    snapshots = repository / "snapshots"
    if not snapshots.is_dir():
        return None
    candidates = sorted(path for path in snapshots.iterdir() if path.is_dir())
    return candidates[-1] if candidates else None


def _transcribe_local(
    wav: Path,
    options: dict[str, Any],
) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
    model_path = _resolve_whisper_model(options["whisper_model"])
    if model_path is None:
        return None, {}
    try:
        from faster_whisper import WhisperModel
    except ImportError:
        return None, {}
    try:
        model = WhisperModel(
            str(model_path),
            device="cpu",
            compute_type="int8",
            local_files_only=True,
        )
        kwargs: dict[str, Any] = {
            "beam_size": 5,
            "vad_filter": True,
            "word_timestamps": True,
        }
        if options["language"]:
            kwargs["language"] = options["language"]
        segments, info = model.transcribe(str(wav), **kwargs)
        records: list[dict[str, Any]] = []
        for index, segment in enumerate(segments, start=1):
            text = segment.text.strip()
            if not text:
                continue
            words = []
            for word in segment.words or []:
                if word.start is None or word.end is None:
                    continue
                words.append(
                    {
                        "start_ms": int(word.start * 1000),
                        "end_ms": int(word.end * 1000),
                        "text": word.word,
                        "probability": round(float(word.probability or 0.0), 6),
                    }
                )
            records.append(
                {
                    "segment": index,
                    "start_ms": int(segment.start * 1000),
                    "end_ms": int(segment.end * 1000),
                    "text": text,
                    "words": words,
                }
            )
        return records, {
            "provider": "faster_whisper_local",
            "model": options["whisper_model"],
            "model_provenance": whisper_model_status(options["whisper_model"]),
            "language": str(info.language or "unknown")[:16],
            "language_probability": round(float(info.language_probability or 0.0), 6),
            "vad_filter": True,
            "word_timestamps": True,
        }
    except Exception:
        return None, {}


def _extract_video(source: Path, extraction: Extraction, options: dict[str, Any]) -> None:
    probe = _probe_av(source)
    sanitized_probe = _sanitize_probe(probe)
    _write_probe(extraction, sanitized_probe)
    streams = sanitized_probe["streams"]
    if not any(stream.get("codec_type") == "video" for stream in streams):
        raise MediaEvidenceError("malformed_media", "No video stream was found")
    duration = _duration_seconds(probe)
    if duration > options["max_duration_seconds"]:
        raise MediaEvidenceError("duration_budget_exceeded", "Video exceeds the duration budget")

    ffmpeg = _binary("ffmpeg")
    interval = options["sample_interval_seconds"]
    frame_count = min(options["max_frames"], max(1, math.ceil(duration / interval)))
    timestamps = [min(duration - 0.001, index * interval) for index in range(frame_count)]
    timestamps = [max(0.0, value) for value in timestamps]
    frame_records: list[tuple[str, int, str]] = []
    for index, timestamp in enumerate(timestamps, start=1):
        relative = f"video/frames/sample-{index:04d}.jpg"
        target = extraction.path(relative)
        run_command(
            [
                str(ffmpeg),
                "-v",
                "error",
                "-ss",
                f"{timestamp:.3f}",
                "-i",
                str(source),
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-vf",
                "scale=1280:-2:force_original_aspect_ratio=decrease",
                "-q:v",
                "3",
                "-map_metadata",
                "-1",
                "-y",
                str(target),
            ],
            timeout=120,
            max_output_bytes=2 * 1024 * 1024,
        )
        if not target.is_file():
            raise MediaEvidenceError("parser_failed", "Video frame extraction produced no image")
        timestamp_ms = int(timestamp * 1000)
        extraction.artifact(relative, "sampled_frame", "image/jpeg")
        extraction.add_evidence(
            "video_frame",
            relative,
            {"timestamp_ms": timestamp_ms, "sample_type": "interval"},
        )
        frame_records.append((relative, timestamp_ms, "interval"))

    scene_pattern = extraction.path("video/scenes/scene-%04d.jpg")
    scene_filter = (
        f"select=gt(scene\\,{options['scene_threshold']:.3f}),showinfo,"
        "scale=1280:-2:force_original_aspect_ratio=decrease"
    )
    try:
        scene_result = run_command(
            [
                str(ffmpeg),
                "-v",
                "info",
                "-i",
                str(source),
                "-map",
                "0:v:0",
                "-vf",
                scene_filter,
                "-fps_mode",
                "vfr",
                "-frames:v",
                str(options["max_scene_frames"]),
                "-q:v",
                "3",
                "-map_metadata",
                "-1",
                "-y",
                str(scene_pattern),
            ],
            timeout=min(600, max(120, duration * 2)),
            max_output_bytes=16 * 1024 * 1024,
        )
        scene_times = [int(float(match) * 1000) for match in _SCENE_TIME.findall(scene_result.stderr)]
        scene_files = sorted((extraction.output / "video" / "scenes").glob("scene-*.jpg"))
        for index, target in enumerate(scene_files):
            relative = target.relative_to(extraction.output).as_posix()
            timestamp_ms = scene_times[index] if index < len(scene_times) else 0
            extraction.artifact(relative, "scene_frame", "image/jpeg")
            extraction.add_evidence(
                "video_frame",
                relative,
                {"timestamp_ms": timestamp_ms, "sample_type": "scene"},
            )
            frame_records.append((relative, timestamp_ms, "scene"))
    except MediaEvidenceError:
        for target in scene_pattern.parent.glob("scene-*.jpg"):
            target.unlink(missing_ok=True)
        extraction.warn("scene_detection_unavailable")

    _create_contact_sheet(extraction, [relative for relative, _, _ in frame_records])
    _ocr_video_frames(extraction, frame_records, options)

    transcript_count = 0
    if any(stream.get("codec_type") == "audio" for stream in streams):
        transcript_count = _extract_audio_bundle(
            source,
            extraction,
            options,
            prefix="video",
            duration=duration,
        )
    else:
        extraction.warn("audio_stream_absent")
    extraction.coverage = {
        "duration_ms": int(duration * 1000),
        "sampled_frames": len(timestamps),
        "scene_frames": max(0, len(frame_records) - len(timestamps)),
        "transcript_segments": transcript_count,
    }


def _create_contact_sheet(extraction: Extraction, frame_paths: list[str]) -> None:
    if not frame_paths:
        return
    try:
        from PIL import Image, ImageOps
    except ImportError:
        extraction.warn("contact_sheet_unavailable")
        return
    thumbnails = []
    for relative in frame_paths[:60]:
        with Image.open(extraction.output / relative) as image:
            thumbnail = ImageOps.contain(image.convert("RGB"), (320, 180))
            canvas = Image.new("RGB", (320, 180), "black")
            canvas.paste(thumbnail, ((320 - thumbnail.width) // 2, (180 - thumbnail.height) // 2))
            thumbnails.append(canvas)
    columns = min(5, len(thumbnails))
    rows = math.ceil(len(thumbnails) / columns)
    sheet = Image.new("RGB", (columns * 320, rows * 180), "black")
    for index, image in enumerate(thumbnails):
        sheet.paste(image, ((index % columns) * 320, (index // columns) * 180))
    relative = "video/contact-sheet.jpg"
    sheet.save(extraction.path(relative), format="JPEG", quality=85, optimize=False, progressive=False)
    extraction.artifact(relative, "contact_sheet", "image/jpeg")


def _ocr_video_frames(
    extraction: Extraction,
    frames: list[tuple[str, int, str]],
    options: dict[str, Any],
) -> None:
    if not options["ocr"]:
        extraction.warn("ocr_disabled")
        return
    if _binary("tesseract", required=False) is None:
        extraction.warn("ocr_unavailable")
        return
    records: list[dict[str, Any]] = []
    for relative, timestamp_ms, sample_type in frames:
        lines = _tesseract_lines(extraction.output / relative, extraction, options)
        for line in lines:
            records.append(
                {
                    "timestamp_ms": timestamp_ms,
                    "sample_type": sample_type,
                    **line,
                }
            )
    if not records:
        return
    relative = "video/frame-ocr.jsonl"
    atomic_write_jsonl(extraction.path(relative), records)
    extraction.artifact(relative, "frame_ocr", "application/x-ndjson")
    for record in records:
        extraction.add_evidence(
            "frame_ocr",
            relative,
            {
                "timestamp_ms": record["timestamp_ms"],
                "sample_type": record["sample_type"],
                "region": record["region"],
                "line": record["line"],
            },
            record["text"],
        )
