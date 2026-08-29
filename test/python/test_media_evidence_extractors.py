from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from media_evidence.contracts import MediaEvidenceError
from media_evidence.extractors import (
    Extraction,
    _extract_video,
    _scan_source,
    clamav_definition_status,
    whisper_model_status,
)


class MediaEvidenceExtractorTests(unittest.TestCase):
    def test_clamav_command_applies_traversal_size_and_timeout_protections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "discussion.txt"
            source.write_text(
                "This document discusses the EICAR-STANDARD-ANTIVIRUS-TEST-FILE marker.",
                encoding="utf-8",
            )
            extraction = Extraction(root / "output")
            definitions = {
                "status": "current",
                "file": "daily.cld",
                "bytes": 1,
                "mtime_ns": 1,
                "sha256": "0" * 64,
            }
            clean = subprocess.CompletedProcess([], 0, "", "")
            max_source_bytes = 123_456_789
            with (
                patch("media_evidence.extractors._binary", return_value=Path("/usr/bin/clamscan")),
                patch("media_evidence.extractors.clamav_definition_status", return_value=definitions),
                patch("media_evidence.extractors.run_command", return_value=clean) as scanner,
            ):
                _scan_source(
                    source,
                    {"scan_policy": "required", "max_source_bytes": max_source_bytes},
                    extraction,
                )

            scanner.assert_called_once_with(
                [
                    "/usr/bin/clamscan",
                    "--no-summary",
                    "--infected",
                    "--stdout",
                    "--cross-fs=no",
                    f"--max-filesize={max_source_bytes}",
                    f"--max-scansize={max_source_bytes}",
                    "--alert-exceeds-max=yes",
                    str(source),
                ],
                timeout=180,
                max_output_bytes=1024 * 1024,
                accepted_returncodes={0, 1, 2},
            )

    def test_required_clamav_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.txt"
            source.write_text("benign", encoding="utf-8")
            extraction = Extraction(root / "output")
            definitions = {
                "status": "current",
                "file": "daily.cld",
                "bytes": 1,
                "mtime_ns": 1,
                "sha256": "0" * 64,
            }
            failed = subprocess.CompletedProcess([], 2, "", "scanner failed")
            with (
                patch("media_evidence.extractors._binary", return_value=Path("/usr/bin/clamscan")),
                patch("media_evidence.extractors.clamav_definition_status", return_value=definitions),
                patch("media_evidence.extractors.run_command", return_value=failed),
                self.assertRaises(MediaEvidenceError) as raised,
            ):
                _scan_source(
                    source,
                    {"scan_policy": "required", "max_source_bytes": 1024},
                    extraction,
                )

            self.assertEqual(raised.exception.code, "scanner_failed")

    def test_required_clamav_wall_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.txt"
            source.write_text("benign", encoding="utf-8")
            extraction = Extraction(root / "output")
            definitions = {
                "status": "current",
                "file": "daily.cld",
                "bytes": 1,
                "mtime_ns": 1,
                "sha256": "0" * 64,
            }
            timeout = MediaEvidenceError("parser_timeout", "wall timeout")
            with (
                patch("media_evidence.extractors._binary", return_value=Path("/usr/bin/clamscan")),
                patch("media_evidence.extractors.clamav_definition_status", return_value=definitions),
                patch("media_evidence.extractors.run_command", side_effect=timeout),
                self.assertRaises(MediaEvidenceError) as raised,
            ):
                _scan_source(
                    source,
                    {"scan_policy": "required", "max_source_bytes": 1024},
                    extraction,
                )

            self.assertIs(raised.exception, timeout)

    def test_failed_scene_extraction_removes_partial_frames_before_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.mp4"
            source.write_bytes(b"video fixture")
            output = root / "output"
            extraction = Extraction(output)
            probe = {
                "streams": [{"codec_type": "video", "duration": "1.0"}],
                "format": {"duration": "1.0"},
            }
            options = {
                "max_duration_seconds": 60,
                "sample_interval_seconds": 30,
                "max_frames": 1,
                "scene_threshold": 0.35,
                "max_scene_frames": 12,
            }

            def run_ffmpeg(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                target = str(argv[-1])
                if "%04d" in target:
                    for index in (1, 2):
                        Path(target.replace("%04d", f"{index:04d}")).write_bytes(b"partial frame")
                    raise MediaEvidenceError("parser_failed", "scene extraction failed")
                Path(target).write_bytes(b"sample frame")
                return subprocess.CompletedProcess(argv, 0, "", "")

            def warn_after_cleanup(code: str) -> None:
                if code == "scene_detection_unavailable":
                    self.assertEqual(list((output / "video" / "scenes").glob("scene-*.jpg")), [])
                Extraction.warn(extraction, code)

            with (
                patch("media_evidence.extractors._probe_av", return_value=probe),
                patch("media_evidence.extractors._binary", return_value=Path("/usr/bin/ffmpeg")),
                patch("media_evidence.extractors.run_command", side_effect=run_ffmpeg),
                patch("media_evidence.extractors._create_contact_sheet"),
                patch("media_evidence.extractors._ocr_video_frames"),
                patch.object(extraction, "warn", side_effect=warn_after_cleanup),
            ):
                _extract_video(source, extraction, options)

            self.assertIn("scene_detection_unavailable", extraction.warnings)
            self.assertFalse(any(artifact["kind"] == "scene_frame" for artifact in extraction.artifacts))
            self.assertEqual(list((output / "video" / "scenes").glob("scene-*.jpg")), [])

    def test_clamav_definition_freshness_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary)
            self.assertEqual(clamav_definition_status(database, now=2_000_000)["status"], "missing")
            daily = database / "daily.cld"
            daily.write_bytes(b"fixture signatures")
            os.utime(daily, (1_999_000, 1_999_000))
            current = clamav_definition_status(database, now=2_000_000)
            self.assertEqual(current["status"], "current")
            self.assertEqual(current["files"], 1)
            self.assertRegex(current["sha256"], r"^[0-9a-f]{64}$")
            main = database / "main.cvd"
            main.write_bytes(b"main signatures")
            os.utime(main, (1_999_000, 1_999_000))
            expanded = clamav_definition_status(database, now=2_000_000)
            self.assertEqual(expanded["files"], 2)
            self.assertNotEqual(expanded["sha256"], current["sha256"])
            main.write_bytes(b"changed main signatures")
            self.assertNotEqual(clamav_definition_status(database, now=2_000_000)["sha256"], expanded["sha256"])
            os.utime(daily, (1, 1))
            self.assertEqual(clamav_definition_status(database, now=2_000_000)["status"], "stale")
            os.utime(daily, (2_100_000, 2_100_000))
            self.assertEqual(clamav_definition_status(database, now=2_000_000)["status"], "future_dated")

    def test_clamav_provenance_hashes_all_supported_loose_database_formats(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary)
            daily = database / "daily.cld"
            daily.write_bytes(b"daily")
            os.utime(daily, (1_999_000, 1_999_000))
            added_suffixes = (
                ".cat",
                ".cdb",
                ".db",
                ".ftm",
                ".gdb",
                ".ldu",
                ".mdu",
                ".msu",
                ".ndu",
                ".pwdb",
                ".sdb",
                ".sign",
                ".yar",
                ".yara",
            )
            yara = database / "audit.yar"
            for index, suffix in enumerate(added_suffixes):
                path = yara if suffix == ".yar" else database / f"audit-{index}{suffix}"
                path.write_bytes(f"definition-{index}".encode())

            before = clamav_definition_status(database, now=2_000_000)
            self.assertEqual(before["status"], "current")
            self.assertEqual(before["files"], len(added_suffixes) + 1)

            yara.write_bytes(b"changed yara definition")
            after = clamav_definition_status(database, now=2_000_000)
            self.assertEqual(after["status"], "current")
            self.assertNotEqual(after["sha256"], before["sha256"])

    def test_clamav_definition_set_rejects_unsafe_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary)
            daily = database / "daily.cld"
            daily.write_bytes(b"daily")
            (database / "main.cvd.sign").symlink_to(daily)
            self.assertEqual(clamav_definition_status(database)["status"], "invalid")

    def test_whisper_readiness_hashes_the_pinned_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            model = Path(temporary)
            model_bytes = b"pinned model fixture"
            (model / "model.bin").write_bytes(model_bytes)
            provenance = {
                "repository": "Systran/faster-whisper-base.en",
                "revision": "3" * 40,
                "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
            }
            (model / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
            with patch("media_evidence.extractors._resolve_whisper_model", return_value=model):
                self.assertEqual(whisper_model_status("base.en")["status"], "available")
                (model / "model.bin").write_bytes(b"corrupt")
                self.assertEqual(whisper_model_status("base.en")["status"], "corrupt")


if __name__ == "__main__":
    unittest.main()
