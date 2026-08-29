from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from media_evidence.pipeline import MediaEvidencePipeline


FFMPEG = Path("/usr/bin/ffmpeg")
FFPROBE = Path("/usr/bin/ffprobe")


@unittest.skipUnless(FFMPEG.is_file() and FFPROBE.is_file(), "FFmpeg utilities are unavailable")
class MediaEvidenceRealLaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def pipeline(self) -> MediaEvidencePipeline:
        return MediaEvidencePipeline(
            root=self.base / "store",
            allowed_roots=[self.inputs],
            require_worker_identity=False,
        )

    @staticmethod
    def fixture_command(*arguments: str) -> None:
        subprocess.run(
            [str(FFMPEG), "-nostdin", "-hide_banner", "-loglevel", "error", *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=30,
        )

    def analyze(self, source: Path) -> tuple[dict, dict, Path]:
        result = self.pipeline().analyze(
            source_path=str(source),
            rights_basis="user_provided",
            privacy="private",
            purpose="real media lane certification fixture",
            options={
                "ocr": False,
                "transcribe": False,
                "scan_policy": "best_effort",
                "require_qpdf": False,
                "sample_interval_seconds": 1.0,
                "max_frames": 4,
                "max_scene_frames": 2,
            },
        )
        manifest_path = Path(result["manifest_path"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return result, manifest, manifest_path

    def test_audio_lane_normalizes_and_anchors_waveform(self) -> None:
        source = self.inputs / "tone.wav"
        self.fixture_command(
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=880:sample_rate=16000:duration=1",
            "-c:a",
            "pcm_s16le",
            "-map_metadata",
            "-1",
            "-y",
            str(source),
        )
        result, manifest, _ = self.analyze(source)
        self.assertEqual(result["media_kind"], "audio")
        self.assertEqual(manifest["source"]["media_kind"], "audio")
        kinds = {artifact["kind"] for artifact in manifest["artifacts"]}
        self.assertIn("normalized_audio", kinds)
        self.assertIn("audio_waveform", kinds)
        self.assertIn("audio_waveform", manifest["evidence"]["kinds"])
        self.assertGreater(manifest["quality"]["coverage"]["duration_ms"], 0)

    def test_video_lane_samples_frames_contact_sheet_and_audio(self) -> None:
        source = self.inputs / "two-second-fixture.mp4"
        self.fixture_command(
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=320x240:r=4:d=2",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=16000:duration=2",
            "-c:v",
            "mpeg4",
            "-q:v",
            "5",
            "-c:a",
            "aac",
            "-shortest",
            "-map_metadata",
            "-1",
            "-y",
            str(source),
        )
        result, manifest, _ = self.analyze(source)
        self.assertEqual(result["media_kind"], "video")
        kinds = {artifact["kind"] for artifact in manifest["artifacts"]}
        self.assertIn("sampled_frame", kinds)
        self.assertIn("contact_sheet", kinds)
        self.assertIn("normalized_audio", kinds)
        self.assertIn("video_frame", manifest["evidence"]["kinds"])
        self.assertGreaterEqual(manifest["quality"]["coverage"]["sampled_frames"], 1)


if __name__ == "__main__":
    unittest.main()
