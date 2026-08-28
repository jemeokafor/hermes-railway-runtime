from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class MediaEvidenceSbomTests(unittest.TestCase):
    def test_generator_emits_deduplicated_cyclonedx_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sbom.json"
            model_provenance = Path(temporary) / "model.json"
            model_provenance.write_text(
                json.dumps(
                    {
                        "repository": "example/model",
                        "revision": "a" * 40,
                        "model_sha256": "b" * 64,
                    }
                ),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "generate_media_sbom.py"),
                    "--output",
                    str(output),
                    "--package-lock",
                    str(REPO_ROOT / "package-lock.json"),
                    "--application-version",
                    "fixture-version",
                    "--model-provenance",
                    str(model_provenance),
                    "--tool",
                    f"uv|0.12.5|{'c' * 64}|pkg:github/astral-sh/uv@0.12.5",
                ],
                cwd=REPO_ROOT,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=True,
                timeout=60,
            )
            sbom = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.5")
            self.assertEqual(sbom["metadata"]["component"]["version"], "fixture-version")
            purls = [component["purl"] for component in sbom["components"]]
            self.assertEqual(purls, sorted(set(purls)))
            self.assertTrue(any(purl.startswith("pkg:pypi/") for purl in purls))
            self.assertTrue(any(purl.startswith("pkg:deb/") for purl in purls))
            self.assertTrue(any(purl.startswith("pkg:npm/") for purl in purls))
            model = next(component for component in sbom["components"] if component["type"] == "machine-learning-model")
            self.assertEqual(model["hashes"][0]["content"], "b" * 64)
            tool = next(component for component in sbom["components"] if component["group"] == "runtime-tool")
            self.assertEqual(tool["hashes"][0]["content"], "c" * 64)


if __name__ == "__main__":
    unittest.main()
