from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from media_evidence.contracts import (
    MediaEvidenceError,
    sign_manifest,
    validate_manifest_schema,
    verify_manifest,
)


def valid_manifest() -> dict:
    digest = "0" * 64
    artifact_id = f"artifact:sha256:{digest}"
    return {
        "schema": "media-evidence/v1",
        "job": {
            "id": f"mev_{'0' * 24}",
            "idempotency_key": digest,
            "state": "completed",
            "trace_id": "0" * 32,
            "created_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
        },
        "source": {
            "sha256": digest,
            "bytes": 1,
            "actual_mime": "image/png",
            "media_kind": "image",
            "name_sha256": digest,
            "declared_suffix": ".png",
            "rights_basis": "user_provided",
            "privacy": "private",
        },
        "acquisition": {
            "adapter": "local",
            "retrieved_at": "2026-01-01T00:00:00Z",
            "redirects": 0,
            "network_used": False,
            "source_uri_sha256": digest,
            "final_uri_sha256": None,
        },
        "execution": {
            "tool": "media_evidence_analyze",
            "tool_version": "1.0.0",
            "runtime": {},
            "network": "denied",
            "sandbox": "seccomp+landlock",
            "resource_class": "cpu",
            "parameters": {},
            "limits": {},
            "dependencies": {},
            "scanner_revision": {
                "status": "unavailable",
                "file": None,
                "bytes": None,
                "mtime_ns": None,
                "sha256": None,
            },
            "queue_wait_ms": 0,
            "duration_ms": 1,
        },
        "artifacts": [],
        "evidence": {"count": 1, "index_artifact_id": artifact_id, "kinds": []},
        "quality": {
            "tier": "complete",
            "warnings": [],
            "disagreements": [],
            "coverage": {},
        },
        "policy": {
            "content_trust": "untrusted",
            "instruction_handling": "never_execute",
            "cloud_egress": "denied",
            "purpose_sha256": digest,
        },
        "integrity": {
            "algorithm": "hmac-sha256",
            "key_id": "0" * 16,
            "payload_sha256": digest,
            "signature": digest,
        },
    }


class ManifestContractTests(unittest.TestCase):
    def test_manifest_schema_honors_any_of(self) -> None:
        manifest = valid_manifest()
        validate_manifest_schema(manifest)
        manifest["execution"]["scanner_revision"]["sha256"] = "a" * 64
        validate_manifest_schema(manifest)

        for invalid in (7, "not-a-digest", []):
            with self.subTest(invalid=invalid):
                candidate = copy.deepcopy(manifest)
                candidate["execution"]["scanner_revision"]["sha256"] = invalid
                with self.assertRaises(MediaEvidenceError):
                    validate_manifest_schema(candidate)

    def test_verify_manifest_returns_false_for_malformed_integrity_types(self) -> None:
        key = b"k" * 32
        signed = sign_manifest({"schema": "fixture"}, key)
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "manifest.key"
            key_path.write_bytes(key)
            key_path.chmod(0o600)
            self.assertTrue(verify_manifest(signed, key_path))

            for malformed in (None, [], "invalid", 1):
                with self.subTest(malformed=malformed):
                    candidate = copy.deepcopy(signed)
                    candidate["integrity"] = malformed
                    self.assertFalse(verify_manifest(candidate, key_path))

            for field in ("algorithm", "key_id", "payload_sha256", "signature"):
                with self.subTest(field=field):
                    candidate = copy.deepcopy(signed)
                    candidate["integrity"][field] = []
                    self.assertFalse(verify_manifest(candidate, key_path))

    def test_verify_manifest_rejects_group_readable_key(self) -> None:
        key = b"k" * 32
        signed = sign_manifest({"schema": "fixture"}, key)
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "manifest.key"
            key_path.write_bytes(key)
            key_path.chmod(0o640)
            self.assertFalse(verify_manifest(signed, key_path))


if __name__ == "__main__":
    unittest.main()
