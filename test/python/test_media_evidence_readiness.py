from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from media_evidence.contracts import MediaEvidenceError


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "media-evidence-readiness.py"
SPEC = importlib.util.spec_from_file_location("media_evidence_readiness", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load media-evidence-readiness.py")
readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)


def healthy_capabilities() -> dict:
    return {
        "ok": True,
        "schema": "media-evidence/v1",
        "tool_version": "1.0.0",
        "sandbox": {
            "seccomp": True,
            "landlock_abi": 3,
            "dedicated_identity": True,
            "dedicated_acquisition_identity": True,
            "aggregate_resource_limits": True,
        },
        "malware_scanner": {"status": "current"},
        "transcription_model": {"status": "available"},
        "binaries": {name: f"/usr/bin/{name}" for name in readiness.REQUIRED_BINARIES},
    }


class FakeBrokerClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.canary_path: Path | None = None

    def capabilities(self) -> dict:
        return healthy_capabilities()

    def analyze(self, **request) -> dict:
        self.calls.append(request)
        if request.get("source_url"):
            raise MediaEvidenceError("remote_address_rejected", "private address")
        self.canary_path = Path(request["source_path"])
        if not self.canary_path.is_file():
            raise AssertionError("readiness canary must exist during the broker request")
        return {"ok": True, "job_id": "mev_0123456789abcdef01234567"}


class MediaEvidenceReadinessTests(unittest.TestCase):
    def test_readiness_uses_broker_for_network_and_media_canaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = FakeBrokerClient()
            record = readiness.check_readiness(
                client,
                input_roots=[Path(temporary)],
                deployment_id="deployment",
                checked_at=43_200,
            )

            self.assertTrue(record["ok"])
            self.assertEqual(record["canary_job_id"], "mev_0123456789abcdef01234567")
            self.assertEqual(len(client.calls), 2)
            self.assertIn("source_url", client.calls[0])
            self.assertIn("source_path", client.calls[1])
            self.assertIsNotNone(client.canary_path)
            self.assertFalse(client.canary_path.exists())

    def test_capability_failure_stops_before_canaries(self) -> None:
        class BrokenCapabilities(FakeBrokerClient):
            def capabilities(self) -> dict:
                capabilities = healthy_capabilities()
                capabilities["sandbox"]["seccomp"] = False
                return capabilities

        with tempfile.TemporaryDirectory() as temporary:
            client = BrokenCapabilities()
            record = readiness.check_readiness(
                client,
                input_roots=[Path(temporary)],
                deployment_id="deployment",
                checked_at=1,
            )
            self.assertFalse(record["ok"])
            self.assertEqual(record["failures"], ["seccomp_unavailable"])
            self.assertEqual(client.calls, [])

    def test_missing_aggregate_limits_stops_before_canaries(self) -> None:
        class MissingAggregateLimits(FakeBrokerClient):
            def capabilities(self) -> dict:
                capabilities = healthy_capabilities()
                capabilities["sandbox"]["aggregate_resource_limits"] = False
                return capabilities

        with tempfile.TemporaryDirectory() as temporary:
            client = MissingAggregateLimits()
            record = readiness.check_readiness(
                client,
                input_roots=[Path(temporary)],
                deployment_id="deployment",
                checked_at=1,
            )
            self.assertFalse(record["ok"])
            self.assertEqual(record["failures"], ["aggregate_resource_limits_unavailable"])
            self.assertEqual(client.calls, [])

    def test_private_network_acceptance_fails_closed(self) -> None:
        class UnsafeAcquisition(FakeBrokerClient):
            def analyze(self, **request) -> dict:
                self.calls.append(request)
                if request.get("source_url"):
                    return {"ok": True, "job_id": "unexpected"}
                return super().analyze(**request)

        with tempfile.TemporaryDirectory() as temporary:
            client = UnsafeAcquisition()
            record = readiness.check_readiness(
                client,
                input_roots=[Path(temporary)],
                deployment_id="deployment",
                checked_at=1,
            )
            self.assertFalse(record["ok"])
            self.assertEqual(record["failures"], ["acquisition_private_dns_accepted"])
            self.assertEqual(len(client.calls), 1)

    def test_broker_errors_are_bounded(self) -> None:
        class MissingBroker(FakeBrokerClient):
            def capabilities(self) -> dict:
                raise OSError("secret-bearing transport detail")

        record = readiness.check_readiness(
            MissingBroker(),
            input_roots=[],
            deployment_id="deployment",
            checked_at=1,
        )
        self.assertEqual(record["failures"], ["broker_unavailable"])
        self.assertNotIn("secret", str(record))


if __name__ == "__main__":
    unittest.main()
