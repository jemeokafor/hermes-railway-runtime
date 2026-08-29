from __future__ import annotations

import ast
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from media_evidence.contracts import MediaEvidenceError


REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_PATH = REPO_ROOT / "media_evidence" / "plugin.py"
BROKER_SOCKET = "/run/test-media-evidence.sock"


class FakeContext:
    def __init__(self) -> None:
        self.tools: dict[str, dict] = {}

    def register_tool(self, **kwargs) -> None:
        self.tools[kwargs["name"]] = kwargs


class FakeBrokerClient:
    instances: list[FakeBrokerClient] = []

    def __init__(self, *, socket_path: str):
        self.socket_path = socket_path
        self.calls: list[tuple[str, dict]] = []
        self.failures: dict[str, Exception] = {}
        self.instances.append(self)

    def _record(self, operation: str, arguments: dict) -> dict:
        self.calls.append((operation, arguments))
        failure = self.failures.get(operation)
        if failure is not None:
            raise failure
        return {"ok": True, "operation": operation}

    def analyze(self, **arguments) -> dict:
        return self._record("analyze", arguments)

    def capabilities(self) -> dict:
        return self._record("capabilities", {})

    def status(self, job_id: str | None) -> dict:
        return self._record("status", {"job_id": job_id})

    def validate_claims(self, *, job_id: str | None, claims: list[dict] | None) -> dict:
        return self._record("validate_claims", {"job_id": job_id, "claims": claims})


def load_plugin(client_type: type = FakeBrokerClient):
    broker_module = ModuleType("media_evidence.broker_client")
    broker_module.BrokerClient = client_type
    spec = importlib.util.spec_from_file_location(
        "media_evidence.plugin_under_test",
        PLUGIN_PATH,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"media_evidence.broker_client": broker_module}):
        spec.loader.exec_module(module)
    return module


class MediaEvidencePluginTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeBrokerClient.instances = []
        self.plugin = load_plugin()
        self.environment = patch.dict(
            os.environ,
            {"MEDIA_EVIDENCE_BROKER_SOCKET": BROKER_SOCKET},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_plugin_registers_bounded_opt_in_tool_surface(self) -> None:
        context = FakeContext()
        self.assertEqual(context.tools, {})

        self.plugin.register(context)

        self.assertEqual(
            set(context.tools),
            {
                "media_evidence_analyze",
                "media_evidence_capabilities",
                "media_evidence_status",
                "media_evidence_validate_claims",
            },
        )
        analyze = context.tools["media_evidence_analyze"]["schema"]
        self.assertEqual(
            set(analyze["parameters"]["required"]),
            {"rights_basis", "privacy", "purpose"},
        )
        self.assertEqual(len(analyze["parameters"]["oneOf"]), 2)
        remote_scan = analyze["parameters"]["allOf"][0]["then"]["properties"]["options"]["properties"]
        self.assertEqual(remote_scan["scan_policy"]["const"], "required")
        self.assertIn("source_path", analyze["parameters"]["properties"])
        self.assertIn("source_url", analyze["parameters"]["properties"])
        self.assertNotIn("output_path", analyze["parameters"]["properties"])
        self.assertIn("opaque provenance and job metadata", analyze["description"])
        self.assertNotIn("artifact paths", analyze["description"].lower())

    def test_all_operations_delegate_to_one_cached_broker_client(self) -> None:
        job_id = "mev_0123456789abcdef01234567"
        claims = [
            {
                "claim": "The source supports this claim.",
                "evidence_ids": ["ev_1"],
                "quotations": [{"evidence_id": "ev_1", "quote": "Exact text"}],
            }
        ]
        analyze_arguments = {
            "source_path": "/data/workspace/source.pdf",
            "rights_basis": "user_provided",
            "privacy": "private",
            "purpose": "Validate a source",
            "options": {"ocr": True},
        }

        responses = [
            json.loads(self.plugin.analyze(analyze_arguments, ignored_context=True)),
            json.loads(self.plugin.capabilities({}, ignored_context=True)),
            json.loads(self.plugin.status({"job_id": job_id}, ignored_context=True)),
            json.loads(
                self.plugin.validate_claims(
                    {"job_id": job_id, "claims": claims},
                    ignored_context=True,
                )
            ),
        ]

        self.assertEqual(
            [response["operation"] for response in responses],
            ["analyze", "capabilities", "status", "validate_claims"],
        )
        self.assertEqual(len(FakeBrokerClient.instances), 1)
        client = FakeBrokerClient.instances[0]
        self.assertEqual(client.socket_path, BROKER_SOCKET)
        self.assertEqual(
            client.calls,
            [
                (
                    "analyze",
                    {
                        "source_path": "/data/workspace/source.pdf",
                        "source_url": None,
                        "allow_network_acquisition": False,
                        "rights_basis": "user_provided",
                        "privacy": "private",
                        "purpose": "Validate a source",
                        "options": {"ocr": True},
                    },
                ),
                ("capabilities", {}),
                ("status", {"job_id": job_id}),
                ("validate_claims", {"job_id": job_id, "claims": claims}),
            ],
        )

    def test_broker_errors_are_bounded_json(self) -> None:
        json.loads(self.plugin.capabilities({}))
        client = FakeBrokerClient.instances[0]
        client.failures["capabilities"] = MediaEvidenceError(
            "broker_unavailable",
            "The media evidence broker is unavailable",
        )
        unavailable = json.loads(self.plugin.capabilities({}))
        self.assertEqual(
            unavailable,
            {
                "ok": False,
                "error": "broker_unavailable",
                "message": "The media evidence broker is unavailable",
            },
        )

        secret = "broker protocol leaked: " + "x" * 10_000
        client.failures["status"] = RuntimeError(secret)
        protocol_error = self.plugin.status({"job_id": "mev_0123456789abcdef01234567"})
        self.assertEqual(
            json.loads(protocol_error),
            {
                "ok": False,
                "error": "internal_error",
                "message": "Media evidence operation failed",
            },
        )
        self.assertLess(len(protocol_error), 200)
        self.assertNotIn(secret, protocol_error)

    def test_missing_socket_configuration_fails_closed(self) -> None:
        with patch.dict(os.environ, {"MEDIA_EVIDENCE_BROKER_SOCKET": ""}):
            response = json.loads(self.plugin.capabilities({}))

        self.assertEqual(
            response,
            {
                "ok": False,
                "error": "broker_unavailable",
                "message": "The media evidence broker is unavailable",
            },
        )
        self.assertEqual(FakeBrokerClient.instances, [])

    def test_plugin_source_has_no_local_pipeline_or_store_fallback(self) -> None:
        source = PLUGIN_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported_modules.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )

        self.assertIn("broker_client", imported_modules)
        self.assertFalse(
            any(
                {"pipeline", "store"}.intersection(module.split("."))
                for module in imported_modules
            )
        )
        for forbidden in (
            "MediaEvidencePipeline",
            "EvidenceStore",
            "MEDIA_EVIDENCE_ROOT",
            "MEDIA_EVIDENCE_INPUT_ROOTS",
            "MEDIA_EVIDENCE_WORKER_USER",
            "MEDIA_EVIDENCE_ACQUISITION_USER",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(source.count("BrokerClient("), 1)


if __name__ == "__main__":
    unittest.main()
