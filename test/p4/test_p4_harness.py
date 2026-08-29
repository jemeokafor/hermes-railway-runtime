from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import wave
from pathlib import Path


P4_ROOT = Path(__file__).resolve().parent
REPO_ROOT = P4_ROOT.parents[1]
MODULE_PATH = P4_ROOT / "p4_image_certification.py"
WRAPPER_PATH = REPO_ROOT / "scripts" / "certify-p4-image.sh"
SPEC = importlib.util.spec_from_file_location("p4_image_certification", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
P4 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P4)


def digest(label: str) -> str:
    return P4.sha256_bytes(label.encode("ascii"))


def valid_preflight() -> dict:
    model = {
        "status": "available",
        "repository": "Systran/faster-whisper-base.en",
        "revision": "d" * 40,
        "model_sha256": "e" * 64,
        "bytes": 1_000_000,
    }
    definitions = {
        "status": "current",
        "file": "daily.cvd",
        "files": 3,
        "bytes": 2_000_000,
        "mtime_ns": 1_000_000_000,
        "sha256": "f" * 64,
    }
    return {
        "orchestrator_uid": 0,
        "worker_identity": {"name": "hermes-media", "uid": 1001, "gid": 1001},
        "acquisition_identity": {"name": "hermes-acquire", "uid": 1002, "gid": 1002},
        "gateway_identity": {"name": "hermes-gateway", "uid": 1003, "gid": 1003},
        "traverse_group": {"name": "hermes-evidence", "gid": 1004},
        "broker_isolation": {
            "uid": 1003,
            "gid": 1003,
            "supplementary_groups": [],
            "store_uid": 0,
            "store_gid": 1004,
            "store_mode": 0o710,
            "store_open_denied": True,
            "store_list_denied": True,
            "key_metadata_denied": True,
            "key_read_denied": True,
            "database_read_denied": True,
            "store_write_denied": True,
            "broker_health": True,
            "broker_capabilities": True,
            "broker_response_opaque": True,
        },
        "sandbox": {
            "seccomp": True,
            "landlock_abi": 3,
            "aggregate_resource_limits": True,
            "aggregate_resource_probe": {
                "cpu_max": "100000 100000",
                "memory_max_bytes": 512 * 1024 * 1024,
                "pids_max": 4,
                "pids_limit_enforced": True,
                "violation": "pids",
                "removed_after_probe": True,
            },
            "identity_probe": {
                "uid": 1001,
                "gid": 1001,
                "seccomp_network_denied": True,
                "landlock_outside_read_denied": True,
                "landlock_allowed_read": True,
                "landlock_allowed_write": True,
            },
        },
        "scanner": {
            "package": "clamav",
            "version": "1.4.3+dfsg-1",
            "sbom_purl": "pkg:deb/debian/clamav@1.4.3%2Bdfsg-1",
            "definitions": definitions,
        },
        "model": model,
        "malware_canary": {
            "sha256": P4.EICAR_SHA256,
            "bytes": 68,
            "observed_error": "malware_detected",
            "published_run": False,
        },
        "harness_mount_read_only": True,
        "image_root_read_only": True,
        "network_interfaces": ["lo"],
    }


def valid_coverage(name: str) -> dict:
    if name == "image":
        return {"width": 1280, "height": 720, "tiles": 0, "ocr_lines": 2}
    if name == "pdf":
        return {"pages_total": 1, "pages_native_text": 0, "pages_rendered": 1, "ocr_lines": 2}
    if name == "mp3":
        return {"duration_ms": 6000, "transcript_segments": 1}
    return {"duration_ms": 6000, "sampled_frames": 6, "scene_frames": 0, "transcript_segments": 1}


def valid_passed_report() -> dict:
    harness_sha256, _ = P4.hash_file(MODULE_PATH)
    report = P4.new_report("sha256:" + "a" * 64, "candidate:test", "b" * 40, harness_sha256)
    report["candidate"] = {
        **report["candidate"],
        "hermes_commit": "d" * 40,
        "sbom": {
            "path": "/opt/hermes-runtime.cdx.json",
            "declared_sha256_path": "/opt/hermes-runtime.cdx.sha256",
            "sha256": "e" * 64,
            "bytes": 123_456,
            "format": "CycloneDX",
            "spec_version": "1.5",
        },
    }
    report["preflight"] = valid_preflight()
    report["corpus"]["inputs"] = [
        {
            "lane": spec["name"],
            "path": f"corpus/{spec['filename']}",
            "sha256": digest(f"corpus:{spec['name']}"),
            "bytes": 10_000 + index,
            "expected_mime": spec["expected_mime"],
            "payload_contract": spec["source_payload_contract"],
        }
        for index, spec in enumerate(P4.LANE_SPECS, start=1)
    ]

    scanner = report["preflight"]["scanner"]["definitions"]
    scanner_subset = {key: scanner[key] for key in ("status", "file", "bytes", "mtime_ns", "sha256")}
    for index, (spec, corpus_input) in enumerate(zip(P4.LANE_SPECS, report["corpus"]["inputs"]), start=1):
        artifacts = []
        for artifact_index, (kind, media_type) in enumerate(spec["artifact_kinds"].items(), start=1):
            artifact_digest = digest(f"{spec['name']}:{kind}:{artifact_index}")
            artifacts.append(
                {
                    "id": f"artifact:sha256:{artifact_digest}",
                    "kind": kind,
                    "path": f"artifacts/{artifact_index:02d}-{kind}",
                    "media_type": media_type,
                    "sha256": artifact_digest,
                    "bytes": 100 + artifact_index,
                    "payload_contract": P4.payload_contract_for_media_type(media_type),
                }
            )
        artifacts.sort(key=lambda item: item["path"])
        evidence_index = next(item for item in artifacts if item["kind"] == "evidence_index")
        text_checks = {}
        if spec["required_ocr_words"]:
            words = sorted(spec["required_ocr_words"])
            text_checks["ocr"] = {"expected_words": words, "matched_words": words}
        if spec["required_transcript_words"]:
            words = sorted(spec["required_transcript_words"])
            text_checks["transcript"] = {"expected_words": words, "matched_words": words}
        lane = {
            "name": spec["name"],
            "status": "passed",
            "source": {
                "path": corpus_input["path"],
                "sha256": corpus_input["sha256"],
                "bytes": corpus_input["bytes"],
                "actual_mime": spec["expected_mime"],
                "media_kind": spec["media_kind"],
                "payload_contract": spec["source_payload_contract"],
            },
            "job_id": f"mev_{digest(spec['name'])[:24]}",
            "manifest": {
                "sha256": digest(f"manifest:{spec['name']}"),
                "bytes": 1000 + index,
                "payload_sha256": digest(f"payload:{spec['name']}"),
                "signature_algorithm": "hmac-sha256",
                "signature_key_id": digest(f"key:{spec['name']}")[:16],
                "signature": digest(f"signature:{spec['name']}"),
            },
            "artifacts": artifacts,
            "evidence": {
                "count": len(spec["evidence_kinds"]),
                "kinds": sorted(spec["evidence_kinds"]),
                "index_artifact_id": evidence_index["id"],
                "text_checks": text_checks,
            },
            "quality": {
                "tier": spec["expected_quality_tier"],
                "warnings": sorted(spec["warnings"]),
                "disagreements": [],
                "coverage": valid_coverage(spec["name"]),
            },
            "scanner_revision": scanner_subset,
            "model_provenance": copy.deepcopy(report["preflight"]["model"]),
            "sandbox": "seccomp+landlock+uid+cgroupv2",
            "runtime_provenance": {
                "image_id": report["candidate"]["image_id"],
                "source_commit": report["candidate"]["source_commit"],
                "sbom_sha256": report["candidate"]["sbom"]["sha256"],
                "deployment_id": "unknown",
            },
        }
        if "probe_contract" in spec:
            duration_ms = int(spec["probe_contract"]["duration_seconds"] * 1000)
            lane["media_contract"] = {
                "source": {
                    "format_names": sorted(spec["probe_contract"]["format_names"]),
                    "duration_ms": duration_ms,
                    "streams": [dict(stream) for stream in spec["probe_contract"]["streams"]],
                },
                "normalized_audio": {
                    "format_names": ["wav"],
                    "duration_ms": duration_ms,
                    "streams": [
                        {
                            "codec_type": "audio",
                            "codec_name": "pcm_s16le",
                            "sample_rate": "16000",
                            "channels": 1,
                        }
                    ],
                },
            }
        report["lanes"].append(lane)
    report["status"] = "passed"
    return P4.finalize_report(report)


def valid_failed_report() -> dict:
    harness_sha256, _ = P4.hash_file(MODULE_PATH)
    report = P4.new_report("sha256:" + "a" * 64, "candidate:test", "b" * 40, harness_sha256)
    error = {"stage": "preflight", "type": "CertificationFailure", "message": "bounded failure"}
    report["errors"] = [error]
    report["lanes"] = [
        {"name": spec["name"], "status": "failed", "error": {"stage": "preflight", "message": error["message"]}}
        for spec in P4.LANE_SPECS
    ]
    return P4.finalize_report(report)


class P4HarnessSourceTests(unittest.TestCase):
    def test_policy_is_exactly_four_strict_real_media_lanes(self) -> None:
        self.assertEqual([item["name"] for item in P4.LANE_SPECS], ["image", "pdf", "mp3", "mp4"])
        self.assertEqual(
            {item["expected_mime"] for item in P4.LANE_SPECS},
            {"image/png", "application/pdf", "audio/mpeg", "video/mp4"},
        )
        self.assertEqual(
            {key: P4.P4_OPTIONS[key] for key in ("scan_policy", "ocr", "transcribe", "require_qpdf")},
            {"scan_policy": "required", "ocr": True, "transcribe": True, "require_qpdf": True},
        )
        self.assertTrue(all(item["artifact_kinds"] and item["evidence_kinds"] for item in P4.LANE_SPECS))
        self.assertEqual([item["expected_quality_tier"] for item in P4.LANE_SPECS], ["complete", "complete", "partial", "partial"])
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("@unittest.skip", source)
        self.assertNotIn(".skipTest(", source)
        self.assertNotIn('"status": "skipped"', source)

    def test_fixture_phrases_are_lane_specific_and_meaningful(self) -> None:
        ocr_sets = [item["required_ocr_words"] for item in P4.LANE_SPECS if item["required_ocr_words"]]
        transcript_sets = [item["required_transcript_words"] for item in P4.LANE_SPECS if item["required_transcript_words"]]
        for collection in (ocr_sets, transcript_sets):
            for index, words in enumerate(collection):
                self.assertGreaterEqual(len(words), 2)
                self.assertTrue(all(len(word) >= 4 for word in words))
                self.assertTrue(all(words.isdisjoint(other) for other in collection[index + 1 :]))
        self.assertNotEqual(P4.CORPUS_DEFINITION["speech"]["mp3_text"], P4.CORPUS_DEFINITION["speech"]["mp4_text"])
        self.assertTrue(P4.LANE_SPECS[2]["required_transcript_words"].issubset(P4.normalized_words(P4.CORPUS_DEFINITION["speech"]["mp3_text"])))
        self.assertTrue(P4.LANE_SPECS[3]["required_transcript_words"].issubset(P4.normalized_words(P4.CORPUS_DEFINITION["speech"]["mp4_text"])))

    def test_malware_canary_is_canonical_and_not_contiguous_in_source(self) -> None:
        payload = P4.eicar_canary_bytes()
        self.assertEqual(len(payload), 68)
        self.assertEqual(P4.sha256_bytes(payload), P4.EICAR_SHA256)
        signature = payload.decode("ascii")
        self.assertNotIn(signature, MODULE_PATH.read_text(encoding="utf-8"))
        self.assertNotIn(signature, Path(__file__).read_text(encoding="utf-8"))

    def test_corpus_definition_and_failed_report_are_canonical_and_bound(self) -> None:
        definition_hash = P4.corpus_definition_sha256()
        self.assertRegex(definition_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(definition_hash, P4.sha256_bytes(P4.canonical_json_bytes(P4.CORPUS_DEFINITION)))
        finalized = valid_failed_report()
        self.assertTrue(P4.verify_report_binding(finalized))
        P4.validate_report_shape(finalized)
        encoded = P4.canonical_json_bytes(finalized)
        self.assertEqual(encoded, json.dumps(finalized, sort_keys=True, separators=(",", ":")).encode("ascii"))
        finalized["candidate"]["source_commit"] = "d" * 40
        self.assertFalse(P4.verify_report_binding(finalized))

    def test_complete_passed_report_shape_and_bounded_false_pass_mutations(self) -> None:
        report = valid_passed_report()
        P4.validate_report_shape(report)

        def remove_sbom_size(candidate: dict) -> None:
            candidate["candidate"]["sbom"].pop("bytes")

        def stale_scanner(candidate: dict) -> None:
            candidate["preflight"]["scanner"]["definitions"]["status"] = "stale"

        def published_canary(candidate: dict) -> None:
            candidate["preflight"]["malware_canary"]["published_run"] = True

        def gateway_can_read_key(candidate: dict) -> None:
            candidate["preflight"]["broker_isolation"]["key_read_denied"] = False

        def broker_leaks_paths(candidate: dict) -> None:
            candidate["preflight"]["broker_isolation"]["broker_response_opaque"] = False

        def pids_limit_not_enforced(candidate: dict) -> None:
            candidate["preflight"]["sandbox"]["aggregate_resource_probe"]["pids_limit_enforced"] = False

        def invalid_corpus_hash(candidate: dict) -> None:
            candidate["corpus"]["inputs"][0]["sha256"] = "bad"

        def empty_lane_source(candidate: dict) -> None:
            candidate["lanes"][0]["source"]["bytes"] = 0

        def missing_manifest_signature(candidate: dict) -> None:
            candidate["lanes"][0]["manifest"]["signature"] = ""

        def unvalidated_artifact(candidate: dict) -> None:
            candidate["lanes"][0]["artifacts"][0]["payload_contract"] = "unchecked"

        def missing_expected_word(candidate: dict) -> None:
            candidate["lanes"][0]["evidence"]["text_checks"]["ocr"]["matched_words"] = []

        def quality_disagreement(candidate: dict) -> None:
            candidate["lanes"][1]["quality"]["disagreements"] = [{"kind": "mismatch"}]

        def changed_model(candidate: dict) -> None:
            candidate["lanes"][2]["model_provenance"]["bytes"] += 1

        def changed_duration(candidate: dict) -> None:
            candidate["lanes"][3]["media_contract"]["source"]["duration_ms"] = 7000

        mutations = (
            remove_sbom_size,
            stale_scanner,
            published_canary,
            gateway_can_read_key,
            broker_leaks_paths,
            pids_limit_not_enforced,
            invalid_corpus_hash,
            empty_lane_source,
            missing_manifest_signature,
            unvalidated_artifact,
            missing_expected_word,
            quality_disagreement,
            changed_model,
            changed_duration,
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                candidate = copy.deepcopy(report)
                mutate(candidate)
                rebound = P4.finalize_report(candidate)
                with self.assertRaises(P4.CertificationFailure):
                    P4.validate_report_shape(rebound)

    def test_artifact_byte_and_structured_payload_checks_are_host_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            png = root / "artifact.png"
            png.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                b"\x00\x00\x00\rIHDR"
                b"\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x00\x00\x00\x00IEND\xaeB`\x82"
            )
            jpeg = root / "artifact.jpg"
            jpeg.write_bytes(b"\xff\xd8\xffpayload\xff\xd9")
            wav = root / "artifact.wav"
            with wave.open(str(wav), "wb") as audio:
                audio.setnchannels(1)
                audio.setsampwidth(2)
                audio.setframerate(16000)
                audio.writeframes(b"\x00\x00" * 160)
            json_path = root / "artifact.json"
            json_path.write_text('{"ok":true}\n', encoding="utf-8")
            ndjson = root / "artifact.jsonl"
            ndjson.write_text('{"record":1}\n{"record":2}\n', encoding="utf-8")

            checks = (
                (png, "image/png", "png"),
                (jpeg, "image/jpeg", "jpeg"),
                (wav, "audio/wav", "wav-pcm-s16le-16000-mono"),
                (json_path, "application/json", "json-object"),
                (ndjson, "application/x-ndjson", "ndjson-objects"),
            )
            for path, media_type, expected in checks:
                with self.subTest(media_type=media_type):
                    self.assertEqual(P4.validate_artifact_payload(path, media_type, "test artifact"), expected)

            ndjson.write_text('{"record":1}\nnot-json\n', encoding="utf-8")
            with self.assertRaises(P4.CertificationFailure):
                P4.validate_artifact_payload(ndjson, "application/x-ndjson", "test artifact")
            json_path.write_text('{"value":NaN}\n', encoding="utf-8")
            with self.assertRaises(P4.CertificationFailure):
                P4.validate_artifact_payload(json_path, "application/json", "test artifact")

    def test_final_reports_are_validated_before_write_and_after_downgrade(self) -> None:
        passed = valid_passed_report()
        self.assertEqual(P4.validated_final_report(passed)["status"], "passed")

        malformed_pass = copy.deepcopy(passed)
        malformed_pass["lanes"][0]["artifacts"][0].pop("payload_contract")
        downgraded = P4.validated_final_report(malformed_pass)
        self.assertEqual(downgraded["status"], "failed")
        self.assertTrue(all(lane["status"] == "failed" for lane in downgraded["lanes"]))
        P4.validate_report_shape(downgraded)

        malformed_failure = valid_failed_report()
        malformed_failure["candidate"]["source_commit"] = "unknown"
        malformed_failure = P4.finalize_report(malformed_failure)
        with self.assertRaisesRegex(P4.CertificationFailure, "malformed failed"):
            P4.validated_final_report(malformed_failure)

        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            malformed = copy.deepcopy(valid_failed_report())
            malformed["binding"]["payload_sha256"] = "0" * 64
            with self.assertRaises(P4.CertificationFailure):
                P4.write_report(report_path, malformed)
            self.assertFalse(report_path.exists())

            P4.write_report(report_path, passed)
            self.assertEqual(P4.validate_report_file(report_path)["status"], "passed")
            cli = subprocess.run(
                [sys.executable, "-I", str(MODULE_PATH), "--validate-report", str(report_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual((cli.returncode, cli.stdout.strip()), (0, "passed"), cli.stderr)
            report_path.write_bytes(report_path.read_bytes() + b" ")
            with self.assertRaisesRegex(P4.CertificationFailure, "canonical"):
                P4.validate_report_file(report_path)

    def test_wrapper_deletes_stale_report_before_docker_cli_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            for command in ("basename", "dirname", "mkdir", "rm"):
                target = shutil.which(command)
                self.assertIsNotNone(target)
                os.symlink(target, binary_dir / command)
            report = root / "stale.json"
            report.write_text('{"status":"passed"}\n', encoding="utf-8")
            result = subprocess.run(
                ["/bin/bash", str(WRAPPER_PATH), "candidate:test"],
                cwd=root,
                env={"PATH": str(binary_dir), "P4_REPORT_PATH": str(report)},
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 69, result.stderr)
            self.assertFalse(report.exists())

    def test_wrapper_deletes_stale_report_before_daemon_and_image_preflight(self) -> None:
        scenarios = {
            "daemon": "#!/bin/sh\nexit 1\n",
            "image": "#!/bin/sh\n[ \"$1\" = info ] && exit 0\nexit 1\n",
        }
        for name, docker_script in scenarios.items():
            with self.subTest(scenario=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary_dir = root / "bin"
                binary_dir.mkdir()
                docker = binary_dir / "docker"
                docker.write_text(docker_script, encoding="utf-8")
                docker.chmod(0o755)
                report = root / "stale.json"
                report.write_text('{"status":"passed"}\n', encoding="utf-8")
                result = subprocess.run(
                    ["/bin/bash", str(WRAPPER_PATH), "candidate:test"],
                    cwd=root,
                    env={"PATH": f"{binary_dir}:/usr/bin:/bin", "P4_REPORT_PATH": str(report)},
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 69 if name == "daemon" else 66, result.stderr)
                self.assertFalse(report.exists())

    def test_wrapper_runs_the_inspected_image_without_network_or_deployment(self) -> None:
        wrapper = WRAPPER_PATH.read_text(encoding="utf-8")
        self.assertIn("--network none", wrapper)
        self.assertIn("--cgroupns private", wrapper)
        self.assertIn("--read-only", wrapper)
        self.assertIn("dst=/p4,readonly", wrapper)
        self.assertIn("--entrypoint /opt/hermes-venv/bin/python", wrapper)
        self.assertRegex(wrapper, r'"\$\{image_id\}"\s+\\?\n?\s*-I')
        self.assertIn("--validate-report", wrapper)
        self.assertLess(wrapper.index("rm -f --"), wrapper.index("command -v docker"))
        self.assertNotRegex(wrapper, r"docker\s+(?:image\s+)?push|docker\s+compose|kubectl|helm\s|railway\s+up|ssh\s")
        self.assertNotIn("/var/run/docker.sock", wrapper)

    def test_build_and_ci_embed_identity_without_baking_test_material(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        workflow = (REPO_ROOT / ".github" / "workflows" / "docker-build.yml").read_text(encoding="utf-8")
        package = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertIn("org.opencontainers.image.revision", dockerfile)
        self.assertIn("/opt/hermes-source.commit", dockerfile)
        self.assertIn("espeak-ng", dockerfile)
        self.assertIn("fonts-dejavu-core", dockerfile)
        self.assertNotRegex(dockerfile, r"COPY\s+test(?:/|\s)")
        self.assertNotIn("COPY scripts ./scripts", dockerfile)
        self.assertNotIn("certify-p4-image.sh", dockerfile)
        self.assertIn("scripts/start-hermes-stack.sh", dockerfile)
        self.assertEqual(package["scripts"]["certify:p4"], "bash scripts/certify-p4-image.sh")
        self.assertIn("test/p4", package["scripts"]["test:media"])
        self.assertRegex(workflow, r"load:\s*true")
        self.assertIn("RAILWAY_GIT_COMMIT_SHA=${{ github.sha }}", workflow)
        self.assertIn("P4 harness self-checks", workflow)
        self.assertIn("npm run certify:p4", workflow)
        self.assertIn("actions/upload-artifact", workflow)
        self.assertRegex(workflow, r"if:\s*always\(\)")


if __name__ == "__main__":
    unittest.main()
