from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from media_evidence.contracts import MediaEvidenceError
from media_evidence.worker_client import WorkerClient


class MediaEvidenceWorkerClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.client = WorkerClient(worker_uid=None, worker_gid=None, require_identity=False)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_result_reader_rejects_empty_and_oversized_descriptors(self) -> None:
        with tempfile.TemporaryFile(dir=self.base) as result:
            with self.assertRaisesRegex(MediaEvidenceError, "invalid"):
                self.client._read_result_descriptor(result.fileno())
            result.write(b"{}")
            result.flush()
            with patch("media_evidence.worker_client._MAX_WORKER_RESULT_BYTES", 1):
                with self.assertRaisesRegex(MediaEvidenceError, "invalid"):
                    self.client._read_result_descriptor(result.fileno())

    def test_result_reader_accepts_one_bounded_regular_json_object(self) -> None:
        with tempfile.TemporaryFile(dir=self.base) as result:
            result.write(b'{"ok":true,"result":{}}')
            result.flush()
            self.assertEqual(os.fstat(result.fileno()).st_nlink, 0)
            self.assertTrue(self.client._read_result_descriptor(result.fileno())["ok"])

    def test_stage_output_monitor_bounds_bytes_and_inodes(self) -> None:
        output = self.base / "output"
        output.mkdir()
        (output / "large.bin").write_bytes(b"12")
        self.assertFalse(self.client._stage_output_within_budget(output, 1))
        self.assertTrue(self.client._stage_output_within_budget(output, 2))
        with patch("media_evidence.worker_client.os.walk", return_value=[(str(output), ["d"] * 5101, [])]):
            self.assertFalse(self.client._stage_output_within_budget(output, 1024))

    def test_worker_identity_command_has_one_supplemental_traverse_group(self) -> None:
        client = WorkerClient(
            worker_uid=1201,
            worker_gid=2201,
            traverse_gid=2203,
            require_identity=True,
        )
        payload = ["/opt/hermes-venv/bin/python", "-I", "-m", "media_evidence.worker"]

        self.assertEqual(
            client._identity_command(payload),
            [
                "/usr/bin/setpriv",
                "--reuid=1201",
                "--regid=2201",
                "--groups=2203",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                *payload,
            ],
        )

    def test_cgroup_violation_is_fail_closed_and_cleaned_up(self) -> None:
        output = self.base / "output"
        output.mkdir()
        source = self.base / "source.bin"
        source.write_bytes(b"source")
        created_commands: list[list[str]] = []
        created_environments: list[dict[str, str]] = []

        class FakeProcess:
            pid = 4242
            returncode = None

            def __init__(self, command, **kwargs) -> None:
                created_commands.append(list(command))
                created_environments.append(dict(kwargs["env"]))

            def poll(self):
                return self.returncode

            def terminate(self) -> None:
                self.returncode = 125

            def wait(self, timeout=None):
                self.returncode = 125
                return self.returncode

        class FakeCgroup:
            def __init__(self, path: Path) -> None:
                self.path = path
                self.closed = False

            def limit_violation(self) -> str:
                return "pids"

            def close(self) -> None:
                self.closed = True

        class FakeManager:
            def __init__(self, root: Path) -> None:
                self.root = root
                self.cgroup = FakeCgroup(root / f"job-1-{'0' * 24}")
                self.options: dict | None = None

            def available(self) -> bool:
                return True

            def create(self, options: dict) -> FakeCgroup:
                self.options = options
                return self.cgroup

        manager = FakeManager(self.base / "cgroups")
        client = WorkerClient(
            worker_uid=1201,
            worker_gid=2201,
            traverse_gid=2203,
            require_identity=True,
            cgroup_manager=manager,
        )
        options = {
            "worker_timeout_seconds": 10.0,
            "max_output_bytes": 1024,
            "cpu_limit_seconds": 10,
            "memory_limit_mb": 512,
            "process_limit": 4,
        }

        with patch("media_evidence.worker_client.os.geteuid", return_value=0), patch(
            "media_evidence.worker_client.os.chown"
        ), patch("media_evidence.worker_client.subprocess.Popen", FakeProcess):
            with self.assertRaisesRegex(MediaEvidenceError, "aggregate resource budget") as context:
                client(source, output, options)

        self.assertEqual(context.exception.code, "worker_resource_exceeded")
        self.assertIs(manager.options, options)
        self.assertTrue(manager.cgroup.closed)
        self.assertIn("--cgroup", created_commands[0])
        self.assertIn(str(manager.cgroup.path), created_commands[0])
        self.assertEqual(created_environments[0]["MEDIA_EVIDENCE_CGROUP_ROOT"], str(manager.root))


if __name__ == "__main__":
    unittest.main()
