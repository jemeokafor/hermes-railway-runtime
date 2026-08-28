from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from media_evidence.contracts import MediaEvidenceError
from media_evidence.sandbox import (
    landlock_abi,
    run_command,
    sanitized_worker_environment,
    seccomp_available,
)
from media_evidence.worker import _WORKER_READ_ONLY_PATHS


REPO_ROOT = Path(__file__).resolve().parents[2]


class MediaEvidenceSandboxTests(unittest.TestCase):
    def test_worker_allowlist_uses_exact_clamav_paths_without_proc(self) -> None:
        self.assertIn(Path("/etc/clamav/certs"), _WORKER_READ_ONLY_PATHS)
        self.assertIn(Path("/etc/localtime"), _WORKER_READ_ONLY_PATHS)
        self.assertNotIn(Path("/etc/clamav"), _WORKER_READ_ONLY_PATHS)
        proc = Path("/proc")
        self.assertFalse(
            any(path == proc or proc in path.parents for path in _WORKER_READ_ONLY_PATHS)
        )

    def test_whisper_model_override_cannot_expand_to_filesystem_root(self) -> None:
        with patch.dict(os.environ, {"MEDIA_EVIDENCE_WHISPER_MODEL_PATH": "/"}):
            with self.assertRaisesRegex(MediaEvidenceError, "model path"):
                sanitized_worker_environment(Path("/tmp/media-output"))

    def run_child(self, source: str, *args: str) -> subprocess.CompletedProcess:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(REPO_ROOT),
            "PYTHONNOUSERSITE": "1",
        }
        return subprocess.run(
            [sys.executable, "-c", textwrap.dedent(source), *args],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_seccomp_denies_network_syscalls(self) -> None:
        if not seccomp_available():
            self.skipTest("libseccomp is unavailable")
        result = self.run_child(
            """
            import errno
            import socket
            from media_evidence.sandbox import install_seccomp

            install_seccomp(required=True)
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except OSError as exc:
                raise SystemExit(0 if exc.errno in {errno.EPERM, errno.EACCES} else 2)
            raise SystemExit(3)
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_seccomp_denies_pidfd_access_to_other_processes(self) -> None:
        if not seccomp_available() or not hasattr(os, "pidfd_open"):
            self.skipTest("pidfd or libseccomp is unavailable")
        result = self.run_child(
            """
            import errno
            import os
            from media_evidence.sandbox import install_seccomp

            install_seccomp(required=True)
            try:
                os.pidfd_open(os.getpid())
            except OSError as exc:
                raise SystemExit(0 if exc.errno in {errno.EPERM, errno.EACCES} else 2)
            raise SystemExit(3)
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_worker_process_can_be_made_non_dumpable(self) -> None:
        result = self.run_child(
            """
            import ctypes
            from media_evidence.sandbox import disable_process_inspection

            disable_process_inspection()
            raise SystemExit(0 if ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) == 0 else 2)
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_landlock_denies_files_outside_allowlist(self) -> None:
        if landlock_abi() < 1:
            self.skipTest("Landlock is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            readable = base / "readable.txt"
            readable.write_text("allowed", encoding="utf-8")
            writable = base / "writable"
            writable.mkdir()
            denied = base / "denied.txt"
            denied.write_text("private", encoding="utf-8")
            result = self.run_child(
                """
                import errno
                import sys
                from pathlib import Path
                from media_evidence.sandbox import restrict_filesystem

                readable, writable, denied = map(Path, sys.argv[1:])
                restrict_filesystem(read_only=[readable], read_write=[writable], required=True)
                assert readable.read_text() == "allowed"
                (writable / "created.txt").write_text("ok")
                try:
                    denied.read_text()
                except OSError as exc:
                    raise SystemExit(0 if exc.errno in {errno.EPERM, errno.EACCES} else 2)
                raise SystemExit(3)
                """,
                str(readable),
                str(writable),
                str(denied),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_parser_output_is_killed_when_it_exceeds_budget(self) -> None:
        command = "import sys, time; sys.stdout.write('x' * 1000000); sys.stdout.flush(); time.sleep(5)"
        with self.assertRaisesRegex(MediaEvidenceError, "diagnostic output budget"):
            run_command(
                [sys.executable, "-c", command],
                timeout=10,
                max_output_bytes=4096,
            )


if __name__ == "__main__":
    unittest.main()
