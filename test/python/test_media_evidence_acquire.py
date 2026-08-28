from __future__ import annotations

import ipaddress
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from media_evidence.acquire import SecureHttpsAcquirer
from media_evidence.contracts import MediaEvidenceError
from media_evidence.sandbox import landlock_abi


class SecureHttpsAcquirerTests(unittest.TestCase):
    def test_rejects_unsafe_url_shapes(self) -> None:
        for url in (
            "http://example.com/file.mp4",
            "https://user:pass@example.com/file.mp4",
            "https://example.com:8443/file.mp4",
            "https://example.com/file.mp4#fragment",
            "https://example.com/file.mp4\n",
            "https://youtu.be/identifier",
        ):
            with self.subTest(url=url), self.assertRaises(MediaEvidenceError):
                SecureHttpsAcquirer._normalize_url(url)

    def test_rejects_private_or_mixed_dns_results(self) -> None:
        acquirer = SecureHttpsAcquirer()
        with self.assertRaisesRegex(MediaEvidenceError, "non-public"):
            acquirer._resolve_global_address("127.0.0.1")
        records = subprocess.CompletedProcess(
            ["getent"],
            0,
            "93.184.216.34 STREAM example.com\n10.0.0.2 STREAM example.com\n",
            "",
        )
        with patch("media_evidence.acquire.run_command", return_value=records):
            with self.assertRaisesRegex(MediaEvidenceError, "non-public"):
                acquirer._resolve_global_address("example.com")

    def test_rejects_multicast_literals_and_dns_results_even_when_global(self) -> None:
        acquirer = SecureHttpsAcquirer()
        for value in ("224.0.0.1", "ff0e::1"):
            self.assertTrue(ipaddress.ip_address(value).is_global)
            with self.subTest(value=value), self.assertRaisesRegex(MediaEvidenceError, "non-public"):
                acquirer._resolve_global_address(value)

        records = subprocess.CompletedProcess(
            ["getent"],
            0,
            "93.184.216.34 STREAM example.com\n224.0.0.1 STREAM example.com\n",
            "",
        )
        with patch("media_evidence.acquire.run_command", return_value=records):
            with self.assertRaisesRegex(MediaEvidenceError, "non-public"):
                acquirer._resolve_global_address("example.com")

    def test_redirects_are_revalidated_and_download_is_ip_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "source.download"
            calls: list[list[str]] = []

            def fake_run(argv, **kwargs):
                calls.append(list(argv))
                header_path = Path(argv[argv.index("--dump-header") + 1])
                body_path = Path(argv[argv.index("--output") + 1])
                if len(calls) == 1:
                    header_path.write_text(
                        "HTTP/1.1 302 Found\r\nLocation: https://cdn.example.net/media.mp4\r\n\r\n",
                        encoding="iso-8859-1",
                    )
                    body_path.write_bytes(b"")
                    stdout = "302\n0"
                else:
                    header_path.write_text("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", encoding="iso-8859-1")
                    body_path.write_bytes(b"media")
                    stdout = "200\n5"
                return subprocess.CompletedProcess(argv, 0, stdout, "")

            with (
                patch.object(SecureHttpsAcquirer, "_resolve_global_address", return_value="93.184.216.34"),
                patch("media_evidence.acquire.run_command", side_effect=fake_run),
                patch("media_evidence.acquire.os.chown"),
            ):
                result = SecureHttpsAcquirer(run_uid=1202, run_gid=2202, traverse_gid=2203).acquire(
                    "https://example.com/start",
                    destination,
                    max_bytes=1024,
                )
            self.assertEqual(destination.read_bytes(), b"media")
            self.assertEqual(result["redirects"], 1)
            self.assertEqual(result["final_origin"], "https://cdn.example.net")
            self.assertEqual(len(calls), 2)
            for command in calls:
                self.assertIn("media_evidence.supervisor", command)
                self.assertIn("media_evidence.acquisition_worker", command)
                self.assertIn("/usr/bin/setpriv", command)
                self.assertIn("/usr/bin/curl", command)
                self.assertIn("--globoff", command)
                self.assertIn("--resolve", command)
                self.assertIn("--noproxy", command)
                self.assertNotIn("--location", command)
                self.assertIn("--groups=2203", command)
                self.assertNotIn("--clear-groups", command)

    def test_acquisition_identity_command_has_one_supplemental_traverse_group(self) -> None:
        destination = Path("/data/media-evidence/quarantine/source.download")
        headers = destination.with_suffix(".headers")
        body = destination.with_suffix(".body")
        acquirer = SecureHttpsAcquirer(run_uid=1202, run_gid=2202, traverse_gid=2203)

        command = acquirer._supervised_command(
            ["/usr/bin/curl", "https://example.com/source"],
            timeout=12,
            write_paths=(headers, body),
        )

        self.assertEqual(
            command,
            [
                sys.executable,
                "-I",
                "-m",
                "media_evidence.supervisor",
                "--timeout",
                "12",
                "--parent-pid",
                str(os.getpid()),
                "--",
                "/usr/bin/setpriv",
                "--reuid=1202",
                "--regid=2202",
                "--groups=2203",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                sys.executable,
                "-I",
                "-m",
                "media_evidence.acquisition_worker",
                "--write",
                str(headers),
                "--write",
                str(body),
                "--",
                "/usr/bin/curl",
                "https://example.com/source",
            ],
        )

    def test_acquisition_worker_can_write_only_declared_files(self) -> None:
        if landlock_abi() < 1:
            self.skipTest("Landlock is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            secret = Path(temporary) / "secret"
            output.touch(mode=0o600)
            secret.write_text("private", encoding="utf-8")
            program = (
                "import sys; from pathlib import Path; output, secret = map(Path, sys.argv[1:]); "
                "denied = False; "
                "\ntry: secret.read_text(encoding='utf-8')\nexcept PermissionError: denied = True\n"
                "output.write_text('denied' if denied else 'readable', encoding='utf-8')"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "media_evidence.acquisition_worker",
                    "--write",
                    str(output),
                    "--",
                    sys.executable,
                    "-c",
                    program,
                    str(output),
                    str(secret),
                ],
                cwd=Path(__file__).resolve().parents[2],
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).resolve().parents[2])},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "denied")


if __name__ == "__main__":
    unittest.main()
