from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from .contracts import MediaEvidenceError, sha256_text, utc_now
from .sandbox import run_command


class SecureHttpsAcquirer:
    def __init__(
        self,
        *,
        max_redirects: int = 3,
        timeout: float = 120.0,
        run_uid: int | None = None,
        run_gid: int | None = None,
        traverse_gid: int | None = None,
    ):
        self.max_redirects = max_redirects
        self.timeout = timeout
        identity = (run_uid, run_gid, traverse_gid)
        if any(value is not None for value in identity) and (
            any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in identity)
            or run_gid == traverse_gid
        ):
            raise ValueError("run_uid, run_gid, and a separate non-root traverse_gid must be configured together")
        self.run_uid = run_uid
        self.run_gid = run_gid
        self.traverse_gid = traverse_gid

    def acquire(self, url: str, destination: Path, *, max_bytes: int) -> dict:
        current = self._normalize_url(url)
        requested_hash = sha256_text(current)
        redirects = 0
        while True:
            parsed = urlsplit(current)
            host = parsed.hostname
            assert host is not None
            address = self._resolve_global_address(host)
            headers = destination.with_suffix(".headers")
            body = destination.with_suffix(".body")
            headers.unlink(missing_ok=True)
            body.unlink(missing_ok=True)
            if self.run_uid is not None and self.run_gid is not None and self.traverse_gid is not None:
                for path in (headers, body):
                    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
                    os.close(descriptor)
                    os.chown(path, self.run_uid, self.run_gid)
            resolve_address = f"[{address}]" if ":" in address else address
            resolve_host = f"[{host}]" if ":" in host else host
            try:
                command = [
                    "/usr/bin/curl",
                    "--disable",
                    "--globoff",
                    "--silent",
                    "--show-error",
                    "--proto",
                    "=https",
                    "--tlsv1.2",
                    "--noproxy",
                    "*",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    str(int(self.timeout)),
                    "--max-filesize",
                    str(max_bytes),
                    "--max-redirs",
                    "0",
                    "--user-agent",
                    "Hermes-Media-Evidence/1.0",
                    "--resolve",
                    f"{resolve_host}:443:{resolve_address}",
                    "--output",
                    str(body),
                    "--dump-header",
                    str(headers),
                    "--write-out",
                    "%{http_code}\n%{size_download}",
                    current,
                ]
                command = self._supervised_command(
                    command,
                    timeout=self.timeout,
                    write_paths=(headers, body),
                )
                result = run_command(
                    command,
                    timeout=self.timeout + 10,
                    max_output_bytes=64 * 1024,
                    accepted_returncodes={0, 63},
                    environment=self._network_environment(),
                    cwd=destination.parent,
                )
            except (MediaEvidenceError, OSError) as exc:
                headers.unlink(missing_ok=True)
                body.unlink(missing_ok=True)
                code = "remote_fetch_timeout" if getattr(exc, "code", None) == "parser_timeout" else "remote_fetch_failed"
                raise MediaEvidenceError(code, "Remote source retrieval failed") from exc
            if result.returncode == 63:
                headers.unlink(missing_ok=True)
                body.unlink(missing_ok=True)
                raise MediaEvidenceError("source_too_large", "Remote source exceeds the byte limit")
            if not headers.is_file() or headers.stat().st_size > 256 * 1024:
                body.unlink(missing_ok=True)
                headers.unlink(missing_ok=True)
                raise MediaEvidenceError("remote_fetch_failed", "Remote response headers are invalid")
            status, response_headers = self._parse_headers(headers.read_text(encoding="iso-8859-1"))
            headers.unlink(missing_ok=True)
            if 300 <= status < 400:
                body.unlink(missing_ok=True)
                location = response_headers.get("location")
                if not location or redirects >= self.max_redirects:
                    raise MediaEvidenceError("remote_redirect_rejected", "Remote redirect policy rejected the source")
                current = self._normalize_url(urljoin(current, location))
                redirects += 1
                continue
            if not 200 <= status < 300:
                body.unlink(missing_ok=True)
                raise MediaEvidenceError("remote_fetch_failed", "Remote source returned a non-success status")
            if not body.is_file():
                raise MediaEvidenceError("remote_fetch_failed", "Remote source returned no body")
            size = body.stat().st_size
            if size <= 0:
                body.unlink(missing_ok=True)
                raise MediaEvidenceError("source_empty", "Remote source is empty")
            if size > max_bytes:
                body.unlink(missing_ok=True)
                raise MediaEvidenceError("source_too_large", "Remote source exceeds the byte limit")
            os.replace(body, destination)
            final = urlsplit(current)
            final_host = final.hostname or ""
            origin_host = f"[{final_host}]" if ":" in final_host else final_host
            origin = urlunsplit(("https", origin_host, "", "", ""))
            return {
                "adapter": "https",
                "source_uri_sha256": requested_hash,
                "final_uri_sha256": sha256_text(current),
                "final_origin": origin,
                "redirects": redirects,
                "network_used": True,
                "retrieved_at": utc_now(),
                "name_sha256": sha256_text(Path(final.path).name or "remote-media"),
                "declared_suffix": Path(final.path).suffix.lower()[:32],
            }

    @staticmethod
    def _normalize_url(raw: str) -> str:
        if (
            not isinstance(raw, str)
            or not raw.strip()
            or len(raw) > 4096
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw)
        ):
            raise MediaEvidenceError("invalid_arguments", "source_url is invalid")
        parsed = urlsplit(raw.strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise MediaEvidenceError("remote_url_rejected", "Only HTTPS media URLs are accepted")
        if parsed.username or parsed.password or parsed.fragment:
            raise MediaEvidenceError("remote_url_rejected", "URL credentials and fragments are not accepted")
        try:
            port = parsed.port
        except ValueError as exc:
            raise MediaEvidenceError("remote_url_rejected", "Remote URL port is invalid") from exc
        if port not in {None, 443}:
            raise MediaEvidenceError("remote_url_rejected", "Only HTTPS port 443 is accepted")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if len(host) > 253:
            raise MediaEvidenceError("remote_url_rejected", "Remote URL host is invalid")
        if host in {"youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be"}:
            raise MediaEvidenceError(
                "specialized_adapter_required",
                "YouTube sources require the captions/media adapter and are not fetched as generic URLs",
            )
        netloc = f"[{host}]" if ":" in host else host
        path = parsed.path or "/"
        return urlunsplit(("https", netloc, path, parsed.query, ""))

    def _resolve_global_address(self, host: str) -> str:
        try:
            literal = ipaddress.ip_address(host)
            addresses = {literal}
        except ValueError:
            try:
                result = run_command(
                    self._supervised_command(
                        ["/usr/bin/getent", "ahosts", host],
                        timeout=15,
                    ),
                    timeout=15,
                    max_output_bytes=64 * 1024,
                    environment=SecureHttpsAcquirer._network_environment(),
                )
            except (MediaEvidenceError, OSError) as exc:
                raise MediaEvidenceError("remote_dns_failed", "Remote host could not be resolved") from exc
            addresses = set()
            for line in result.stdout.splitlines():
                try:
                    addresses.add(ipaddress.ip_address(line.split()[0]))
                except (IndexError, ValueError):
                    continue
        if not addresses or any(not self._is_public_unicast_address(address) for address in addresses):
            raise MediaEvidenceError("remote_address_rejected", "Remote host resolved to a non-public address")
        return str(sorted(addresses, key=lambda address: (address.version, int(address)))[0])

    @staticmethod
    def _is_public_unicast_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            address.is_global
            and not address.is_multicast
            and not address.is_unspecified
            and not address.is_reserved
            and not address.is_loopback
            and not address.is_link_local
        )

    def _supervised_command(
        self,
        command: list[str],
        *,
        timeout: float,
        write_paths: tuple[Path, ...] = (),
    ) -> list[str]:
        sandboxed = [
            sys.executable,
            "-I",
            "-m",
            "media_evidence.acquisition_worker",
        ]
        for path in write_paths:
            sandboxed.extend(("--write", str(path)))
        sandboxed.extend(("--", *command))
        if self.run_uid is not None and self.run_gid is not None and self.traverse_gid is not None:
            sandboxed = [
                "/usr/bin/setpriv",
                f"--reuid={self.run_uid}",
                f"--regid={self.run_gid}",
                f"--groups={self.traverse_gid}",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                *sandboxed,
            ]
        return [
            sys.executable,
            "-I",
            "-m",
            "media_evidence.supervisor",
            "--timeout",
            str(timeout),
            "--parent-pid",
            str(os.getpid()),
            "--",
            *sandboxed,
        ]

    @staticmethod
    def _network_environment() -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    @staticmethod
    def _parse_headers(raw: str) -> tuple[int, dict[str, str]]:
        blocks = [block for block in raw.replace("\r\n", "\n").split("\n\n") if block.strip()]
        if not blocks:
            raise MediaEvidenceError("remote_fetch_failed", "Remote response headers are empty")
        block = blocks[-1]
        lines = block.splitlines()
        parts = lines[0].split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise MediaEvidenceError("remote_fetch_failed", "Remote response status is invalid")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        return int(parts[1]), headers
