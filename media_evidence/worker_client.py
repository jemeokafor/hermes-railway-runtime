from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .cgroup import CgroupV2Manager, JobCgroup
from .contracts import MediaEvidenceError, atomic_write_json
from .sandbox import sanitized_worker_environment


_MAX_WORKER_RESULT_BYTES = 72 * 1024 * 1024
_WORKER_ERROR_MESSAGES = {
    "dependency_unavailable": "A required media dependency is unavailable",
    "duration_budget_exceeded": "The source exceeds the duration budget",
    "encrypted_pdf": "Encrypted PDFs are not accepted",
    "insufficient_evidence": "Extraction produced no anchored evidence",
    "invalid_arguments": "The media worker received invalid options",
    "malformed_media": "The source is malformed or unreadable",
    "malware_detected": "The source failed malware screening",
    "mime_probe_failed": "The source media type could not be determined",
    "page_budget_exceeded": "The source exceeds the page budget",
    "parser_failed": "A media parser rejected the source",
    "parser_output_exceeded": "A media parser exceeded its output budget",
    "parser_timeout": "A media parser exceeded its time budget",
    "pixel_budget_exceeded": "The source exceeds the pixel budget",
    "sandbox_unavailable": "The media sandbox is unavailable",
    "sandbox_violation": "The media worker violated its sandbox contract",
    "scanner_definitions_invalid": "Malware definitions are unavailable or invalid",
    "scanner_failed": "Required malware screening failed",
    "scanner_unavailable": "The required malware scanner is unavailable",
    "unsupported_media_type": "The detected media type is not supported",
    "worker_failed": "The media worker failed",
    "worker_resource_exceeded": "The media worker exceeded its aggregate resource budget",
}


class WorkerClient:
    def __init__(
        self,
        *,
        worker_uid: int | None,
        worker_gid: int | None,
        traverse_gid: int | None = None,
        require_identity: bool,
        cgroup_manager: CgroupV2Manager | None = None,
    ):
        self.worker_uid = worker_uid
        self.worker_gid = worker_gid
        self.traverse_gid = traverse_gid
        self.require_identity = require_identity
        self.cgroup_manager = cgroup_manager or (CgroupV2Manager() if require_identity else None)

    def aggregate_limits_available(self) -> bool:
        return self.cgroup_manager is not None and self.cgroup_manager.available()

    def __call__(self, source_path: Path, output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
        control_options = output_dir / ".worker-options.json"
        stdout_path = output_dir / ".worker-stdout.log"
        stderr_path = output_dir / ".worker-stderr.log"
        temporary = output_dir / "tmp"
        temporary.mkdir(mode=0o700)
        atomic_write_json(control_options, options, mode=0o440)

        if self.require_identity:
            if (
                os.geteuid() != 0
                or self.worker_uid is None
                or self.worker_gid is None
                or self.traverse_gid is None
                or 0 in {self.worker_uid, self.worker_gid, self.traverse_gid}
                or self.worker_gid == self.traverse_gid
            ):
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    "The media worker cannot enter its dedicated identity",
                )
            for path in (output_dir, temporary):
                os.chown(path, self.worker_uid, self.worker_gid)
                os.chmod(path, 0o700)
            os.chown(control_options, self.worker_uid, self.worker_gid)
            os.chmod(control_options, 0o400)

        python = Path("/opt/hermes-venv/bin/python")
        installed = Path("/opt/hermes-agent/media_evidence").is_dir() and python.is_file()
        if not installed:
            python = Path(sys.executable)
        environment = sanitized_worker_environment(output_dir)
        if not self.require_identity:
            environment["MEDIA_EVIDENCE_UNSAFE_TEST_IDENTITY"] = "1"
        cwd = "/opt/hermes-agent" if installed else str(Path(__file__).resolve().parents[1])
        if not installed:
            environment["PYTHONPATH"] = cwd

        cgroup: JobCgroup | None = None
        try:
            if self.require_identity:
                if self.cgroup_manager is None:
                    raise MediaEvidenceError(
                        "sandbox_unavailable",
                        "Aggregate media resource controls are unavailable",
                    )
                cgroup = self.cgroup_manager.create(options)
                environment["MEDIA_EVIDENCE_CGROUP_ROOT"] = str(self.cgroup_manager.root)
            with tempfile.TemporaryFile(prefix=".worker-result-", dir=output_dir) as result_file:
                result_descriptor = result_file.fileno()
                worker_command = [
                    str(python),
                    *(["-I"] if installed else []),
                    "-m",
                    "media_evidence.worker",
                    "--source",
                    str(source_path),
                    "--output",
                    str(output_dir),
                    "--options",
                    str(control_options),
                    "--result-fd",
                    str(result_descriptor),
                ]
                if self.require_identity:
                    worker_command = self._identity_command(worker_command)
                command = [
                    str(python),
                    *(["-I"] if installed else []),
                    "-m",
                    "media_evidence.supervisor",
                    "--timeout",
                    str(options["worker_timeout_seconds"]),
                    "--parent-pid",
                    str(os.getpid()),
                    *(["--cgroup", str(cgroup.path)] if cgroup is not None else []),
                    "--pass-fd",
                    str(result_descriptor),
                    "--",
                    *worker_command,
                ]
                with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                    process = subprocess.Popen(
                        command,
                        cwd=cwd,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        shell=False,
                        close_fds=True,
                        pass_fds=(result_descriptor,),
                        start_new_session=True,
                    )
                    deadline = time.monotonic() + options["worker_timeout_seconds"] + 20
                    while process.poll() is None:
                        violation = cgroup.limit_violation() if cgroup is not None else None
                        if violation is not None:
                            self._terminate_supervisor(process)
                            raise MediaEvidenceError(
                                "worker_resource_exceeded",
                                "The media worker exceeded its aggregate resource budget",
                            )
                        if not self._stage_output_within_budget(output_dir, options["max_output_bytes"]):
                            self._terminate_supervisor(process)
                            raise MediaEvidenceError(
                                "worker_output_exceeded",
                                "The media worker exceeded its output budget",
                            )
                        if time.monotonic() >= deadline:
                            self._terminate_supervisor(process)
                            exc = subprocess.TimeoutExpired(command, options["worker_timeout_seconds"] + 20)
                            raise MediaEvidenceError(
                                "worker_timeout",
                                "The media worker exceeded its wall-clock budget",
                            ) from exc
                        time.sleep(0.1)
                    returncode = process.returncode
                    violation = cgroup.limit_violation() if cgroup is not None else None
                    if violation is not None:
                        raise MediaEvidenceError(
                            "worker_resource_exceeded",
                            "The media worker exceeded its aggregate resource budget",
                        )
                    if returncode is None:
                        raise MediaEvidenceError(
                            "worker_failed",
                            "The media worker exited without a status",
                        )

                if returncode == 124:
                    raise MediaEvidenceError("worker_timeout", "The media worker exceeded its wall-clock budget")
                if returncode == 125:
                    raise MediaEvidenceError("sandbox_unavailable", "The media worker supervisor failed closed")
                for log_path in (stdout_path, stderr_path):
                    if log_path.stat().st_size > 1024 * 1024:
                        raise MediaEvidenceError(
                            "worker_output_exceeded",
                            "The media worker exceeded its diagnostic output budget",
                        )
                payload = self._read_result_descriptor(result_descriptor)
                if returncode != 0 or not payload.get("ok", False):
                    error = payload.get("error")
                    if not isinstance(error, str) or error not in _WORKER_ERROR_MESSAGES:
                        error = "worker_failed"
                    raise MediaEvidenceError(error, _WORKER_ERROR_MESSAGES[error])
                result = payload.get("result")
                if not isinstance(result, dict):
                    raise MediaEvidenceError("worker_contract_error", "The media worker result is invalid")
                return result
        finally:
            for path in (control_options, stdout_path, stderr_path):
                path.unlink(missing_ok=True)
            try:
                temporary.rmdir()
            except OSError:
                pass
            if cgroup is not None:
                cgroup.close()

    def _identity_command(self, command: list[str]) -> list[str]:
        if self.worker_uid is None or self.worker_gid is None or self.traverse_gid is None:
            raise MediaEvidenceError(
                "sandbox_unavailable",
                "The media worker cannot enter its dedicated identity",
            )
        return [
            "/usr/bin/setpriv",
            f"--reuid={self.worker_uid}",
            f"--regid={self.worker_gid}",
            f"--groups={self.traverse_gid}",
            "--no-new-privs",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            *command,
        ]

    @staticmethod
    def _read_result_descriptor(descriptor: int) -> dict[str, Any]:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= _MAX_WORKER_RESULT_BYTES:
            raise MediaEvidenceError("worker_contract_error", "The media worker result file is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        content = bytearray()
        while len(content) <= _MAX_WORKER_RESULT_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_WORKER_RESULT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != metadata.st_size or len(content) > _MAX_WORKER_RESULT_BYTES:
            raise MediaEvidenceError(
                "worker_contract_error",
                "The media worker result exceeded its budget",
            )
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise MediaEvidenceError("worker_contract_error", "The media worker did not return valid JSON") from exc
        if not isinstance(payload, dict):
            raise MediaEvidenceError("worker_contract_error", "The media worker result is invalid")
        return payload

    @staticmethod
    def _stage_output_within_budget(output_dir: Path, max_bytes: int) -> bool:
        total = 0
        control_total = 0
        count = 0
        controls = {".worker-options.json", ".worker-stderr.log", ".worker-stdout.log"}
        try:
            for root, directories, files in os.walk(output_dir, topdown=True, followlinks=False):
                count += len(directories) + len(files)
                if count > 5100:
                    return False
                root_path = Path(root)
                for name in files:
                    size = (root_path / name).lstat().st_size
                    relative = (root_path / name).relative_to(output_dir).as_posix()
                    if relative in controls:
                        control_total += size
                        if control_total > 4 * 1024 * 1024:
                            return False
                        continue
                    total += size
                    if total > max_bytes:
                        return False
        except OSError:
            return False
        return True

    @staticmethod
    def _terminate_supervisor(process: subprocess.Popen) -> None:
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=15)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
