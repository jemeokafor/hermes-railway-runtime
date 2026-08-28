from __future__ import annotations

import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any

from .contracts import MediaEvidenceError


_DEFAULT_CGROUP_ROOT = Path("/sys/fs/cgroup/hermes-media")
_JOB_CGROUP = re.compile(r"^job-[0-9]+-[0-9a-f]{24}$")
_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
_CGROUP_ERROR = "Aggregate media resource controls are unavailable"


def configured_cgroup_root() -> Path:
    raw = os.getenv("MEDIA_EVIDENCE_CGROUP_ROOT", str(_DEFAULT_CGROUP_ROOT)).strip()
    candidate = Path(raw)
    normalized = Path(os.path.abspath(candidate)) if candidate.is_absolute() else candidate
    if (
        not raw
        or not candidate.is_absolute()
        or normalized != candidate
        or candidate == Path(candidate.anchor)
    ):
        raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR)
    return candidate


def _decode_mount_path(value: str) -> Path:
    for encoded, decoded in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
        value = value.replace(encoded, decoded)
    return Path(value)


def _parse_key_values(path: Path) -> dict[str, int]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
        values: dict[str, int] = {}
        for line in lines:
            fields = line.split()
            if len(fields) != 2 or fields[0] in values:
                raise ValueError
            value = int(fields[1])
            if value < 0:
                raise ValueError
            values[fields[0]] = value
        return values
    except (OSError, UnicodeError, ValueError) as exc:
        raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR) from exc


class JobCgroup:
    def __init__(
        self,
        manager: CgroupV2Manager,
        path: Path,
        *,
        cpu_budget_usec: int,
    ):
        self.manager = manager
        self.path = path
        self.cpu_budget_usec = cpu_budget_usec
        self._closed = False

    def limit_violation(self) -> str | None:
        cpu = _parse_key_values(self.path / "cpu.stat")
        memory = _parse_key_values(self.path / "memory.events")
        pids = _parse_key_values(self.path / "pids.events")
        if cpu.get("usage_usec", 0) >= self.cpu_budget_usec:
            return "cpu"
        if any(memory.get(name, 0) > 0 for name in ("max", "oom", "oom_kill")):
            return "memory"
        if pids.get("max", 0) > 0:
            return "pids"
        return None

    def close(self) -> None:
        if self._closed:
            return
        self.manager._remove_cgroup(self.path)
        self._closed = True


class CgroupV2Manager:
    def __init__(
        self,
        root: Path | None = None,
        *,
        mountinfo_path: Path = Path("/proc/self/mountinfo"),
        self_cgroup_path: Path = Path("/proc/self/cgroup"),
    ):
        self.root = root if root is not None else configured_cgroup_root()
        self.mountinfo_path = mountinfo_path
        self.self_cgroup_path = self_cgroup_path
        self._lock = threading.Lock()
        self._prepared = False

    def available(self) -> bool:
        try:
            probe = self.create(
                {
                    "cpu_limit_seconds": 10,
                    "memory_limit_mb": 512,
                    "process_limit": 4,
                }
            )
            probe.close()
        except MediaEvidenceError:
            return False
        return True

    def create(self, options: dict[str, Any]) -> JobCgroup:
        self._prepare()
        name = f"job-{os.getpid()}-{secrets.token_hex(12)}"
        path = self.root / name
        try:
            os.mkdir(path, 0o700)
            self._validate_directory(path)
            controls = {
                "cgroup.max.depth": "0",
                "cgroup.max.descendants": "0",
                "cpu.max": "100000 100000",
                "memory.max": str(options["memory_limit_mb"] * 1024 * 1024),
                "memory.oom.group": "1",
                "memory.swap.max": "0",
                "pids.max": str(options["process_limit"]),
            }
            for name, value in controls.items():
                self._write_control(path / name, value)
                if self._read_control(path / name) != value:
                    raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR)
            for name in (
                "cgroup.events",
                "cgroup.kill",
                "cgroup.procs",
                "cpu.stat",
                "memory.events",
                "pids.events",
            ):
                self._validate_control(path / name)
            return JobCgroup(
                self,
                path,
                cpu_budget_usec=options["cpu_limit_seconds"] * 1_000_000,
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            self._discard_partial(path)
            raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR) from exc
        except MediaEvidenceError:
            self._discard_partial(path)
            raise

    def _prepare(self) -> None:
        with self._lock:
            if self._prepared:
                return
            try:
                if not self.root.is_absolute() or self.root == Path(self.root.anchor):
                    raise OSError("invalid cgroup root")
                parent = self.root.parent
                if parent.resolve(strict=True) != parent:
                    raise OSError("unsafe cgroup parent")
                if self.self_cgroup_path.read_text(encoding="ascii").strip() != "0::/":
                    raise OSError("the process is not at a private cgroup namespace root")
                mount = self._cgroup2_mount_for(parent)
                if self.root == mount:
                    raise OSError("cgroup root cannot be the cgroup2 mount")
                self._enable_controllers(parent)
                try:
                    os.mkdir(self.root, 0o700)
                except FileExistsError:
                    pass
                self._validate_directory(self.root)
                self._cleanup_stale_jobs()
                if self._read_control(self.root / "cgroup.procs"):
                    raise OSError("cgroup manager root contains processes")
                self._enable_controllers(self.root)
            except (OSError, UnicodeError, ValueError) as exc:
                raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR) from exc
            self._prepared = True

    def _cgroup2_mount_for(self, path: Path) -> Path:
        try:
            lines = self.mountinfo_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise OSError("mount information is unavailable") from exc
        matches: list[Path] = []
        for line in lines:
            if " - " not in line:
                continue
            left, right = line.split(" - ", 1)
            fields = left.split()
            filesystem = right.split()
            if len(fields) < 5 or not filesystem or filesystem[0] != "cgroup2":
                continue
            mount = _decode_mount_path(fields[4])
            try:
                path.relative_to(mount)
            except ValueError:
                continue
            matches.append(mount)
        if not matches:
            raise OSError("no containing cgroup2 mount")
        return max(matches, key=lambda value: len(value.parts))

    def _enable_controllers(self, path: Path) -> None:
        available = self._controller_set(path / "cgroup.controllers")
        if not _REQUIRED_CONTROLLERS.issubset(available):
            raise OSError("required cgroup controllers are unavailable")
        enabled = self._controller_set(path / "cgroup.subtree_control")
        missing = _REQUIRED_CONTROLLERS - enabled
        if missing:
            self._write_control(
                path / "cgroup.subtree_control",
                " ".join(f"+{name}" for name in sorted(missing)),
            )
            enabled = self._controller_set(path / "cgroup.subtree_control")
        if not _REQUIRED_CONTROLLERS.issubset(enabled):
            raise OSError("required cgroup controllers could not be enabled")

    def _cleanup_stale_jobs(self) -> None:
        for path in self.root.iterdir():
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise OSError("cgroup root changed during validation") from exc
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            if _JOB_CGROUP.fullmatch(path.name) is None:
                raise OSError("unexpected child cgroup")
            self._remove_cgroup(path)

    def _remove_cgroup(self, path: Path) -> None:
        try:
            self._validate_job_path(path)
            self._write_control(path / "cgroup.kill", "1")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                events = _parse_key_values(path / "cgroup.events")
                if events.get("populated") == 0:
                    break
                time.sleep(0.02)
            else:
                raise OSError("cgroup remained populated")
            os.rmdir(path)
        except (OSError, UnicodeError, ValueError) as exc:
            raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR) from exc

    def _discard_partial(self, path: Path) -> None:
        try:
            if path.exists():
                self._remove_cgroup(path)
        except MediaEvidenceError:
            pass

    def _validate_job_path(self, path: Path) -> None:
        if path.parent != self.root or _JOB_CGROUP.fullmatch(path.name) is None:
            raise OSError("invalid job cgroup")
        self._validate_directory(path)

    @staticmethod
    def _validate_directory(path: Path) -> None:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
            or path.resolve(strict=True) != path
        ):
            raise OSError("unsafe cgroup directory")

    @staticmethod
    def _validate_control(path: Path) -> None:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise OSError("unsafe cgroup control")

    @classmethod
    def _read_control(cls, path: Path) -> str:
        cls._validate_control(path)
        return path.read_text(encoding="ascii").strip()

    @classmethod
    def _write_control(cls, path: Path, value: str) -> None:
        cls._validate_control(path)
        with path.open("w", encoding="ascii") as handle:
            handle.write(value)

    @classmethod
    def _controller_set(cls, path: Path) -> set[str]:
        return {value.removeprefix("+") for value in cls._read_control(path).split()}


def join_job_cgroup(path: Path) -> None:
    root = configured_cgroup_root()
    try:
        if path.parent != root or _JOB_CGROUP.fullmatch(path.name) is None:
            raise OSError("invalid job cgroup")
        CgroupV2Manager._validate_directory(path)
        procs = path / "cgroup.procs"
        CgroupV2Manager._write_control(procs, str(os.getpid()))
        members = {int(value) for value in CgroupV2Manager._read_control(procs).split()}
        if os.getpid() not in members:
            raise OSError("supervisor did not enter its job cgroup")
    except (OSError, UnicodeError, ValueError) as exc:
        raise MediaEvidenceError("sandbox_unavailable", _CGROUP_ERROR) from exc
