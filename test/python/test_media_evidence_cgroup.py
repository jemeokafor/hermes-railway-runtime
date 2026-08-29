from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from media_evidence.cgroup import CgroupV2Manager, join_job_cgroup
from media_evidence.contracts import MediaEvidenceError


class FakeCgroupFilesystem:
    def __init__(self, base: Path):
        self.mount = base / "cgroup"
        self.mount.mkdir(mode=0o700)
        self.root = self.mount / "hermes-media"
        self.mountinfo = base / "mountinfo"
        self.mountinfo.write_text(
            f"36 25 0:32 / {self.mount} rw,nosuid,nodev - cgroup2 cgroup rw\n",
            encoding="utf-8",
        )
        self.self_cgroup = base / "self-cgroup"
        self.self_cgroup.write_text("0::/\n", encoding="ascii")
        self._initialize(self.mount, manager=True)
        self.original_mkdir = os.mkdir
        self.original_rmdir = os.rmdir

    @staticmethod
    def _write(path: Path, value: str = "") -> None:
        path.write_text(value, encoding="ascii")
        path.chmod(0o600)

    def _initialize(self, path: Path, *, manager: bool = False) -> None:
        self._write(path / "cgroup.controllers", "cpu memory pids\n")
        self._write(path / "cgroup.subtree_control", "" if manager else "cpu memory pids\n")
        self._write(path / "cgroup.procs")
        if manager:
            return
        for name, value in {
            "cgroup.events": "populated 0\nfrozen 0\n",
            "cgroup.kill": "",
            "cgroup.max.depth": "max\n",
            "cgroup.max.descendants": "max\n",
            "cpu.max": "max 100000\n",
            "cpu.stat": "usage_usec 0\nuser_usec 0\nsystem_usec 0\n",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
            "memory.max": "max\n",
            "memory.oom.group": "0\n",
            "memory.swap.max": "max\n",
            "pids.events": "max 0\n",
            "pids.max": "max\n",
        }.items():
            self._write(path / name, value)

    def mkdir(self, path: str | bytes | os.PathLike, mode: int = 0o777, *, dir_fd=None) -> None:
        if dir_fd is not None:
            self.original_mkdir(path, mode, dir_fd=dir_fd)
            return
        candidate = Path(path)
        self.original_mkdir(candidate, mode)
        self._initialize(candidate, manager=candidate == self.root)

    def rmdir(self, path: str | bytes | os.PathLike, *, dir_fd=None) -> None:
        if dir_fd is not None:
            self.original_rmdir(path, dir_fd=dir_fd)
            return
        candidate = Path(path)
        for child in candidate.iterdir():
            child.unlink()
        self.original_rmdir(candidate)

    def patches(self):
        return (
            patch("media_evidence.cgroup.os.mkdir", side_effect=self.mkdir),
            patch("media_evidence.cgroup.os.rmdir", side_effect=self.rmdir),
        )


class MediaEvidenceCgroupTests(unittest.TestCase):
    OPTIONS = {
        "cpu_limit_seconds": 17,
        "memory_limit_mb": 768,
        "process_limit": 9,
    }

    def test_job_cgroup_enforces_aggregate_controls_and_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            filesystem = FakeCgroupFilesystem(Path(temporary))
            mkdir_patch, rmdir_patch = filesystem.patches()
            with mkdir_patch, rmdir_patch:
                manager = CgroupV2Manager(
                    filesystem.root,
                    mountinfo_path=filesystem.mountinfo,
                    self_cgroup_path=filesystem.self_cgroup,
                )
                job = manager.create(self.OPTIONS)

                self.assertEqual((job.path / "cpu.max").read_text(encoding="ascii"), "100000 100000")
                self.assertEqual((job.path / "memory.max").read_text(encoding="ascii"), str(768 * 1024 * 1024))
                self.assertEqual((job.path / "memory.swap.max").read_text(encoding="ascii"), "0")
                self.assertEqual((job.path / "memory.oom.group").read_text(encoding="ascii"), "1")
                self.assertEqual((job.path / "pids.max").read_text(encoding="ascii"), "9")
                self.assertEqual((job.path / "cgroup.max.depth").read_text(encoding="ascii"), "0")
                self.assertEqual((job.path / "cgroup.max.descendants").read_text(encoding="ascii"), "0")

                with patch.dict(os.environ, {"MEDIA_EVIDENCE_CGROUP_ROOT": str(filesystem.root)}):
                    join_job_cgroup(job.path)
                self.assertEqual(
                    (job.path / "cgroup.procs").read_text(encoding="ascii"),
                    str(os.getpid()),
                )
                self.assertIsNone(job.limit_violation())
                (job.path / "cpu.stat").write_text(
                    f"usage_usec {17 * 1_000_000}\n",
                    encoding="ascii",
                )
                self.assertEqual(job.limit_violation(), "cpu")

                path = job.path
                job.close()
                self.assertFalse(path.exists())

    def test_memory_and_pid_events_are_fail_closed_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            filesystem = FakeCgroupFilesystem(Path(temporary))
            mkdir_patch, rmdir_patch = filesystem.patches()
            with mkdir_patch, rmdir_patch:
                manager = CgroupV2Manager(
                    filesystem.root,
                    mountinfo_path=filesystem.mountinfo,
                    self_cgroup_path=filesystem.self_cgroup,
                )
                memory_job = manager.create(self.OPTIONS)
                (memory_job.path / "memory.events").write_text("max 1\noom 0\noom_kill 0\n", encoding="ascii")
                self.assertEqual(memory_job.limit_violation(), "memory")
                memory_job.close()

                pids_job = manager.create(self.OPTIONS)
                (pids_job.path / "pids.events").write_text("max 1\n", encoding="ascii")
                self.assertEqual(pids_job.limit_violation(), "pids")
                pids_job.close()

    def test_capability_probe_requires_all_controllers_and_cgroup2_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            filesystem = FakeCgroupFilesystem(Path(temporary))
            (filesystem.mount / "cgroup.controllers").write_text("cpu memory\n", encoding="ascii")
            manager = CgroupV2Manager(
                filesystem.root,
                mountinfo_path=filesystem.mountinfo,
                self_cgroup_path=filesystem.self_cgroup,
            )
            mkdir_patch, rmdir_patch = filesystem.patches()
            with mkdir_patch, rmdir_patch:
                self.assertFalse(manager.available())

        with tempfile.TemporaryDirectory() as temporary:
            filesystem = FakeCgroupFilesystem(Path(temporary))
            filesystem.mountinfo.write_text(
                f"36 25 0:32 / {filesystem.mount} rw - tmpfs tmpfs rw\n",
                encoding="utf-8",
            )
            manager = CgroupV2Manager(
                filesystem.root,
                mountinfo_path=filesystem.mountinfo,
                self_cgroup_path=filesystem.self_cgroup,
            )
            mkdir_patch, rmdir_patch = filesystem.patches()
            with mkdir_patch, rmdir_patch:
                self.assertFalse(manager.available())

    def test_join_rejects_a_cgroup_outside_the_configured_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            configured = base / "configured"
            configured.mkdir()
            outside = base / "outside" / f"job-1-{'0' * 24}"
            with patch.dict(os.environ, {"MEDIA_EVIDENCE_CGROUP_ROOT": str(configured)}):
                with self.assertRaises(MediaEvidenceError):
                    join_job_cgroup(outside)


if __name__ == "__main__":
    unittest.main()
