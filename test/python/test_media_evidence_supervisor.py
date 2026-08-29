from __future__ import annotations

import errno
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class MediaEvidenceSupervisorTests(unittest.TestCase):
    @staticmethod
    def assert_process_exits(pid: int) -> None:
        for _ in range(100):
            try:
                state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2]
            except (FileNotFoundError, ProcessLookupError):
                return
            if state == "Z":
                return
            time.sleep(0.02)
        raise AssertionError(f"Process {pid} survived supervisor cleanup")

    def test_supervisor_kills_detached_descendants_after_worker_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "descendant.pid"
            worker = (
                "import subprocess, sys; from pathlib import Path; "
                "p=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True); "
                "Path(sys.argv[1]).write_text(str(p.pid), encoding='ascii')"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "media_evidence.supervisor",
                    "--timeout",
                    "5",
                    "--parent-pid",
                    str(os.getpid()),
                    "--",
                    sys.executable,
                    "-c",
                    worker,
                    str(pid_path),
                ],
                cwd=REPO_ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(REPO_ROOT)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            descendant = int(pid_path.read_text(encoding="ascii"))
            for _ in range(50):
                try:
                    os.kill(descendant, 0)
                except OSError as exc:
                    if exc.errno == errno.ESRCH:
                        break
                time.sleep(0.02)
            else:
                self.fail("Detached parser descendant survived supervisor cleanup")

    def test_supervisor_termination_cleans_worker_and_detached_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "descendant.pid"
            worker = (
                "import subprocess, sys, time; from pathlib import Path; "
                "p=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True); "
                "Path(sys.argv[1]).write_text(str(p.pid), encoding='ascii'); time.sleep(30)"
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "media_evidence.supervisor",
                    "--timeout",
                    "30",
                    "--parent-pid",
                    str(os.getpid()),
                    "--",
                    sys.executable,
                    "-c",
                    worker,
                    str(pid_path),
                ],
                cwd=REPO_ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(REPO_ROOT)},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(100):
                if pid_path.exists():
                    break
                time.sleep(0.02)
            else:
                process.kill()
                self.fail("Worker did not create its detached descendant")
            descendant = int(pid_path.read_text(encoding="ascii"))
            process.terminate()
            self.assertEqual(process.wait(timeout=10), 125)
            self.assert_process_exits(descendant)

    def test_supervisor_parent_death_cleans_worker_and_detached_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            supervisor_pid_path = Path(temporary) / "supervisor.pid"
            descendant_pid_path = Path(temporary) / "descendant.pid"
            worker = (
                "import subprocess, sys, time; from pathlib import Path; "
                "p=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True); "
                "Path(sys.argv[1]).write_text(str(p.pid), encoding='ascii'); time.sleep(30)"
            )
            launcher = "\n".join(
                [
                    "import os, subprocess, sys, time",
                    "from pathlib import Path",
                    "repo, supervisor_path, descendant_path, worker = sys.argv[1:]",
                    "environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONPATH': repo}",
                    "process = subprocess.Popen([sys.executable, '-m', 'media_evidence.supervisor', '--timeout', '30', '--parent-pid', str(os.getpid()), '--', sys.executable, '-c', worker, descendant_path], cwd=repo, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)",
                    "Path(supervisor_path).write_text(str(process.pid), encoding='ascii')",
                    "deadline = time.monotonic() + 5",
                    "while not Path(descendant_path).exists() and time.monotonic() < deadline: time.sleep(0.02)",
                    "os._exit(0)",
                ]
            )
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    launcher,
                    str(REPO_ROOT),
                    str(supervisor_pid_path),
                    str(descendant_pid_path),
                    worker,
                ],
                cwd=REPO_ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(REPO_ROOT)},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=10,
            )
            self.assertTrue(descendant_pid_path.exists())
            supervisor = int(supervisor_pid_path.read_text(encoding="ascii"))
            descendant = int(descendant_pid_path.read_text(encoding="ascii"))
            self.assert_process_exits(supervisor)
            self.assert_process_exits(descendant)

    def test_supervisor_rejects_stale_expected_parent_before_worker_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "spawned"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "media_evidence.supervisor",
                    "--timeout",
                    "5",
                    "--parent-pid",
                    str(os.getpid() + 100000),
                    "--",
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                    str(marker),
                ],
                cwd=REPO_ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(REPO_ROOT)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 125)
            self.assertFalse(marker.exists())

    def test_supervisor_joins_job_cgroup_before_worker_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroups"
            root.mkdir(mode=0o700)
            job = root / f"job-1-{'0' * 24}"
            job.mkdir(mode=0o700)
            procs = job / "cgroup.procs"
            procs.write_text("", encoding="ascii")
            procs.chmod(0o600)
            marker = Path(temporary) / "joined"
            worker = (
                "import os, sys; from pathlib import Path; "
                "observed=Path(sys.argv[1]).read_text(encoding='ascii').strip(); "
                "sys.exit(2) if observed != str(os.getppid()) else Path(sys.argv[2]).touch()"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "media_evidence.supervisor",
                    "--timeout",
                    "5",
                    "--parent-pid",
                    str(os.getpid()),
                    "--cgroup",
                    str(job),
                    "--",
                    sys.executable,
                    "-c",
                    worker,
                    str(procs),
                    str(marker),
                ],
                cwd=REPO_ROOT,
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "PYTHONPATH": str(REPO_ROOT),
                    "MEDIA_EVIDENCE_CGROUP_ROOT": str(root),
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            self.assertTrue(marker.exists())

    def test_supervisor_cgroup_join_failure_prevents_worker_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroups"
            root.mkdir(mode=0o700)
            job = root / f"job-1-{'0' * 24}"
            job.mkdir(mode=0o700)
            marker = Path(temporary) / "spawned"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "media_evidence.supervisor",
                    "--timeout",
                    "5",
                    "--parent-pid",
                    str(os.getpid()),
                    "--cgroup",
                    str(job),
                    "--",
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                    str(marker),
                ],
                cwd=REPO_ROOT,
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "PYTHONPATH": str(REPO_ROOT),
                    "MEDIA_EVIDENCE_CGROUP_ROOT": str(root),
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 125)
            self.assertFalse(marker.exists())

    def test_immediate_parent_exit_cannot_leave_a_worker_alive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            supervisor_pid_path = Path(temporary) / "supervisor.pid"
            marker = Path(temporary) / "survived"
            launcher = "\n".join(
                [
                    "import os, subprocess, sys",
                    "from pathlib import Path",
                    "repo, pid_path, marker = sys.argv[1:]",
                    "environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONPATH': repo}",
                    "worker = 'import sys, time; from pathlib import Path; time.sleep(0.5); Path(sys.argv[1]).touch(); time.sleep(30)'",
                    "process = subprocess.Popen([sys.executable, '-m', 'media_evidence.supervisor', '--timeout', '30', '--parent-pid', str(os.getpid()), '--', sys.executable, '-c', worker, marker], cwd=repo, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)",
                    "Path(pid_path).write_text(str(process.pid), encoding='ascii')",
                    "os._exit(0)",
                ]
            )
            subprocess.run(
                [sys.executable, "-c", launcher, str(REPO_ROOT), str(supervisor_pid_path), str(marker)],
                cwd=REPO_ROOT,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(REPO_ROOT)},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=10,
            )
            supervisor = int(supervisor_pid_path.read_text(encoding="ascii"))
            self.assert_process_exits(supervisor)
            time.sleep(0.7)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
