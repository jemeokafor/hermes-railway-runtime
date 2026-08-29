from __future__ import annotations

import argparse
import ctypes
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .cgroup import join_job_cgroup


_PR_SET_CHILD_SUBREAPER = 36
_PR_SET_PDEATHSIG = 1
_SUPERVISOR_TIMEOUT_EXIT = 124
_SUPERVISOR_CLEANUP_EXIT = 125
_STOP_REQUESTED = False


def _set_child_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not become a child subreaper")


def _set_parent_death_signal() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not configure parent-death handling")


def _child_pids() -> list[int]:
    path = f"/proc/{os.getpid()}/task/{os.getpid()}/children"
    try:
        content = open(path, "r", encoding="ascii").read().strip()
    except OSError:
        return []
    return [int(value) for value in content.split() if value.isdigit()]


def _reap_children() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _terminate_adopted_children(timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _reap_children()
        children = _child_pids()
        if not children:
            return True
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.02)
    _reap_children()
    return not _child_pids()


def _request_stop(_signum: int, _frame: object) -> None:
    global _STOP_REQUESTED
    _STOP_REQUESTED = True


def supervise(
    command: list[str],
    timeout: float,
    expected_parent_pid: int,
    pass_fds: tuple[int, ...] = (),
    cgroup_path: Path | None = None,
) -> int:
    global _STOP_REQUESTED
    _STOP_REQUESTED = False
    if not command or not os.path.isabs(command[0]):
        return _SUPERVISOR_CLEANUP_EXIT
    for name in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(name, _request_stop)
    _set_child_subreaper()
    _set_parent_death_signal()
    if cgroup_path is not None:
        join_job_cgroup(cgroup_path)
    if _STOP_REQUESTED or os.getppid() != expected_parent_pid:
        return _SUPERVISOR_CLEANUP_EXIT
    child = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        shell=False,
        close_fds=True,
        pass_fds=pass_fds,
        start_new_session=False,
    )
    deadline = time.monotonic() + timeout
    timed_out = False
    interrupted = False
    while child.poll() is None:
        if _STOP_REQUESTED or os.getppid() != expected_parent_pid:
            interrupted = True
            try:
                os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            try:
                os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            break
        time.sleep(0.05)
    returncode = child.returncode if child.returncode is not None else _SUPERVISOR_CLEANUP_EXIT
    if not _terminate_adopted_children():
        return _SUPERVISOR_CLEANUP_EXIT
    if interrupted:
        return _SUPERVISOR_CLEANUP_EXIT
    return _SUPERVISOR_TIMEOUT_EXIT if timed_out else returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--cgroup")
    parser.add_argument("--pass-fd", type=int, action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if (
        not 1 <= args.timeout <= 1800
        or args.parent_pid < 1
        or any(descriptor < 3 for descriptor in args.pass_fd)
    ):
        return _SUPERVISOR_CLEANUP_EXIT
    try:
        return supervise(
            command,
            args.timeout,
            args.parent_pid,
            tuple(args.pass_fd),
            Path(args.cgroup) if args.cgroup else None,
        )
    except BaseException:
        return _SUPERVISOR_CLEANUP_EXIT


if __name__ == "__main__":
    sys.exit(main())
