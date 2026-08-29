from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
import resource
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable, Sequence

from .contracts import MediaEvidenceError


_SCMP_ACT_ALLOW = 0x7FFF0000
_SCMP_ACT_ERRNO = 0x00050000
_WHISPER_MODEL_ROOT = Path("/opt/media-models")

_DENIED_SYSCALLS = (
    "socket",
    "socketpair",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "shutdown",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "ptrace",
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "io_uring_setup",
    "io_uring_register",
    "io_uring_enter",
    "open_by_handle_at",
    "name_to_handle_at",
    "process_vm_readv",
    "process_vm_writev",
    "pidfd_open",
    "pidfd_getfd",
    "fanotify_init",
    "kcmp",
    "keyctl",
    "add_key",
    "request_key",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "reboot",
    "swapon",
    "swapoff",
)

_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_DUMPABLE = 4

_LL_EXECUTE = 1 << 0
_LL_WRITE_FILE = 1 << 1
_LL_READ_FILE = 1 << 2
_LL_READ_DIR = 1 << 3
_LL_REMOVE_DIR = 1 << 4
_LL_REMOVE_FILE = 1 << 5
_LL_MAKE_CHAR = 1 << 6
_LL_MAKE_DIR = 1 << 7
_LL_MAKE_REG = 1 << 8
_LL_MAKE_SOCK = 1 << 9
_LL_MAKE_FIFO = 1 << 10
_LL_MAKE_BLOCK = 1 << 11
_LL_MAKE_SYM = 1 << 12
_LL_REFER = 1 << 13
_LL_TRUNCATE = 1 << 14
_LL_IOCTL_DEV = 1 << 15

_LL_READ_ACCESS = _LL_EXECUTE | _LL_READ_FILE | _LL_READ_DIR
_LL_WRITE_ACCESS = (
    _LL_WRITE_FILE
    | _LL_REMOVE_DIR
    | _LL_REMOVE_FILE
    | _LL_MAKE_DIR
    | _LL_MAKE_REG
    | _LL_MAKE_SOCK
    | _LL_MAKE_FIFO
    | _LL_MAKE_SYM
    | _LL_REFER
    | _LL_TRUNCATE
)


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def disable_process_inspection() -> None:
    if _libc().prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise MediaEvidenceError("sandbox_unavailable", "Could not disable process inspection")


def _landlock_syscalls() -> tuple[int, int, int] | None:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64", "aarch64", "arm64", "riscv64"}:
        return 444, 445, 446
    return None


def _seccomp_library_name() -> str | None:
    discovered = ctypes.util.find_library("seccomp")
    if discovered:
        return discovered
    machine = platform.machine().lower()
    architecture = {
        "x86_64": "x86_64-linux-gnu",
        "amd64": "x86_64-linux-gnu",
        "aarch64": "aarch64-linux-gnu",
        "arm64": "aarch64-linux-gnu",
    }.get(machine)
    candidates = [Path("/lib64/libseccomp.so.2"), Path("/usr/lib64/libseccomp.so.2")]
    if architecture:
        candidates.extend(
            (
                Path("/lib") / architecture / "libseccomp.so.2",
                Path("/usr/lib") / architecture / "libseccomp.so.2",
            )
        )
    return str(next((path for path in candidates if path.is_file()), "")) or None


def seccomp_available() -> bool:
    return _seccomp_library_name() is not None


def install_seccomp(*, required: bool = True) -> bool:
    library_name = _seccomp_library_name()
    if not library_name:
        if required:
            raise MediaEvidenceError("sandbox_unavailable", "libseccomp is unavailable")
        return False

    library = ctypes.CDLL(library_name, use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int

    context = library.seccomp_init(_SCMP_ACT_ALLOW)
    if not context:
        raise MediaEvidenceError("sandbox_unavailable", "Could not initialize seccomp")
    try:
        action = _SCMP_ACT_ERRNO | errno.EPERM
        for name in _DENIED_SYSCALLS:
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                continue
            result = library.seccomp_rule_add(context, action, number, 0)
            if result != 0:
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    f"Could not add seccomp rule for {name}",
                )
        if library.seccomp_load(context) != 0:
            raise MediaEvidenceError("sandbox_unavailable", "Could not load seccomp rules")
    finally:
        library.seccomp_release(context)
    return True


def landlock_abi() -> int:
    numbers = _landlock_syscalls()
    if numbers is None:
        return 0
    create_ruleset, _, _ = numbers
    ctypes.set_errno(0)
    result = _libc().syscall(
        ctypes.c_long(create_ruleset),
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result < 0:
        return 0
    return int(result)


def _handled_landlock_access(abi: int) -> int:
    access = (
        _LL_EXECUTE
        | _LL_WRITE_FILE
        | _LL_READ_FILE
        | _LL_READ_DIR
        | _LL_REMOVE_DIR
        | _LL_REMOVE_FILE
        | _LL_MAKE_CHAR
        | _LL_MAKE_DIR
        | _LL_MAKE_REG
        | _LL_MAKE_SOCK
        | _LL_MAKE_FIFO
        | _LL_MAKE_BLOCK
        | _LL_MAKE_SYM
    )
    if abi >= 2:
        access |= _LL_REFER
    if abi >= 3:
        access |= _LL_TRUNCATE
    if abi >= 5:
        access |= _LL_IOCTL_DEV
    return access


def restrict_filesystem(
    *,
    read_only: Iterable[Path],
    read_write: Iterable[Path],
    required: bool = True,
) -> bool:
    numbers = _landlock_syscalls()
    abi = landlock_abi()
    if numbers is None or abi < 1:
        if required:
            raise MediaEvidenceError("sandbox_unavailable", "Landlock is unavailable")
        return False

    create_ruleset, add_rule, restrict_self = numbers
    handled = _handled_landlock_access(abi)
    ruleset_attr = _LandlockRulesetAttr(handled_access_fs=handled)
    libc = _libc()
    ruleset_fd = libc.syscall(
        ctypes.c_long(create_ruleset),
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        ctypes.c_uint(0),
    )
    if ruleset_fd < 0:
        error = ctypes.get_errno()
        raise MediaEvidenceError(
            "sandbox_unavailable",
            f"Could not create Landlock ruleset: errno {error}",
        )

    path_fds: list[int] = []
    try:
        entries: list[tuple[Path, int]] = []
        entries.extend((Path(path), _LL_READ_ACCESS) for path in read_only)
        entries.extend((Path(path), _LL_READ_ACCESS | _LL_WRITE_ACCESS) for path in read_write)
        seen: set[tuple[str, int]] = set()
        for path, requested_access in entries:
            if not path.exists():
                continue
            resolved = path.resolve()
            if resolved.is_dir():
                allowed_access = requested_access & handled
            else:
                file_access = _LL_READ_FILE
                if requested_access & _LL_WRITE_ACCESS:
                    file_access |= _LL_WRITE_FILE | _LL_TRUNCATE
                if requested_access & _LL_EXECUTE:
                    file_access |= _LL_EXECUTE
                allowed_access = file_access & handled
            key = (str(resolved), allowed_access)
            if key in seen:
                continue
            seen.add(key)
            descriptor = os.open(resolved, os.O_PATH | os.O_CLOEXEC)
            path_fds.append(descriptor)
            rule_attr = _LandlockPathBeneathAttr(
                allowed_access=allowed_access,
                parent_fd=descriptor,
            )
            result = libc.syscall(
                ctypes.c_long(add_rule),
                ctypes.c_int(ruleset_fd),
                ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule_attr),
                ctypes.c_uint(0),
            )
            if result < 0:
                error = ctypes.get_errno()
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    f"Could not add Landlock path rule: errno {error}",
                )

        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise MediaEvidenceError(
                "sandbox_unavailable",
                f"Could not set no_new_privs: errno {error}",
            )
        result = libc.syscall(
            ctypes.c_long(restrict_self),
            ctypes.c_int(ruleset_fd),
            ctypes.c_uint(0),
        )
        if result < 0:
            error = ctypes.get_errno()
            raise MediaEvidenceError(
                "sandbox_unavailable",
                f"Could not apply Landlock ruleset: errno {error}",
            )
    finally:
        for descriptor in path_fds:
            os.close(descriptor)
        os.close(ruleset_fd)
    return True


def apply_resource_limits(options: dict) -> None:
    limits = [
        (resource.RLIMIT_CORE, 0, 0),
        (resource.RLIMIT_CPU, options["cpu_limit_seconds"], options["cpu_limit_seconds"] + 5),
        (
            resource.RLIMIT_AS,
            options["memory_limit_mb"] * 1024 * 1024,
            options["memory_limit_mb"] * 1024 * 1024,
        ),
        (
            resource.RLIMIT_FSIZE,
            options["file_limit_mb"] * 1024 * 1024,
            options["file_limit_mb"] * 1024 * 1024,
        ),
        (resource.RLIMIT_NOFILE, options["open_file_limit"], options["open_file_limit"]),
    ]
    for kind, soft, hard in limits:
        current_soft, current_hard = resource.getrlimit(kind)
        bounded_hard = hard if current_hard == resource.RLIM_INFINITY else min(hard, current_hard)
        bounded_soft = min(soft, bounded_hard)
        resource.setrlimit(kind, (bounded_soft, bounded_hard))


def validated_whisper_model_path(raw: str) -> Path | None:
    value = raw.strip()
    if not value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        raise MediaEvidenceError("sandbox_unavailable", "The configured Whisper model path is invalid")
    try:
        resolved = candidate.resolve(strict=True)
        root = _WHISPER_MODEL_ROOT.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise MediaEvidenceError("sandbox_unavailable", "The configured Whisper model path is invalid") from exc
    if not relative.parts or resolved != Path(os.path.abspath(candidate)) or not resolved.is_dir():
        raise MediaEvidenceError("sandbox_unavailable", "The configured Whisper model path is invalid")
    root_metadata = root.lstat()
    if root.is_symlink() or root_metadata.st_uid != 0 or root_metadata.st_mode & 0o022:
        raise MediaEvidenceError("sandbox_unavailable", "The configured Whisper model path is unsafe")
    current = root
    for part in relative.parts:
        current = current / part
        metadata = current.lstat()
        if current.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise MediaEvidenceError("sandbox_unavailable", "The configured Whisper model path is unsafe")
    return resolved


def sanitized_worker_environment(output_dir: Path) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "HF_HOME": "/data/.cache/huggingface",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "CT2_USE_EXPERIMENTAL_PACKED_GEMM": "0",
        "TMPDIR": str(output_dir / "tmp"),
    }
    model_path = os.getenv("MEDIA_EVIDENCE_WHISPER_MODEL_PATH", "").strip()
    if model_path:
        environment["MEDIA_EVIDENCE_WHISPER_MODEL_PATH"] = str(validated_whisper_model_path(model_path))
    return environment


def run_command(
    argv: Sequence[str],
    *,
    timeout: float,
    max_output_bytes: int = 8 * 1024 * 1024,
    accepted_returncodes: set[int] | None = None,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    if not argv or not os.path.isabs(argv[0]):
        raise MediaEvidenceError("sandbox_violation", "Parser executable must be an absolute path")
    accepted_returncodes = accepted_returncodes or {0}
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            shell=False,
            start_new_session=True,
            close_fds=True,
            env=environment,
            cwd=str(cwd) if cwd else None,
        )
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise MediaEvidenceError(
                    "parser_timeout",
                    "A media parser exceeded its wall-clock budget",
                )
            try:
                returncode = process.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                if (
                    os.fstat(stdout_file.fileno()).st_size > max_output_bytes
                    or os.fstat(stderr_file.fileno()).st_size > max_output_bytes
                ):
                    _kill_process_group(process)
                    raise MediaEvidenceError(
                        "parser_output_exceeded",
                        "A media parser exceeded its diagnostic output budget",
                    )

        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout_raw = stdout_file.read(max_output_bytes + 1)
        stderr_raw = stderr_file.read(max_output_bytes + 1)
        if len(stdout_raw) > max_output_bytes or len(stderr_raw) > max_output_bytes:
            raise MediaEvidenceError(
                "parser_output_exceeded",
                "A media parser exceeded its diagnostic output budget",
            )
        stdout = stdout_raw.decode("utf-8", errors="replace")
        stderr = stderr_raw.decode("utf-8", errors="replace")
        if returncode not in accepted_returncodes:
            detail = (stderr or stdout).strip()[-2000:]
            raise MediaEvidenceError(
                "parser_failed",
                "A media parser returned an error",
                details={"returncode": returncode, "diagnostic": detail},
            )
        return subprocess.CompletedProcess(list(argv), returncode, stdout, stderr)


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise MediaEvidenceError(
            "parser_termination_failed",
            "A media parser could not be terminated",
        ) from exc
