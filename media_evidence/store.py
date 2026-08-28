from __future__ import annotations

import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .contracts import MediaEvidenceError, atomic_write_bytes, canonical_json_bytes, utc_now


_TELEMETRY_MAX_BYTES = 64 * 1024 * 1024
_TELEMETRY_BACKUPS = 5
_LEDGER_MAX_BYTES = 16 * 1024 * 1024
_LEDGER_MAX_RECORDS = 10_000
_ZERO_DIGEST = "0" * 64
_CAPACITY_RESERVATION_SCHEMA = "media-evidence-capacity-reservation/v1"
_CAPACITY_JOB_ID = re.compile(r"^mev_[0-9a-f]{24}$")
_CAPACITY_RESERVATION_FILE = re.compile(r"^(mev_[0-9a-f]{24})\.reservation$")
_CAPACITY_RESERVATION_TEMP = re.compile(r"^\.tmp-(mev_[0-9a-f]{24})-[0-9a-f]{32}\.reservation$")
_MAX_CAPACITY_RESERVATION_BYTES = 4 * 1024 * 1024 * 1024
_MAX_CAPACITY_RESERVATION_RECORD_BYTES = 512
_MAX_CAPACITY_RESERVATIONS = 1024


class _CapacityReservation:
    def __init__(self, store: EvidenceStore, name: str, descriptor: int):
        self._store = store
        self._name = name
        self._descriptor = descriptor

    def release(self) -> None:
        if self._descriptor < 0:
            return
        descriptor = self._descriptor
        self._descriptor = -1
        self._store._release_capacity_reservation(self._name, descriptor)

    def __enter__(self) -> _CapacityReservation:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class EvidenceStore:
    _DIRECTORY_POLICY = (
        (".", "traverse", 0o710),
        ("cas", "worker", 0o750),
        ("cas/sha256", "worker", 0o750),
        ("keys", "root", 0o700),
        ("locks", "root", 0o700),
        ("locks/capacity-reservations", "root", 0o700),
        ("quarantine", "acquisition", 0o710),
        ("runs", "worker", 0o750),
        ("ledgers", "root", 0o700),
        ("telemetry", "root", 0o700),
    )

    def __init__(
        self,
        root: Path,
        *,
        worker_gid: int | None = None,
        acquisition_gid: int | None = None,
        traverse_gid: int | None = None,
    ):
        self.root = Path(root)
        self.worker_gid = worker_gid
        self.acquisition_gid = acquisition_gid
        self.traverse_gid = traverse_gid
        configured_gids = (worker_gid, acquisition_gid, traverse_gid)
        self.production_identity = any(gid is not None for gid in configured_gids)
        if self.production_identity:
            if (
                any(isinstance(gid, bool) or not isinstance(gid, int) or gid <= 0 for gid in configured_gids)
                or len(set(configured_gids)) != len(configured_gids)
                or os.geteuid() != 0
            ):
                raise MediaEvidenceError(
                    "configuration_error",
                    "Evidence store identities must be distinct non-root groups managed by root",
                )
            self.owner_uid = 0
            self.control_gid: int | None = 0
        else:
            if any(gid is not None for gid in configured_gids):
                raise MediaEvidenceError("configuration_error", "Evidence store identity configuration is incomplete")
            self.owner_uid = os.geteuid()
            self.control_gid = None

        self.database_path = self.root / "jobs.sqlite3"
        self.key_path = self.root / "keys" / "manifest-hmac-v1.key"
        self.capacity_reservation_directory = self.root / "locks" / "capacity-reservations"
        self._validate_store_parent_chain()
        for path, uid, gid, mode in self._resolved_directory_policy(
            self.root,
            owner_uid=self.owner_uid,
            worker_gid=self.worker_gid,
            acquisition_gid=self.acquisition_gid,
            traverse_gid=self.traverse_gid,
        ):
            self._ensure_secure_directory(path, mode, uid=uid, gid=gid)

        database_exists = self._validate_fixed_file(
            self.database_path,
            mode=0o600,
            message="Evidence store database ownership or permissions are unsafe",
        )
        self._validate_fixed_file(
            self.key_path,
            mode=0o600,
            message="Manifest signing key permissions are unsafe",
        )
        if not database_exists:
            self._create_control_file(self.database_path)
        self._initialize_database()
        self._validate_fixed_file(
            self.database_path,
            mode=0o600,
            message="Evidence store database ownership or permissions are unsafe",
        )

    @classmethod
    def _resolved_directory_policy(
        cls,
        root: Path,
        *,
        owner_uid: int,
        worker_gid: int | None,
        acquisition_gid: int | None,
        traverse_gid: int | None,
    ) -> tuple[tuple[Path, int, int | None, int], ...]:
        role_gids = {
            "root": 0 if traverse_gid is not None else None,
            "worker": worker_gid,
            "acquisition": acquisition_gid,
            "traverse": traverse_gid,
        }
        return tuple(
            (
                root if relative == "." else root / relative,
                owner_uid,
                role_gids[role],
                mode,
            )
            for relative, role, mode in cls._DIRECTORY_POLICY
        )

    def _validate_store_parent_chain(self) -> None:
        for candidate in reversed(self.root.parents):
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The evidence store parent path is unavailable",
                ) from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise MediaEvidenceError(
                    "configuration_error",
                    "The evidence store contains an unsafe directory component",
                )
            if self.production_identity and metadata.st_uid != 0:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The evidence store parent path must be root-owned",
                )

    def _ensure_secure_directory(self, path: Path, mode: int, *, uid: int, gid: int | None) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            try:
                path.mkdir(mode=mode)
                if gid is not None:
                    os.chown(path, uid, gid)
                os.chmod(path, mode)
                metadata = path.lstat()
            except OSError as exc:
                raise MediaEvidenceError(
                    "configuration_error",
                    "The evidence store directory could not be created safely",
                ) from exc
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "The evidence store directory could not be inspected safely",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise MediaEvidenceError(
                "configuration_error",
                "The evidence store contains an unsafe directory component",
            )
        if (
            metadata.st_uid != uid
            or (gid is not None and metadata.st_gid != gid)
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The evidence store directory ownership or permissions are unsafe",
            )

    def _validate_fixed_file(self, path: Path, *, mode: int, message: str) -> bool:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        if not path.is_file() or path.is_symlink() or metadata.st_nlink != 1:
            raise MediaEvidenceError("configuration_error", "The evidence store contains an unsafe control file")
        if (
            metadata.st_uid != self.owner_uid
            or (self.control_gid is not None and metadata.st_gid != self.control_gid)
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise MediaEvidenceError("configuration_error", message)
        return True

    def _create_control_file(self, path: Path) -> None:
        try:
            descriptor = os.open(
                path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "Evidence store control file could not be created safely",
            ) from exc
        try:
            os.fchmod(descriptor, 0o600)
            if self.control_gid is not None:
                os.fchown(descriptor, self.owner_uid, self.control_gid)
        finally:
            os.close(descriptor)

    def ensure_worker_directory(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.root / "cas" / "sha256")
        except ValueError as exc:
            raise MediaEvidenceError("configuration_error", "Worker directory is outside the CAS") from exc
        if len(relative.parts) != 1 or relative.parts[0] in {"", ".", ".."}:
            raise MediaEvidenceError("configuration_error", "Worker directory is outside the CAS")
        self._ensure_secure_directory(
            path,
            0o750,
            uid=self.owner_uid,
            gid=self.worker_gid if self.production_identity else None,
        )

    def _set_group(self, path: Path) -> None:
        if self.production_identity:
            assert self.worker_gid is not None
            os.chown(path, self.owner_uid, self.worker_gid)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize_database(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    source_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    manifest_path TEXT,
                    manifest_sha256 TEXT,
                    error_code TEXT,
                    trace_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(job_id)
                );
                CREATE INDEX IF NOT EXISTS events_job_id_idx ON events(job_id, id);
                CREATE TABLE IF NOT EXISTS ledger_heads (
                    job_id TEXT PRIMARY KEY,
                    record_count INTEGER NOT NULL,
                    head_sha256 TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(job_id)
                );
                """
            )

    @contextmanager
    def job_lock(self, job_id: str) -> Iterator[None]:
        with self._control_lock(f"{job_id}.lock", "Evidence job lock is unsafe"):
            yield

    @contextmanager
    def worker_slot(self, resource_class: str) -> Iterator[None]:
        if resource_class not in {"acquisition", "cpu", "gpu", "storage"}:
            raise ValueError("Unknown worker resource class")
        with self._control_lock(
            f"worker-{resource_class}.lock",
            "Evidence worker slot lock is unsafe",
        ):
            yield

    @contextmanager
    def _control_lock(self, name: str, message: str) -> Iterator[None]:
        path = self.root / "locks" / name
        descriptor = self._open_control_descriptor(path, message)
        locked = False
        try:
            self._validate_control_descriptor(path, descriptor, message)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            self._validate_control_descriptor(path, descriptor, message)
        except MediaEvidenceError:
            os.close(descriptor)
            raise
        except OSError as exc:
            os.close(descriptor)
            raise MediaEvidenceError("configuration_error", message) from exc
        try:
            yield
        finally:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _open_control_descriptor(self, path: Path, message: str) -> int:
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            return os.open(path, flags)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        try:
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                return os.open(path, flags)
            except OSError as exc:
                raise MediaEvidenceError("configuration_error", message) from exc
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        try:
            os.fchmod(descriptor, 0o600)
            if self.control_gid is not None:
                os.fchown(descriptor, self.owner_uid, self.control_gid)
        except OSError as exc:
            os.close(descriptor)
            raise MediaEvidenceError("configuration_error", message) from exc
        return descriptor

    def _validate_control_descriptor(self, path: Path, descriptor: int, message: str) -> None:
        try:
            metadata = os.fstat(descriptor)
            path_metadata = path.lstat()
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != self.owner_uid
            or (self.control_gid is not None and metadata.st_gid != self.control_gid)
            or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise MediaEvidenceError("configuration_error", message)

    def _open_capacity_reservation_directory(self) -> int:
        message = "Capacity reservation controls are unsafe"
        try:
            descriptor = os.open(
                self.capacity_reservation_directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            metadata = os.fstat(descriptor)
            path_metadata = self.capacity_reservation_directory.lstat()
        except OSError as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            raise MediaEvidenceError("configuration_error", message) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != self.owner_uid
            or (self.control_gid is not None and metadata.st_gid != self.control_gid)
            or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            os.close(descriptor)
            raise MediaEvidenceError("configuration_error", message)
        return descriptor

    def _capacity_entry_metadata(self, directory_descriptor: int, name: str, descriptor: int) -> os.stat_result:
        message = "Capacity reservation controls are unsafe"
        try:
            metadata = os.fstat(descriptor)
            path_metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != self.owner_uid
            or (self.control_gid is not None and metadata.st_gid != self.control_gid)
            or metadata.st_size > _MAX_CAPACITY_RESERVATION_RECORD_BYTES
            or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise MediaEvidenceError("configuration_error", message)
        return metadata

    def _open_capacity_entry(self, directory_descriptor: int, name: str) -> int:
        message = "Capacity reservation controls are unsafe"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        try:
            self._capacity_entry_metadata(directory_descriptor, name, descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _read_capacity_reservation(descriptor: int, expected_job_id: str) -> dict[str, Any]:
        message = "Capacity reservation control is malformed"
        try:
            before = os.fstat(descriptor)
            if not 1 <= before.st_size <= _MAX_CAPACITY_RESERVATION_RECORD_BYTES:
                raise MediaEvidenceError("configuration_error", message)
            content = os.pread(descriptor, _MAX_CAPACITY_RESERVATION_RECORD_BYTES + 1, 0)
            after = os.fstat(descriptor)
            record = json.loads(content.decode("ascii"))
        except MediaEvidenceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MediaEvidenceError("configuration_error", message) from exc
        if (
            before.st_size != after.st_size
            or len(content) != before.st_size
            or not isinstance(record, dict)
            or set(record) != {"schema", "job_id", "reserved_bytes", "owner_pid"}
            or record.get("schema") != _CAPACITY_RESERVATION_SCHEMA
            or record.get("job_id") != expected_job_id
            or isinstance(record.get("reserved_bytes"), bool)
            or not isinstance(record.get("reserved_bytes"), int)
            or not 1 <= record["reserved_bytes"] <= _MAX_CAPACITY_RESERVATION_BYTES
            or isinstance(record.get("owner_pid"), bool)
            or not isinstance(record.get("owner_pid"), int)
            or record["owner_pid"] <= 0
            or canonical_json_bytes(record) != content
        ):
            raise MediaEvidenceError("configuration_error", message)
        return record

    @staticmethod
    def _capacity_reservation_is_active(descriptor: int) -> bool:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                return True
            raise MediaEvidenceError(
                "configuration_error",
                "Capacity reservation controls are unsafe",
            ) from exc
        return False

    def _unlink_capacity_entry(self, directory_descriptor: int, name: str, descriptor: int) -> None:
        self._capacity_entry_metadata(directory_descriptor, name, descriptor)
        try:
            os.unlink(name, dir_fd=directory_descriptor)
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "Capacity reservation controls are unsafe",
            ) from exc

    def _active_capacity_reservation_bytes_locked(self, directory_descriptor: int) -> int:
        try:
            names = sorted(os.listdir(directory_descriptor))
        except OSError as exc:
            raise MediaEvidenceError(
                "configuration_error",
                "Capacity reservation controls are unsafe",
            ) from exc
        if len(names) > _MAX_CAPACITY_RESERVATIONS:
            raise MediaEvidenceError("configuration_error", "Capacity reservation controls are unsafe")

        total = 0
        removed = False
        for name in names:
            final_match = _CAPACITY_RESERVATION_FILE.fullmatch(name)
            temporary_match = _CAPACITY_RESERVATION_TEMP.fullmatch(name)
            if final_match is None and temporary_match is None:
                raise MediaEvidenceError("configuration_error", "Capacity reservation controls are unsafe")
            descriptor = self._open_capacity_entry(directory_descriptor, name)
            try:
                active = self._capacity_reservation_is_active(descriptor)
                if temporary_match is not None:
                    if active:
                        raise MediaEvidenceError(
                            "configuration_error",
                            "Capacity reservation controls are unsafe",
                        )
                    self._unlink_capacity_entry(directory_descriptor, name, descriptor)
                    removed = True
                    continue

                record = self._read_capacity_reservation(descriptor, final_match.group(1))
                if active:
                    total += record["reserved_bytes"]
                else:
                    self._unlink_capacity_entry(directory_descriptor, name, descriptor)
                    removed = True
            finally:
                os.close(descriptor)
        if removed:
            os.fsync(directory_descriptor)
        return total

    def active_capacity_reservation_bytes(self) -> int:
        with self._control_lock(
            "capacity-reservations.lock",
            "Capacity reservation controls are unsafe",
        ):
            directory_descriptor = self._open_capacity_reservation_directory()
            try:
                return self._active_capacity_reservation_bytes_locked(directory_descriptor)
            finally:
                os.close(directory_descriptor)

    def acquire_capacity_reservation(self, job_id: str, reserved_bytes: int) -> _CapacityReservation:
        if not isinstance(job_id, str) or _CAPACITY_JOB_ID.fullmatch(job_id) is None:
            raise ValueError("Invalid capacity reservation job id")
        if (
            isinstance(reserved_bytes, bool)
            or not isinstance(reserved_bytes, int)
            or not 1 <= reserved_bytes <= _MAX_CAPACITY_RESERVATION_BYTES
        ):
            raise ValueError("Invalid capacity reservation size")

        final_name = f"{job_id}.reservation"
        temporary_name = f".tmp-{job_id}-{secrets.token_hex(16)}.reservation"
        with self._control_lock(
            "capacity-reservations.lock",
            "Capacity reservation controls are unsafe",
        ):
            directory_descriptor = self._open_capacity_reservation_directory()
            descriptor: int | None = None
            published = False
            try:
                self._active_capacity_reservation_bytes_locked(directory_descriptor)
                try:
                    os.stat(final_name, dir_fd=directory_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise MediaEvidenceError(
                        "integrity_failure",
                        "An active capacity reservation already exists for this job",
                    )

                descriptor = os.open(
                    temporary_name,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                os.fchmod(descriptor, 0o600)
                if self.control_gid is not None:
                    os.fchown(descriptor, self.owner_uid, self.control_gid)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                record = {
                    "schema": _CAPACITY_RESERVATION_SCHEMA,
                    "job_id": job_id,
                    "reserved_bytes": reserved_bytes,
                    "owner_pid": os.getpid(),
                }
                view = memoryview(canonical_json_bytes(record))
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "Capacity reservation write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
                self._capacity_entry_metadata(directory_descriptor, temporary_name, descriptor)
                self._read_capacity_reservation(descriptor, job_id)
                os.rename(
                    temporary_name,
                    final_name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                )
                published = True
                self._capacity_entry_metadata(directory_descriptor, final_name, descriptor)
                os.fsync(directory_descriptor)
                reservation = _CapacityReservation(self, final_name, descriptor)
                descriptor = None
                return reservation
            except MediaEvidenceError:
                raise
            except OSError as exc:
                raise MediaEvidenceError(
                    "configuration_error",
                    "Capacity reservation could not be created safely",
                ) from exc
            finally:
                if descriptor is not None:
                    if not published:
                        try:
                            os.unlink(temporary_name, dir_fd=directory_descriptor)
                            os.fsync(directory_descriptor)
                        except FileNotFoundError:
                            pass
                        except OSError:
                            pass
                    os.close(descriptor)
                os.close(directory_descriptor)

    def _release_capacity_reservation(self, name: str, descriptor: int) -> None:
        try:
            with self._control_lock(
                "capacity-reservations.lock",
                "Capacity reservation controls are unsafe",
            ):
                directory_descriptor = self._open_capacity_reservation_directory()
                try:
                    match = _CAPACITY_RESERVATION_FILE.fullmatch(name)
                    if match is None:
                        raise MediaEvidenceError(
                            "configuration_error",
                            "Capacity reservation controls are unsafe",
                        )
                    self._capacity_entry_metadata(directory_descriptor, name, descriptor)
                    self._read_capacity_reservation(descriptor, match.group(1))
                    self._unlink_capacity_entry(directory_descriptor, name, descriptor)
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return dict(row) if row else None

    def begin_job(
        self,
        *,
        job_id: str,
        idempotency_key: str,
        source_sha256: str,
        trace_id: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id, idempotency_key, source_sha256, state, stage,
                    manifest_path, manifest_sha256, error_code, trace_id,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 'running', 'queued', NULL, NULL, NULL, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    state = 'running', stage = 'recovering', manifest_path = NULL,
                    manifest_sha256 = NULL, error_code = NULL, updated_at = excluded.updated_at
                """,
                (job_id, idempotency_key, source_sha256, trace_id, now, now),
            )
        job = self.get_job(job_id)
        assert job is not None
        return job

    def transition(
        self,
        job_id: str,
        *,
        state: str,
        stage: str,
        manifest_path: str | None = None,
        manifest_sha256: str | None = None,
        error_code: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET state = ?, stage = ?, manifest_path = ?, manifest_sha256 = ?,
                    error_code = ?, updated_at = ?
                WHERE job_id = ?
                """,
                (
                    state,
                    stage,
                    manifest_path,
                    manifest_sha256,
                    error_code,
                    now,
                    job_id,
                ),
            )
            connection.execute(
                "INSERT INTO events (job_id, event, detail_json, created_at) VALUES (?, ?, ?, ?)",
                (job_id, stage, canonical_json_bytes(detail or {}).decode("utf-8"), now),
            )

    def _read_signing_key(self) -> bytes | None:
        try:
            descriptor = os.open(self.key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size != 32
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != self.owner_uid
                or (self.control_gid is not None and metadata.st_gid != self.control_gid)
            ):
                raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe")
            key = os.read(descriptor, 33)
        finally:
            os.close(descriptor)
        if len(key) != 32:
            raise MediaEvidenceError("configuration_error", "Manifest signing key has an invalid length")
        return key

    def signing_key(self) -> bytes:
        with self._control_lock("signing-key.lock", "Manifest signing key lock is unsafe"):
            existing = self._read_signing_key()
            if existing is not None:
                return existing

            temporary = self.key_path.with_name(f".{self.key_path.name}.tmp")
            try:
                temporary_metadata = temporary.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe") from exc
            else:
                if (
                    not stat.S_ISREG(temporary_metadata.st_mode)
                    or temporary_metadata.st_nlink != 1
                    or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
                    or temporary_metadata.st_uid != self.owner_uid
                    or (self.control_gid is not None and temporary_metadata.st_gid != self.control_gid)
                ):
                    raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe")
                temporary.unlink()
                self._fsync_control_directory(self.key_path.parent)

            key = secrets.token_bytes(32)
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temporary,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                )
                os.fchmod(descriptor, 0o600)
                if self.control_gid is not None:
                    os.fchown(descriptor, self.owner_uid, self.control_gid)
                view = memoryview(key)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "Signing key write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None
                try:
                    self.key_path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe")
                os.replace(temporary, self.key_path)
                self._fsync_control_directory(self.key_path.parent)
            except MediaEvidenceError:
                raise
            except OSError as exc:
                raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                temporary.unlink(missing_ok=True)

            initialized = self._read_signing_key()
            if initialized is None or not hmac.compare_digest(initialized, key):
                raise MediaEvidenceError("configuration_error", "Manifest signing key is unsafe")
            if stat.S_IMODE(self.key_path.stat().st_mode) != 0o600:
                raise MediaEvidenceError("configuration_error", "Manifest signing key permissions are unsafe")
            return initialized

    @staticmethod
    def _fsync_control_directory(path: Path) -> None:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def append_telemetry(self, event: dict[str, Any]) -> None:
        path = self.root / "telemetry" / "events.jsonl"
        payload = canonical_json_bytes(event) + b"\n"
        if len(payload) > 64 * 1024:
            raise ValueError("Telemetry event exceeds its budget")
        with self._control_lock("telemetry.lock", "Evidence telemetry lock is unsafe"):
            if path.exists() and path.stat().st_size + len(payload) > _TELEMETRY_MAX_BYTES:
                self._rotate_telemetry(path)
            descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_CLOEXEC, 0o640)
            try:
                view = memoryview(payload)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @staticmethod
    def _rotate_telemetry(path: Path) -> None:
        oldest = path.with_name(f"{path.name}.{_TELEMETRY_BACKUPS}")
        oldest.unlink(missing_ok=True)
        for index in range(_TELEMETRY_BACKUPS - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            if source.exists():
                os.replace(source, path.with_name(f"{path.name}.{index + 1}"))
        os.replace(path, path.with_name(f"{path.name}.1"))

    def write_ledger(self, job_id: str, records: list[dict[str, Any]]) -> Path:
        directory = self.root / "ledgers" / job_id
        self._ensure_secure_directory(
            directory,
            0o700,
            uid=self.owner_uid,
            gid=self.control_gid,
        )
        path = directory / "claims.jsonl"
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise MediaEvidenceError("integrity_failure", "Claim ledger is unsafe")
            if metadata.st_size > _LEDGER_MAX_BYTES:
                raise MediaEvidenceError("ledger_limit_exceeded", "Claim ledger has reached its size limit")
            existing = path.read_bytes()
        else:
            existing = b""

        key = self.signing_key()
        previous, count, heads = self._verify_ledger(existing, key)
        with self.connect() as connection:
            stored_head = connection.execute(
                "SELECT record_count, head_sha256 FROM ledger_heads WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if stored_head is None:
            if count:
                raise MediaEvidenceError("integrity_failure", "Claim ledger head is missing")
        else:
            stored_count = int(stored_head["record_count"])
            if stored_count < 0 or stored_count > count or heads[stored_count] != stored_head["head_sha256"]:
                raise MediaEvidenceError("integrity_failure", "Claim ledger rollback was detected")
        if count + len(records) > _LEDGER_MAX_RECORDS:
            raise MediaEvidenceError("ledger_limit_exceeded", "Claim ledger has reached its record limit")
        additions: list[bytes] = []
        key_id = hashlib.sha256(key).hexdigest()[:16]
        for record in records:
            payload = {"record": record, "previous_sha256": previous}
            payload_bytes = canonical_json_bytes(payload)
            envelope = {
                **record,
                "ledger_integrity": {
                    "algorithm": "hmac-sha256-chain",
                    "key_id": key_id,
                    "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                    "previous_sha256": previous,
                    "signature": hmac.new(key, payload_bytes, hashlib.sha256).hexdigest(),
                },
            }
            line = canonical_json_bytes(envelope)
            additions.append(line + b"\n")
            previous = hashlib.sha256(line).hexdigest()
        addition = b"".join(additions)
        if len(existing) + len(addition) > _LEDGER_MAX_BYTES:
            raise MediaEvidenceError("ledger_limit_exceeded", "Claim ledger has reached its size limit")
        atomic_write_bytes(path, existing + addition, mode=0o440)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO ledger_heads (job_id, record_count, head_sha256, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    record_count = excluded.record_count,
                    head_sha256 = excluded.head_sha256,
                    updated_at = excluded.updated_at
                """,
                (job_id, count + len(records), previous, utc_now()),
            )
        return path

    @staticmethod
    def _verify_ledger(content: bytes, key: bytes) -> tuple[str, int, list[str]]:
        previous = _ZERO_DIGEST
        count = 0
        heads = [previous]
        for line in content.splitlines():
            try:
                envelope = json.loads(line)
                integrity = envelope.pop("ledger_integrity")
                payload = {"record": envelope, "previous_sha256": previous}
                payload_bytes = canonical_json_bytes(payload)
                valid = (
                    integrity.get("algorithm") == "hmac-sha256-chain"
                    and hmac.compare_digest(integrity.get("key_id", ""), hashlib.sha256(key).hexdigest()[:16])
                    and hmac.compare_digest(integrity.get("previous_sha256", ""), previous)
                    and hmac.compare_digest(
                        integrity.get("payload_sha256", ""), hashlib.sha256(payload_bytes).hexdigest()
                    )
                    and hmac.compare_digest(
                        integrity.get("signature", ""), hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
                    )
                )
            except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise MediaEvidenceError("integrity_failure", "Claim ledger integrity verification failed") from exc
            if not valid:
                raise MediaEvidenceError("integrity_failure", "Claim ledger integrity verification failed")
            previous = hashlib.sha256(canonical_json_bytes({**envelope, "ledger_integrity": integrity})).hexdigest()
            count += 1
            heads.append(previous)
        return previous, count, heads
