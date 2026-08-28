from __future__ import annotations

import multiprocessing
import grp
import os
import pwd
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from media_evidence.contracts import MediaEvidenceError
from media_evidence.store import EvidenceStore


def _capacity_reservation_process(
    root: str,
    job_id: str,
    reserved_bytes: int,
    ready,
    release,
    crash: bool,
) -> None:
    store = EvidenceStore(Path(root))
    reservation = store.acquire_capacity_reservation(job_id, reserved_bytes)
    ready.set()
    if crash:
        os._exit(0)
    if not release.wait(5):
        os._exit(2)
    reservation.release()


class EvidenceStoreKeyTests(unittest.TestCase):
    def test_preexisting_group_readable_signing_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            root.mkdir(mode=0o710)
            key_directory = root / "keys"
            key_directory.mkdir(mode=0o700)
            key_path = key_directory / "manifest-hmac-v1.key"
            key_path.write_bytes(b"k" * 32)
            key_path.chmod(0o640)

            with self.assertRaisesRegex(MediaEvidenceError, "permissions are unsafe"):
                EvidenceStore(root)

    def test_new_signing_key_has_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            self.assertEqual(len(store.signing_key()), 32)
            self.assertEqual(stat.S_IMODE(store.key_path.stat().st_mode), 0o600)

    def test_signing_key_load_rejects_world_readable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            store.signing_key()
            store.key_path.chmod(0o604)

            with self.assertRaisesRegex(MediaEvidenceError, "signing key is unsafe"):
                store.signing_key()


class EvidenceStoreIdentityPolicyTests(unittest.TestCase):
    def test_production_directory_policy_is_exact(self) -> None:
        root = Path("/evidence")
        policy = EvidenceStore._resolved_directory_policy(
            root,
            owner_uid=0,
            worker_gid=1101,
            acquisition_gid=1102,
            traverse_gid=1103,
        )
        self.assertEqual(
            policy,
            (
                (root, 0, 1103, 0o710),
                (root / "cas", 0, 1101, 0o750),
                (root / "cas" / "sha256", 0, 1101, 0o750),
                (root / "keys", 0, 0, 0o700),
                (root / "locks", 0, 0, 0o700),
                (root / "locks" / "capacity-reservations", 0, 0, 0o700),
                (root / "quarantine", 0, 1102, 0o710),
                (root / "runs", 0, 1101, 0o750),
                (root / "ledgers", 0, 0, 0o700),
                (root / "telemetry", 0, 0, 0o700),
            ),
        )

    def test_unsafe_existing_root_is_rejected_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            root.mkdir(mode=0o750)

            with self.assertRaisesRegex(MediaEvidenceError, "ownership or permissions are unsafe"):
                EvidenceStore(root)

            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o750)

    def test_actual_role_group_traversal_when_privileged(self) -> None:
        if os.geteuid() != 0 or not Path("/usr/bin/setpriv").is_file():
            self.skipTest("root setpriv privileges are unavailable")
        try:
            run_uid = pwd.getpwnam("nobody").pw_uid
        except KeyError:
            self.skipTest("a non-root probe identity is unavailable")
        gids = sorted({entry.gr_gid for entry in grp.getgrall() if entry.gr_gid > 0})
        if len(gids) < 3:
            self.skipTest("three non-root groups are unavailable")
        worker_gid, acquisition_gid, traverse_gid = gids[-3:]

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            base.chmod(0o711)
            root = base / "store"
            store = EvidenceStore(
                root,
                worker_gid=worker_gid,
                acquisition_gid=acquisition_gid,
                traverse_gid=traverse_gid,
            )

            expected = EvidenceStore._resolved_directory_policy(
                root,
                owner_uid=0,
                worker_gid=worker_gid,
                acquisition_gid=acquisition_gid,
                traverse_gid=traverse_gid,
            )
            for path, uid, gid, mode in expected:
                metadata = path.stat()
                self.assertEqual((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)), (uid, gid, mode))
            database = store.database_path.stat()
            self.assertEqual((database.st_uid, database.st_gid, stat.S_IMODE(database.st_mode)), (0, 0, 0o600))

            def probe(primary_gid: int, expression: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        "/usr/bin/setpriv",
                        f"--reuid={run_uid}",
                        f"--regid={primary_gid}",
                        f"--groups={traverse_gid}",
                        "--no-new-privs",
                        "--bounding-set=-all",
                        "--inh-caps=-all",
                        "--ambient-caps=-all",
                        sys.executable,
                        "-c",
                        expression,
                        str(root),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            worker_probe = probe(
                worker_gid,
                "import os,sys; r=sys.argv[1]; ok=(os.access(r,os.X_OK) and "
                "os.access(r+'/cas/sha256',os.R_OK|os.X_OK) and os.access(r+'/runs',os.R_OK|os.X_OK) "
                "and not os.access(r+'/quarantine',os.X_OK) and not os.access(r+'/keys',os.X_OK)); "
                "raise SystemExit(0 if ok else 1)",
            )
            if worker_probe.returncode != 0 and "Operation not permitted" in worker_probe.stderr:
                self.skipTest("setpriv cannot change groups in this environment")
            self.assertEqual(worker_probe.returncode, 0, worker_probe.stderr)

            acquisition_probe = probe(
                acquisition_gid,
                "import os,sys; r=sys.argv[1]; ok=(os.access(r,os.X_OK) and "
                "os.access(r+'/quarantine',os.X_OK) and not os.access(r+'/cas',os.X_OK) "
                "and not os.access(r+'/runs',os.X_OK) and not os.access(r+'/keys',os.X_OK)); "
                "raise SystemExit(0 if ok else 1)",
            )
            self.assertEqual(acquisition_probe.returncode, 0, acquisition_probe.stderr)

    def test_concurrent_first_use_never_publishes_a_partial_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            partial_write = threading.Event()
            resume_write = threading.Event()
            second_finished = threading.Event()
            first_call = True
            call_lock = threading.Lock()
            real_write = os.write
            keys: list[bytes] = []
            errors: list[BaseException] = []

            def delayed_write(descriptor: int, payload: bytes | memoryview) -> int:
                nonlocal first_call
                with call_lock:
                    delay = first_call
                    first_call = False
                if delay:
                    written = real_write(descriptor, payload[:1])
                    partial_write.set()
                    if not resume_write.wait(5):
                        raise TimeoutError("test did not release signing-key write")
                    return written
                return real_write(descriptor, payload)

            def load_key(*, finished: threading.Event | None = None) -> None:
                try:
                    keys.append(store.signing_key())
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    if finished is not None:
                        finished.set()

            with patch("media_evidence.store.os.write", side_effect=delayed_write):
                first = threading.Thread(target=load_key)
                first.start()
                self.assertTrue(partial_write.wait(2))
                second = threading.Thread(target=load_key, kwargs={"finished": second_finished})
                second.start()
                try:
                    self.assertFalse(store.key_path.exists())
                    self.assertFalse(second_finished.wait(0.1))
                finally:
                    resume_write.set()
                first.join(2)
                second.join(2)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(keys), 2)
            self.assertEqual(keys[0], keys[1])
            metadata = store.key_path.stat()
            self.assertEqual(metadata.st_size, 32)
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)


class EvidenceStoreCapacityReservationTests(unittest.TestCase):
    def test_active_reservation_is_visible_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            context = multiprocessing.get_context("fork")
            ready = context.Event()
            release = context.Event()
            process = context.Process(
                target=_capacity_reservation_process,
                args=(str(store.root), f"mev_{'1' * 24}", 4096, ready, release, False),
            )
            process.start()
            self.assertTrue(ready.wait(5))
            try:
                self.assertEqual(store.active_capacity_reservation_bytes(), 4096)
            finally:
                release.set()
                process.join(5)
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(store.active_capacity_reservation_bytes(), 0)

    def test_reservation_is_recovered_after_owner_process_death(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            context = multiprocessing.get_context("fork")
            ready = context.Event()
            release = context.Event()
            process = context.Process(
                target=_capacity_reservation_process,
                args=(str(store.root), f"mev_{'2' * 24}", 8192, ready, release, True),
            )
            process.start()
            self.assertTrue(ready.wait(5))
            process.join(5)
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(len(list(store.capacity_reservation_directory.iterdir())), 1)

            self.assertEqual(store.active_capacity_reservation_bytes(), 0)
            self.assertEqual(list(store.capacity_reservation_directory.iterdir()), [])

    def test_unsafe_and_malformed_reservation_controls_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "store")
            reservation = store.capacity_reservation_directory / f"mev_{'3' * 24}.reservation"
            target = Path(temporary) / "outside"
            target.write_text("outside", encoding="utf-8")
            reservation.symlink_to(target)
            with self.assertRaisesRegex(MediaEvidenceError, "unsafe"):
                store.active_capacity_reservation_bytes()
            reservation.unlink()
            reservation.write_text("{}", encoding="ascii")
            reservation.chmod(0o600)
            with self.assertRaisesRegex(MediaEvidenceError, "malformed"):
                store.active_capacity_reservation_bytes()


if __name__ == "__main__":
    unittest.main()
