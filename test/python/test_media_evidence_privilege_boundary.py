from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from media_evidence.broker import BrokerServer
from media_evidence.store import EvidenceStore


GATEWAY_UID = 23102
GATEWAY_GID = 23102
WORKER_GID = 23100
ACQUISITION_GID = 23101
TRAVERSE_GID = 23103


class StoreBackedPipeline:
    def __init__(self, store: EvidenceStore):
        self.store = store

    def status(self, job_id: str) -> dict[str, object]:
        if len(self.store.signing_key()) != 32:
            raise RuntimeError("signing key is unavailable")
        return {
            "ok": True,
            "job_id": job_id,
            "state": "completed",
            "stage": "published",
            "trace_id": "2" * 32,
            "created_at": "2026-08-28T12:00:00.000Z",
            "updated_at": "2026-08-28T12:00:01.000Z",
        }


GATEWAY_PROBE = r"""
import errno
import json
import os
import sys
from pathlib import Path

from media_evidence.broker_client import BrokerClient


def denied(callback):
    try:
        callback()
    except OSError as exc:
        return exc.errno in {errno.EACCES, errno.EPERM}
    return False


root = Path(sys.argv[1])
socket_path = Path(sys.argv[2])
gateway_gid = int(sys.argv[3])
client = BrokerClient(socket_path=socket_path, gateway_gid=gateway_gid, timeout=5)
health = client.health()
status = client.status("mev_" + "1" * 24)
print(json.dumps({
    "uid": os.geteuid(),
    "gid": os.getegid(),
    "supplementary_groups": os.getgroups(),
    "store_open_denied": denied(lambda: os.open(root, os.O_RDONLY | os.O_DIRECTORY)),
    "store_list_denied": denied(lambda: list(root.iterdir())),
    "key_metadata_denied": denied(lambda: (root / "keys").lstat()),
    "key_read_denied": denied(lambda: (root / "keys" / "manifest-hmac-v1.key").read_bytes()),
    "database_read_denied": denied(lambda: (root / "jobs.sqlite3").read_bytes()),
    "store_write_denied": denied(lambda: (root / "gateway-write-probe").write_bytes(b"denied")),
    "broker_health": health.get("ok") is True and health.get("status") == "ready",
    "broker_store_access": status.get("state") == "completed",
}, sort_keys=True, separators=(",", ":")))
"""


class MediaEvidencePrivilegeBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(
        os.geteuid() == 0 and Path("/usr/bin/setpriv").is_file(),
        "run as root or in a mapped user namespace to exercise production identities",
    )
    def test_gateway_uses_broker_but_cannot_access_evidence_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            base.chmod(0o755)
            # Host-owned ancestors appear as overflow UIDs in an unprivileged user
            # namespace; the production store root and all descendants remain real.
            with mock.patch.object(EvidenceStore, "_validate_store_parent_chain"):
                store = EvidenceStore(
                    base / "store",
                    worker_gid=WORKER_GID,
                    acquisition_gid=ACQUISITION_GID,
                    traverse_gid=TRAVERSE_GID,
                )
            self.assertEqual(len(store.signing_key()), 32)
            server = BrokerServer(
                socket_path=base / "broker" / "broker.sock",
                pipeline=StoreBackedPipeline(store),
                gateway_uid=GATEWAY_UID,
                gateway_gid=GATEWAY_GID,
                request_timeout=5,
            )
            server.start()
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"install_signal_handlers": False},
                daemon=True,
            )
            thread.start()
            try:
                result = subprocess.run(
                    [
                        "/usr/bin/setpriv",
                        f"--reuid={GATEWAY_UID}",
                        f"--regid={GATEWAY_GID}",
                        "--clear-groups",
                        "--no-new-privs",
                        "--bounding-set=-all",
                        "--inh-caps=-all",
                        "--ambient-caps=-all",
                        "--pdeathsig=SIGKILL",
                        sys.executable,
                        "-c",
                        GATEWAY_PROBE,
                        str(store.root),
                        str(server.socket_path),
                        str(GATEWAY_GID),
                    ],
                    cwd=Path(__file__).resolve().parents[2],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                    env={
                        "HOME": "/nonexistent",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONNOUSERSITE": "1",
                    },
                )
            finally:
                server.shutdown()
                thread.join(timeout=2)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["uid"], GATEWAY_UID)
            self.assertEqual(payload["gid"], GATEWAY_GID)
            self.assertEqual(payload["supplementary_groups"], [])
            for field in (
                "store_open_denied",
                "store_list_denied",
                "key_metadata_denied",
                "key_read_denied",
                "database_read_denied",
                "store_write_denied",
                "broker_health",
                "broker_store_access",
            ):
                self.assertIs(payload[field], True, field)


if __name__ == "__main__":
    unittest.main()
