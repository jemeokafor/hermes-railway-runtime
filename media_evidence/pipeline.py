from __future__ import annotations

import errno
import grp
import hashlib
import hmac
import json
import math
import os
import platform
import pwd
import re
import secrets
import shutil
import stat
import struct
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .contracts import (
    PRIVACY_CLASSES,
    RIGHTS_BASES,
    SCHEMA_ID,
    TOOL_VERSION,
    WORKER_SCHEMA_ID,
    MediaEvidenceError,
    atomic_write_json,
    atomic_write_jsonl,
    canonical_json_bytes,
    hash_file,
    normalize_options,
    sha256_bytes,
    sha256_text,
    sign_manifest,
    utc_now,
    validate_manifest_schema,
    verify_manifest,
)
from .extractors import clamav_definition_status, whisper_model_status
from .sandbox import landlock_abi, seccomp_available
from .store import EvidenceStore


WorkerRunner = Callable[[Path, Path, dict[str, Any]], dict[str, Any]]

_JOB_ID = re.compile(r"^mev_[0-9a-f]{24}$")
_SAFE_CODE = re.compile(r"^[a-zA-Z0-9_.:+/-]{1,160}$")
_MAX_ARTIFACTS = 5000
_MAX_EVIDENCE = 20000
_MAX_TEXT_PER_EVIDENCE = 256 * 1024
_MAX_EVIDENCE_TEXT = 64 * 1024 * 1024
_MAX_STRUCTURED_ARTIFACT_BYTES = 72 * 1024 * 1024
_TEXT_EVIDENCE_KINDS = {"frame_ocr", "ocr_text", "page_text", "transcript_segment"}
_EVIDENCE_ARTIFACT_KINDS = {
    "audio_waveform": {"audio_waveform"},
    "frame_ocr": {"frame_ocr"},
    "image_region": {"image_tile", "sanitized_image"},
    "ocr_text": {"ocr_text"},
    "page_image": {"page_image"},
    "page_text": {"native_text"},
    "transcript_segment": {"structured_transcript"},
    "video_frame": {"sampled_frame", "scene_frame"},
}
_EVIDENCE_MEDIA_KINDS = {
    "audio_waveform": {"audio", "video"},
    "frame_ocr": {"video"},
    "image_region": {"image"},
    "ocr_text": {"document", "image"},
    "page_image": {"document"},
    "page_text": {"document"},
    "transcript_segment": {"audio", "video"},
    "video_frame": {"video"},
}


class MediaEvidencePipeline:
    def __init__(
        self,
        *,
        root: Path,
        allowed_roots: list[Path],
        worker_runner: WorkerRunner | None = None,
        require_worker_identity: bool = True,
        worker_user: str = "hermes-media",
        acquisition_user: str = "hermes-acquire",
        traverse_group: str = "hermes-evidence",
        gateway_user: str = "hermes-gateway",
    ):
        configured_root = Path(root).expanduser()
        if not configured_root.is_absolute():
            raise MediaEvidenceError("configuration_error", "The evidence store root must be absolute")
        self.root = Path(os.path.abspath(configured_root))
        self.allowed_roots = [self._validated_input_root(path) for path in allowed_roots]
        if not self.allowed_roots:
            raise MediaEvidenceError("configuration_error", "No media input roots are available")
        if any(
            self.root.is_relative_to(allowed_root) or allowed_root.is_relative_to(self.root)
            for allowed_root in self.allowed_roots
        ):
            raise MediaEvidenceError(
                "configuration_error",
                "The evidence store and media input roots must not overlap",
            )

        self.require_worker_identity = require_worker_identity
        self.worker_uid: int | None = None
        self.worker_gid: int | None = None
        self.acquisition_uid: int | None = None
        self.acquisition_gid: int | None = None
        self.traverse_gid: int | None = None
        if require_worker_identity:
            if os.geteuid() != 0:
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    "Dedicated media identities require a root orchestrator",
                )
            try:
                identity = pwd.getpwnam(worker_user)
                acquisition_identity = pwd.getpwnam(acquisition_user)
                traverse_identity = grp.getgrnam(traverse_group)
                gateway_identity = pwd.getpwnam(gateway_user)
            except KeyError as exc:
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    "A dedicated media identity or evidence traverse group is unavailable",
                ) from exc
            self.worker_uid = identity.pw_uid
            self.worker_gid = identity.pw_gid
            self.acquisition_uid = acquisition_identity.pw_uid
            self.acquisition_gid = acquisition_identity.pw_gid
            self.traverse_gid = traverse_identity.gr_gid
            gateway_uid = gateway_identity.pw_uid
            gateway_gid = gateway_identity.pw_gid
            if (
                0
                in {
                    self.worker_uid,
                    self.worker_gid,
                    self.acquisition_uid,
                    self.acquisition_gid,
                    self.traverse_gid,
                    gateway_uid,
                    gateway_gid,
                }
                or len({self.worker_uid, self.acquisition_uid, gateway_uid}) != 3
                or len({self.worker_gid, self.acquisition_gid, gateway_gid, self.traverse_gid}) != 4
                or self.traverse_gid in {self.worker_gid, self.acquisition_gid, gateway_gid}
            ):
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    "Media identities, gateway identity, and the evidence traverse group must be distinct and non-root",
                )
            if (
                gateway_gid == self.traverse_gid
                or gateway_identity.pw_name in getattr(traverse_identity, "gr_mem", ())
            ):
                raise MediaEvidenceError(
                    "sandbox_unavailable",
                    "The gateway must not be a member of the evidence traverse group",
                )

        self.store = EvidenceStore(
            self.root,
            worker_gid=self.worker_gid,
            acquisition_gid=self.acquisition_gid,
            traverse_gid=self.traverse_gid,
        )
        if worker_runner is None:
            from .worker_client import WorkerClient

            self.worker_runner = WorkerClient(
                worker_uid=self.worker_uid,
                worker_gid=self.worker_gid,
                traverse_gid=self.traverse_gid,
                require_identity=require_worker_identity,
            )
        else:
            self.worker_runner = worker_runner

    @staticmethod
    def _validated_input_root(raw_path: Path) -> Path:
        configured = Path(raw_path).expanduser()
        if not configured.is_absolute():
            raise MediaEvidenceError("configuration_error", "Media input roots must be absolute")
        candidate = Path(os.path.abspath(configured))
        if candidate == Path(candidate.anchor):
            raise MediaEvidenceError("configuration_error", "The filesystem root cannot be a media input root")
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise MediaEvidenceError("configuration_error", "A media input root is unavailable") from exc
            if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise MediaEvidenceError("configuration_error", "A media input root is unsafe")
        return candidate

    def analyze(
        self,
        *,
        source_path: str | None = None,
        source_url: str | None = None,
        allow_network_acquisition: bool = False,
        rights_basis: str,
        privacy: str,
        purpose: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if rights_basis not in RIGHTS_BASES:
            raise MediaEvidenceError("invalid_arguments", "rights_basis is invalid")
        if privacy not in PRIVACY_CLASSES:
            raise MediaEvidenceError("invalid_arguments", "privacy is invalid")
        if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 1024:
            raise MediaEvidenceError("invalid_arguments", "purpose must contain 1 to 1024 characters")
        if bool(source_path) == bool(source_url):
            raise MediaEvidenceError("invalid_arguments", "Provide exactly one of source_path or source_url")
        if options is None:
            raw_options: dict[str, Any] = {}
        elif isinstance(options, dict):
            raw_options = dict(options)
        else:
            raise MediaEvidenceError("invalid_arguments", "options must be an object")
        if source_url and isinstance(raw_options, dict):
            if raw_options.get("scan_policy", "required") != "required":
                raise MediaEvidenceError(
                    "invalid_arguments",
                    "Remote acquisition requires scan_policy=required",
                )
            raw_options["scan_policy"] = "required"
        normalized_options = normalize_options(raw_options)
        scanner_status = clamav_definition_status()
        scanner_revision = {
            key: scanner_status[key]
            for key in ("status", "file", "bytes", "mtime_ns", "sha256")
        }
        if source_url:
            if allow_network_acquisition is not True:
                raise MediaEvidenceError(
                    "network_consent_required",
                    "Remote acquisition requires allow_network_acquisition=true",
                )
            with self.store.worker_slot("storage"):
                source = self._ingest_https_source(source_url, normalized_options["max_source_bytes"])
        else:
            with self.store.worker_slot("storage"):
                source = self._ingest_local_source(source_path or "", normalized_options["max_source_bytes"])
        purpose_identifier = sha256_text(purpose.strip())
        if privacy != "public":
            source = dict(source)
            for field in ("name_sha256", "source_uri_sha256", "final_uri_sha256"):
                if isinstance(source.get(field), str):
                    source[field] = self._private_identifier(field, source[field])
            source["final_origin"] = None
            purpose_identifier = self._private_identifier("purpose", sha256_text(purpose.strip()))
        parameters = {
            "schema": SCHEMA_ID,
            "tool_version": TOOL_VERSION,
            "source_sha256": source["sha256"],
            "acquisition_adapter": source["adapter"],
            "source_uri_sha256": source["source_uri_sha256"],
            "rights_basis": rights_basis,
            "privacy": privacy,
            "purpose_sha256": purpose_identifier,
            "options": normalized_options,
            "scanner_revision": scanner_revision if normalized_options["scan_policy"] == "required" else None,
        }
        idempotency_key = sha256_bytes(canonical_json_bytes(parameters))
        job_id = f"mev_{idempotency_key[:24]}"

        with self.store.job_lock(job_id):
            existing = self.store.get_job(job_id)
            if existing and (
                existing["idempotency_key"] != idempotency_key or existing["source_sha256"] != source["sha256"]
            ):
                raise MediaEvidenceError("integrity_failure", "Stored job identity does not match the request")
            if existing and existing["state"] == "completed":
                return self._cached_response(existing, source["sha256"])
            recovered = self._recover_published_run(
                job_id=job_id,
                existing=existing,
                idempotency_key=idempotency_key,
                source_sha256=source["sha256"],
            )
            if recovered is not None:
                return self._cached_response(recovered, source["sha256"])

            return self._run_new_job(
                job_id=job_id,
                existing=existing,
                idempotency_key=idempotency_key,
                source=source,
                rights_basis=rights_basis,
                privacy=privacy,
                purpose_sha256=parameters["purpose_sha256"],
                options=normalized_options,
                scanner_revision=scanner_revision,
            )

    def _run_new_job(
        self,
        *,
        job_id: str,
        existing: dict[str, Any] | None,
        idempotency_key: str,
        source: dict[str, Any],
        rights_basis: str,
        privacy: str,
        purpose_sha256: str,
        options: dict[str, Any],
        scanner_revision: dict[str, Any],
    ) -> dict[str, Any]:
        trace_id = existing["trace_id"] if existing else secrets.token_hex(16)
        span_id = secrets.token_hex(8)
        job = self.store.begin_job(
            job_id=job_id,
            idempotency_key=idempotency_key,
            source_sha256=source["sha256"],
            trace_id=trace_id,
        )
        stage: Path | None = None
        capacity_reservation = None
        queue_entered = time.monotonic()
        started = queue_entered
        try:
            self.store.transition(job_id, state="running", stage="waiting_worker")
            with self.store.worker_slot("cpu"):
                queue_wait_ms = max(0, int((time.monotonic() - queue_entered) * 1000))
                with self.store.worker_slot("storage"):
                    self._remove_stale_stages(job_id)
                    self._ensure_storage_capacity(options["max_output_bytes"])
                    capacity_reservation = self.store.acquire_capacity_reservation(
                        job_id,
                        options["max_output_bytes"],
                    )
                    stage = Path(tempfile.mkdtemp(prefix=f".tmp-{job_id}-", dir=self.root / "runs"))
                self.store.transition(job_id, state="running", stage="extracting")
                worker_result = self.worker_runner(source["cas_path"], stage, options)
            self.store.transition(job_id, state="running", stage="validating")
            result = self._publish_run(
                stage=stage,
                job=job,
                idempotency_key=idempotency_key,
                source=source,
                rights_basis=rights_basis,
                privacy=privacy,
                purpose_sha256=purpose_sha256,
                options=options,
                worker_result=worker_result,
                scanner_revision=scanner_revision,
                queue_wait_ms=queue_wait_ms,
                duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            )
        except BaseException as exc:
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)
            code = exc.code if isinstance(exc, MediaEvidenceError) else "internal_error"
            self.store.transition(
                job_id,
                state="failed",
                stage="failed",
                error_code=code,
            )
            self._append_telemetry_best_effort(
                {
                    "schema": "media-evidence-telemetry/v1",
                    "event": "job_failed",
                    "job_id": job_id,
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "error_code": code,
                    "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
                    "created_at": utc_now(),
                }
            )
            if isinstance(exc, MediaEvidenceError):
                raise
            raise MediaEvidenceError("internal_error", "Media extraction failed unexpectedly") from exc
        finally:
            if capacity_reservation is not None:
                capacity_reservation.release()

        self._append_telemetry_best_effort(
            {
                "schema": "media-evidence-telemetry/v1",
                "event": "job_completed",
                "job_id": job_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "media_kind": result["media_kind"],
                "queue_wait_ms": result["queue_wait_ms"],
                "duration_ms": result["duration_ms"],
                "created_at": utc_now(),
            }
        )
        return result

    def status(self, job_id: str) -> dict[str, Any]:
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise MediaEvidenceError("invalid_arguments", "job_id is invalid")
        job = self.store.get_job(job_id)
        if not job:
            raise MediaEvidenceError("job_not_found", "Media evidence job was not found")
        if job["state"] != "completed":
            with self.store.job_lock(job_id):
                job = self.store.get_job(job_id)
                if job is None:
                    raise MediaEvidenceError("job_not_found", "Media evidence job was not found")
                recovered = self._recover_published_run(
                    job_id=job_id,
                    existing=job,
                    idempotency_key=job["idempotency_key"],
                    source_sha256=job["source_sha256"],
                )
                if recovered is not None:
                    job = recovered
        response = {
            "ok": True,
            "job_id": job_id,
            "state": job["state"],
            "stage": job["stage"],
            "trace_id": job["trace_id"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
        }
        if job["state"] == "completed":
            manifest_path = Path(job["manifest_path"] or "")
            manifest = self._load_verified_manifest(manifest_path)
            manifest_sha256, _ = hash_file(manifest_path)
            if manifest["job"]["id"] != job_id or manifest_sha256 != job["manifest_sha256"]:
                raise MediaEvidenceError("integrity_failure", "Completed job metadata failed verification")
            self._verify_manifest_artifacts(manifest_path, manifest)
            self._verify_frozen_tree(manifest_path.parent)
            response["manifest_path"] = str(manifest_path)
        if job["error_code"]:
            response["error_code"] = job["error_code"]
        return response

    def capabilities(self) -> dict[str, Any]:
        aggregate_limits = getattr(self.worker_runner, "aggregate_limits_available", None)
        binaries = {
            name: path if Path(path).is_file() and os.access(path, os.X_OK) else None
            for name, path in {
                "clamscan": "/usr/bin/clamscan",
                "exiftool": "/usr/bin/exiftool",
                "ffmpeg": "/usr/bin/ffmpeg",
                "ffprobe": "/usr/bin/ffprobe",
                "file": "/usr/bin/file",
                "pdfinfo": "/usr/bin/pdfinfo",
                "pdftoppm": "/usr/bin/pdftoppm",
                "pdftotext": "/usr/bin/pdftotext",
                "qpdf": "/usr/bin/qpdf",
                "tesseract": "/usr/bin/tesseract",
            }.items()
        }
        return {
            "ok": True,
            "schema": SCHEMA_ID,
            "tool_version": TOOL_VERSION,
            "media_kinds": ["audio", "document", "image", "video"],
            "source_adapters": ["https", "local"],
            "cloud_egress": "denied",
            "sandbox": {
                "seccomp": seccomp_available(),
                "landlock_abi": landlock_abi(),
                "dedicated_identity": self.worker_uid is not None,
                "dedicated_acquisition_identity": self.acquisition_uid is not None,
                "aggregate_resource_limits": bool(
                    self.require_worker_identity
                    and callable(aggregate_limits)
                    and aggregate_limits()
                ),
            },
            "malware_scanner": clamav_definition_status(),
            "transcription_model": whisper_model_status("base.en"),
            "binaries": binaries,
        }

    def validate_claims(self, *, job_id: str, claims: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise MediaEvidenceError("invalid_arguments", "job_id is invalid")
        if not isinstance(claims, list) or not 1 <= len(claims) <= 100:
            raise MediaEvidenceError("invalid_arguments", "claims must contain 1 to 100 entries")

        with self.store.job_lock(job_id):
            job = self.store.get_job(job_id)
            if not job or job["state"] != "completed":
                raise MediaEvidenceError("job_not_ready", "Media evidence job is not completed")
            manifest_path = Path(job["manifest_path"])
            manifest = self._load_verified_manifest(manifest_path)
            manifest_sha256, _ = hash_file(manifest_path)
            if manifest["job"]["id"] != job_id or manifest_sha256 != job["manifest_sha256"]:
                raise MediaEvidenceError("integrity_failure", "Completed job metadata failed verification")
            index_artifact = next(
                (
                    artifact
                    for artifact in manifest["artifacts"]
                    if artifact["id"] == manifest["evidence"]["index_artifact_id"]
                    and artifact["kind"] == "evidence_index"
                ),
                None,
            )
            if not index_artifact:
                raise MediaEvidenceError("integrity_failure", "Evidence index is missing")
            self._verify_manifest_artifacts(manifest_path, manifest, {index_artifact["id"]})
            self._verify_frozen_tree(manifest_path.parent)
            index_path = self._manifest_artifact_path(manifest_path.parent, index_artifact["path"])
            evidence: dict[str, dict[str, Any]] = {}
            for line in index_path.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                evidence[record["evidence_id"]] = record

            accepted = 0
            rejected = 0
            ledger_records: list[dict[str, Any]] = []
            for raw_claim in claims:
                record, valid = self._validate_claim(raw_claim, evidence, job_id)
                ledger_records.append(record)
                if valid:
                    accepted += 1
                else:
                    rejected += 1
            cited_artifacts = {
                evidence[evidence_id]["artifact_id"]
                for record in ledger_records
                for evidence_id in record["evidence_ids"]
                if evidence_id in evidence
            }
            self._verify_manifest_artifacts(manifest_path, manifest, cited_artifacts)
            ledger_path = self.store.write_ledger(job_id, ledger_records)
            ledger_sha256, _ = hash_file(ledger_path)
            self._append_telemetry_best_effort(
                {
                    "schema": "media-evidence-telemetry/v1",
                    "event": "claims_validated",
                    "job_id": job_id,
                    "accepted": accepted,
                    "rejected": rejected,
                    "created_at": utc_now(),
                }
            )
            return {
                "ok": rejected == 0,
                "job_id": job_id,
                "accepted": accepted,
                "rejected": rejected,
                "ledger_path": str(ledger_path),
                "ledger_sha256": ledger_sha256,
            }

    def _append_telemetry_best_effort(self, event: dict[str, Any]) -> None:
        try:
            self.store.append_telemetry(event)
        except Exception:
            pass

    def _ingest_local_source(self, raw_path: str, max_bytes: int) -> dict[str, Any]:
        if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
            raise MediaEvidenceError("invalid_arguments", "source_path is invalid")
        requested = Path(os.path.abspath(os.path.expanduser(raw_path.strip())))
        try:
            requested.relative_to(self.root)
        except ValueError:
            pass
        else:
            raise MediaEvidenceError("source_not_allowed", "The evidence store cannot be used as an input root")

        selected_root: Path | None = None
        relative: Path | None = None
        for allowed_root in self.allowed_roots:
            try:
                candidate = requested.relative_to(allowed_root)
            except ValueError:
                continue
            if candidate.parts and all(part not in {"", ".", ".."} for part in candidate.parts):
                selected_root = allowed_root
                relative = candidate
                break
        if selected_root is None or relative is None:
            raise MediaEvidenceError("source_not_allowed", "source_path is outside the allowed roots")

        descriptor = self._open_beneath(selected_root, relative)
        temporary = self.root / "quarantine" / f".ingest-{secrets.token_hex(16)}"
        digest = hashlib.sha256()
        copied = 0
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise MediaEvidenceError("source_not_regular", "source_path is not a regular file")
            if before.st_size <= 0:
                raise MediaEvidenceError("source_empty", "source_path is empty")
            if before.st_size > max_bytes:
                raise MediaEvidenceError("source_too_large", "source_path exceeds the configured byte limit")
            self._ensure_storage_capacity(before.st_size)
            output_fd = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
                0o600,
            )
            try:
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > max_bytes:
                        raise MediaEvidenceError("source_too_large", "source_path exceeded the byte limit while reading")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(output_fd, view)
                        view = view[written:]
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
            after = os.fstat(descriptor)
            if (
                copied != before.st_size
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
                or after.st_ino != before.st_ino
                or after.st_dev != before.st_dev
                or after.st_mode != before.st_mode
                or after.st_nlink != before.st_nlink
            ):
                raise MediaEvidenceError("source_changed", "source_path changed while it was being ingested")
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            os.close(descriptor)

        source_sha256 = digest.hexdigest()
        cas_path = self._promote_to_cas(temporary, source_sha256, copied)
        return {
            "sha256": source_sha256,
            "bytes": copied,
            "cas_path": cas_path,
            "adapter": "local",
            "network_used": False,
            "redirects": 0,
            "final_origin": None,
            "name_sha256": sha256_text(relative.name),
            "declared_suffix": requested.suffix.lower()[:32],
            "source_uri_sha256": sha256_text(f"local:{requested}"),
            "final_uri_sha256": None,
            "retrieved_at": utc_now(),
        }

    def _ingest_https_source(self, source_url: str, max_bytes: int) -> dict[str, Any]:
        from .acquire import SecureHttpsAcquirer

        temporary = self.root / "quarantine" / f"remote-{secrets.token_hex(16)}.download"
        try:
            available = self._available_growth_bytes()
            if available < 1:
                raise MediaEvidenceError("storage_pressure", "Evidence storage has insufficient free space")
            effective_max = min(max_bytes, available)
            metadata = SecureHttpsAcquirer(
                run_uid=self.acquisition_uid,
                run_gid=self.acquisition_gid,
                traverse_gid=self.traverse_gid,
            ).acquire(source_url, temporary, max_bytes=effective_max)
            source_sha256, size = hash_file(temporary)
            if size <= 0 or size > max_bytes:
                raise MediaEvidenceError("source_too_large", "Remote source violates the byte budget")
            cas_path = self._promote_to_cas(temporary, source_sha256, size)
            return {
                **metadata,
                "sha256": source_sha256,
                "bytes": size,
                "cas_path": cas_path,
            }
        finally:
            temporary.unlink(missing_ok=True)
            temporary.with_suffix(".headers").unlink(missing_ok=True)
            temporary.with_suffix(".body").unlink(missing_ok=True)

    def _promote_to_cas(self, temporary: Path, source_sha256: str, size: int) -> Path:
        cas_path = self.root / "cas" / "sha256" / source_sha256[:2] / source_sha256
        parent_existed = cas_path.parent.exists()
        self.store.ensure_worker_directory(cas_path.parent)
        reused = False
        try:
            os.link(temporary, cas_path)
        except FileExistsError:
            reused = True
            existing_digest, existing_size = hash_file(cas_path)
            if existing_digest != source_sha256 or existing_size != size:
                raise MediaEvidenceError("integrity_failure", "Existing CAS object failed verification")
        finally:
            temporary.unlink(missing_ok=True)
        if not reused:
            os.chmod(cas_path, 0o440)
            self.store._set_group(cas_path)
        descriptor = os.open(cas_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode) and reused and metadata.st_nlink > 1:
                self._remove_orphaned_quarantine_links(metadata)
                metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o440
                or metadata.st_uid != self.store.owner_uid
                or (
                    self.store.production_identity
                    and self.worker_gid is not None
                    and metadata.st_gid != self.worker_gid
                )
            ):
                raise MediaEvidenceError("integrity_failure", "CAS object is unsafe")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_directory(cas_path.parent)
        if not parent_existed:
            self._fsync_directory(cas_path.parent.parent)
        return cas_path

    def _remove_orphaned_quarantine_links(self, cas_metadata: os.stat_result) -> None:
        removed = False
        try:
            candidates = list((self.root / "quarantine").iterdir())
        except OSError as exc:
            raise MediaEvidenceError("integrity_failure", "Quarantine recovery failed") from exc
        for candidate in candidates:
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise MediaEvidenceError("integrity_failure", "Quarantine recovery failed") from exc
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_dev == cas_metadata.st_dev
                and metadata.st_ino == cas_metadata.st_ino
            ):
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise MediaEvidenceError("integrity_failure", "Quarantine recovery failed") from exc
                removed = True
        if removed:
            self._fsync_directory(self.root / "quarantine")

    def _available_growth_bytes(self) -> int:
        usage = shutil.disk_usage(self.root)
        try:
            configured_reserve = int(os.getenv("MEDIA_EVIDENCE_MIN_FREE_BYTES", str(512 * 1024 * 1024)))
        except ValueError as exc:
            raise MediaEvidenceError("configuration_error", "MEDIA_EVIDENCE_MIN_FREE_BYTES is invalid") from exc
        if not 64 * 1024 * 1024 <= configured_reserve <= 50 * 1024 * 1024 * 1024:
            raise MediaEvidenceError("configuration_error", "MEDIA_EVIDENCE_MIN_FREE_BYTES is out of range")
        reserve = max(configured_reserve, min(2 * 1024 * 1024 * 1024, usage.total // 10))
        active_reservations = self.store.active_capacity_reservation_bytes()
        return max(0, usage.free - reserve - active_reservations)

    def _private_identifier(self, domain: str, value: str) -> str:
        payload = f"media-evidence/v1:{domain}:{value}".encode("ascii")
        return hmac.new(self.store.signing_key(), payload, hashlib.sha256).hexdigest()

    def _ensure_storage_capacity(self, required_bytes: int) -> None:
        if required_bytes > self._available_growth_bytes():
            raise MediaEvidenceError(
                "storage_pressure",
                "Evidence storage cannot preserve its required free-space reserve",
            )

    @staticmethod
    def _open_beneath(root: Path, relative: Path) -> int:
        flags_directory = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        current = os.open(root, flags_directory)
        try:
            for part in relative.parts[:-1]:
                next_descriptor = os.open(part, flags_directory, dir_fd=current)
                os.close(current)
                current = next_descriptor
            try:
                descriptor = os.open(
                    relative.parts[-1],
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=current,
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise MediaEvidenceError(
                        "source_symlink_rejected",
                        "source_path contains a symbolic link",
                    ) from exc
                raise MediaEvidenceError("source_unreadable", "source_path could not be opened") from exc
            return descriptor
        except MediaEvidenceError:
            raise
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise MediaEvidenceError(
                    "source_symlink_rejected",
                    "source_path contains a symbolic link",
                ) from exc
            raise MediaEvidenceError("source_unreadable", "source_path could not be opened") from exc
        finally:
            os.close(current)

    def _cached_response(self, job: dict[str, Any], source_sha256: str) -> dict[str, Any]:
        manifest_path = Path(job["manifest_path"] or "")
        manifest = self._load_verified_manifest(manifest_path)
        manifest_sha256, _ = hash_file(manifest_path)
        if (
            manifest["job"]["id"] != job["job_id"]
            or manifest["job"]["idempotency_key"] != job["idempotency_key"]
            or manifest["source"]["sha256"] != source_sha256
            or manifest_sha256 != job["manifest_sha256"]
        ):
            raise MediaEvidenceError("integrity_failure", "Cached run metadata does not match its manifest")
        if manifest["execution"]["parameters"].get("scan_policy") == "required":
            current = clamav_definition_status()
            current_revision = {
                key: current.get(key)
                for key in ("status", "file", "bytes", "mtime_ns", "sha256")
            }
            if current.get("status") != "current" or current_revision != manifest["execution"]["scanner_revision"]:
                raise MediaEvidenceError(
                    "scanner_definitions_invalid",
                    "Required malware definitions changed or are no longer current",
                )
        self._verify_manifest_artifacts(manifest_path, manifest)
        self._verify_frozen_tree(manifest_path.parent)
        return {
            "ok": True,
            "cached": True,
            "job_id": job["job_id"],
            "trace_id": job["trace_id"],
            "source_sha256": source_sha256,
            "media_kind": manifest["source"]["media_kind"],
            "quality_tier": manifest["quality"]["tier"],
            "evidence_count": manifest["evidence"]["count"],
            "manifest_path": str(manifest_path),
            "duration_ms": manifest["execution"]["duration_ms"],
            "queue_wait_ms": manifest["execution"]["queue_wait_ms"],
        }

    def _recover_published_run(
        self,
        *,
        job_id: str,
        existing: dict[str, Any] | None,
        idempotency_key: str,
        source_sha256: str,
    ) -> dict[str, Any] | None:
        final = self.root / "runs" / job_id
        if not final.exists() and not final.is_symlink():
            return None
        try:
            metadata = final.lstat()
        except OSError as exc:
            raise MediaEvidenceError("integrity_failure", "Published run path could not be inspected") from exc
        if final.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise MediaEvidenceError("integrity_failure", "Published run path is invalid")

        manifest_path = final / "manifest.json"
        manifest = self._load_verified_manifest(manifest_path)
        if (
            manifest["job"]["id"] != job_id
            or manifest["job"]["idempotency_key"] != idempotency_key
            or manifest["source"]["sha256"] != source_sha256
        ):
            raise MediaEvidenceError("integrity_failure", "Published run identity failed verification")
        self._verify_manifest_artifacts(manifest_path, manifest)
        self._verify_frozen_tree(manifest_path.parent)
        manifest_sha256, _ = hash_file(manifest_path)
        if existing is None:
            existing = self.store.begin_job(
                job_id=job_id,
                idempotency_key=idempotency_key,
                source_sha256=source_sha256,
                trace_id=manifest["job"]["trace_id"],
            )
        self.store.transition(
            job_id,
            state="completed",
            stage="recovered_published",
            manifest_path=str(manifest_path),
            manifest_sha256=manifest_sha256,
            detail={"recovered": True},
        )
        recovered = self.store.get_job(job_id)
        if recovered is None:
            raise MediaEvidenceError("integrity_failure", "Published run recovery was not durable")
        self._append_telemetry_best_effort(
            {
                "schema": "media-evidence-telemetry/v1",
                "event": "job_recovered",
                "job_id": job_id,
                "trace_id": recovered["trace_id"],
                "created_at": utc_now(),
            }
        )
        return recovered

    def _load_verified_manifest(self, path: Path) -> dict[str, Any]:
        try:
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 8 * 1024 * 1024
            ):
                raise OSError
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MediaEvidenceError("integrity_failure", "Manifest is missing or invalid") from exc
        if not verify_manifest(manifest, self.store.key_path):
            raise MediaEvidenceError("integrity_failure", "Manifest signature verification failed")
        try:
            validate_manifest_schema(manifest)
        except MediaEvidenceError as exc:
            raise MediaEvidenceError("integrity_failure", "Manifest failed contract validation") from exc
        return manifest

    def _remove_stale_stages(self, job_id: str) -> None:
        for path in (self.root / "runs").glob(f".tmp-{job_id}-*"):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)

    def _publish_run(
        self,
        *,
        stage: Path,
        job: dict[str, Any],
        idempotency_key: str,
        source: dict[str, Any],
        rights_basis: str,
        privacy: str,
        purpose_sha256: str,
        options: dict[str, Any],
        worker_result: dict[str, Any],
        scanner_revision: dict[str, Any],
        queue_wait_ms: int,
        duration_ms: int,
    ) -> dict[str, Any]:
        if not isinstance(worker_result, dict) or worker_result.get("schema") != WORKER_SCHEMA_ID:
            raise MediaEvidenceError("worker_contract_error", "Worker returned an invalid contract")
        actual_mime = self._safe_code(worker_result.get("actual_mime"), "actual_mime")
        media_kind = worker_result.get("media_kind")
        if media_kind not in {"audio", "document", "image", "video"}:
            raise MediaEvidenceError("worker_contract_error", "Worker returned an invalid media kind")

        raw_artifacts = worker_result.get("artifacts")
        raw_evidence = worker_result.get("evidence")
        coverage = worker_result.get("coverage", {})
        if not isinstance(raw_artifacts, list) or not 1 <= len(raw_artifacts) <= _MAX_ARTIFACTS:
            raise MediaEvidenceError("worker_contract_error", "Worker returned an invalid artifact list")
        if not isinstance(raw_evidence, list) or not 1 <= len(raw_evidence) <= _MAX_EVIDENCE:
            raise MediaEvidenceError("worker_contract_error", "Worker returned an invalid evidence list")
        if not isinstance(coverage, dict):
            raise MediaEvidenceError("worker_contract_error", "Worker coverage is invalid")
        self._validate_safe_metadata(coverage)

        actual_files = self._enumerate_stage_files(stage, options["max_output_bytes"])
        declared_paths: set[str] = set()
        artifacts: list[dict[str, Any]] = []
        artifact_by_path: dict[str, dict[str, Any]] = {}
        for raw in raw_artifacts:
            if not isinstance(raw, dict):
                raise MediaEvidenceError("worker_contract_error", "Worker artifact entry is invalid")
            relative = self._safe_worker_artifact_path(raw.get("path"))
            if relative in declared_paths:
                raise MediaEvidenceError("worker_contract_error", "Worker declared a duplicate artifact path")
            declared_paths.add(relative)
            path = self._stage_artifact_path(stage, relative)
            digest, size = hash_file(path)
            artifact = {
                "id": f"artifact:sha256:{digest}",
                "kind": self._safe_code(raw.get("kind"), "artifact kind"),
                "path": relative,
                "sha256": digest,
                "bytes": size,
                "media_type": self._safe_code(raw.get("media_type"), "artifact media type"),
            }
            artifacts.append(artifact)
            artifact_by_path[relative] = artifact
        if actual_files != declared_paths:
            raise MediaEvidenceError(
                "worker_contract_error",
                "Worker output contained undeclared or missing files",
            )

        structured_cache: dict[str, list[dict[str, Any]]] = {}
        self._verify_worker_coverage(
            stage=stage,
            artifacts=artifacts,
            media_kind=media_kind,
            coverage=coverage,
            cache=structured_cache,
        )

        evidence_records: list[dict[str, Any]] = []
        evidence_ids: set[str] = set()
        total_text = 0
        for raw in raw_evidence:
            if not isinstance(raw, dict):
                raise MediaEvidenceError("worker_contract_error", "Worker evidence entry is invalid")
            artifact_path = self._safe_worker_artifact_path(raw.get("artifact_path"))
            artifact = artifact_by_path.get(artifact_path)
            if artifact is None:
                raise MediaEvidenceError("worker_contract_error", "Evidence references an unknown artifact")
            kind = self._safe_code(raw.get("kind"), "evidence kind")
            anchor = raw.get("anchor")
            if not isinstance(anchor, dict) or not anchor or len(canonical_json_bytes(anchor)) > 4096:
                raise MediaEvidenceError("worker_contract_error", "Evidence anchor is invalid")
            self._validate_safe_metadata(anchor)
            text = raw.get("text")
            if text is not None:
                if not isinstance(text, str) or len(text.encode("utf-8")) > _MAX_TEXT_PER_EVIDENCE:
                    raise MediaEvidenceError("worker_contract_error", "Evidence text exceeds its limit")
                total_text += len(text.encode("utf-8"))
                if total_text > _MAX_EVIDENCE_TEXT:
                    raise MediaEvidenceError("worker_contract_error", "Combined evidence text exceeds its limit")
                content_sha256 = sha256_text(text)
            else:
                content_sha256 = artifact["sha256"]
            self._validate_evidence_anchor(
                kind=kind,
                anchor=anchor,
                artifact_kind=artifact["kind"],
                media_kind=media_kind,
                coverage=coverage,
                text=text,
            )
            if kind in _TEXT_EVIDENCE_KINDS:
                self._verify_text_evidence(
                    stage=stage,
                    artifact=artifact,
                    kind=kind,
                    anchor=anchor,
                    text=text or "",
                    cache=structured_cache,
                )
            identity = {
                "job_id": job["job_id"],
                "kind": kind,
                "artifact_id": artifact["id"],
                "anchor": anchor,
                "content_sha256": content_sha256,
            }
            evidence_id = f"ev:{kind}:{sha256_bytes(canonical_json_bytes(identity))[:24]}"
            if evidence_id in evidence_ids:
                raise MediaEvidenceError("worker_contract_error", "Worker returned duplicate evidence")
            evidence_ids.add(evidence_id)
            record = {
                "evidence_id": evidence_id,
                "kind": kind,
                "artifact_id": artifact["id"],
                "anchor": anchor,
                "content_sha256": content_sha256,
                "trust": "untrusted",
                "instructional_text": False,
            }
            if text is not None:
                record["text"] = text
            evidence_records.append(record)

        evidence_path = stage / "evidence" / "index.jsonl"
        atomic_write_jsonl(evidence_path, evidence_records)
        evidence_digest, evidence_size = hash_file(evidence_path)
        evidence_artifact = {
            "id": f"artifact:sha256:{evidence_digest}",
            "kind": "evidence_index",
            "path": "evidence/index.jsonl",
            "sha256": evidence_digest,
            "bytes": evidence_size,
            "media_type": "application/x-ndjson",
        }
        artifacts.append(evidence_artifact)

        warnings = self._safe_code_list(worker_result.get("warnings", []), "warning")
        if self._declared_suffix_mismatch(source["declared_suffix"], actual_mime):
            warnings.append("declared_suffix_mismatch")
        disagreements = worker_result.get("disagreements", [])
        dependencies = worker_result.get("dependencies", {})
        if not isinstance(disagreements, list) or len(disagreements) > 1000:
            raise MediaEvidenceError("worker_contract_error", "Worker disagreements are invalid")
        if not isinstance(dependencies, dict):
            raise MediaEvidenceError("worker_contract_error", "Worker metadata is invalid")
        self._validate_safe_metadata(disagreements)
        self._validate_safe_metadata(dependencies)
        definitions = dependencies.get("clamav_definitions")
        if not isinstance(definitions, dict) or not isinstance(definitions.get("status"), str):
            raise MediaEvidenceError("worker_contract_error", "Worker malware scanner provenance is invalid")
        effective_scanner_revision = {
            key: definitions.get(key)
            for key in ("status", "file", "bytes", "mtime_ns", "sha256")
        }
        if options["scan_policy"] == "required":
            if definitions.get("status") != "current":
                raise MediaEvidenceError("worker_contract_error", "Worker malware scanner provenance is invalid")
            if (
                re.fullmatch(r"[0-9a-f]{64}", str(effective_scanner_revision.get("sha256"))) is None
                or effective_scanner_revision != scanner_revision
            ):
                raise MediaEvidenceError(
                    "scanner_definitions_changed",
                    "Malware definitions changed before required screening completed",
                )
        tier = worker_result.get("quality_tier")
        if tier not in {"complete", "partial", "insufficient"}:
            tier = "partial" if warnings or disagreements else "complete"

        completed_at = utc_now()
        manifest = {
            "schema": SCHEMA_ID,
            "job": {
                "id": job["job_id"],
                "idempotency_key": idempotency_key,
                "state": "completed",
                "trace_id": job["trace_id"],
                "created_at": job["created_at"],
                "completed_at": completed_at,
            },
            "source": {
                "sha256": source["sha256"],
                "bytes": source["bytes"],
                "actual_mime": actual_mime,
                "media_kind": media_kind,
                "name_sha256": source["name_sha256"],
                "declared_suffix": source["declared_suffix"],
                "rights_basis": rights_basis,
                "privacy": privacy,
            },
            "acquisition": {
                "adapter": source["adapter"],
                "retrieved_at": source["retrieved_at"],
                "redirects": source["redirects"],
                "network_used": source["network_used"],
                "source_uri_sha256": source["source_uri_sha256"],
                "final_uri_sha256": source["final_uri_sha256"],
                "final_origin": source["final_origin"],
            },
            "execution": {
                "tool": "media_evidence_analyze",
                "tool_version": TOOL_VERSION,
                "runtime": self._runtime_identity(),
                "network": "denied",
                "sandbox": (
                    "seccomp+landlock+uid+cgroupv2"
                    if self.require_worker_identity
                    else "seccomp+landlock"
                ),
                "resource_class": "cpu",
                "parameters": options,
                "limits": {
                    key: options[key]
                    for key in (
                        "cpu_limit_seconds",
                        "file_limit_mb",
                        "max_duration_seconds",
                        "max_frames",
                        "max_output_bytes",
                        "max_pages",
                        "max_pixels",
                        "max_source_bytes",
                        "memory_limit_mb",
                        "open_file_limit",
                        "process_limit",
                        "worker_timeout_seconds",
                    )
                },
                "dependencies": dependencies,
                "scanner_revision": effective_scanner_revision,
                "queue_wait_ms": queue_wait_ms,
                "duration_ms": duration_ms,
            },
            "artifacts": sorted(artifacts, key=lambda item: item["path"]),
            "evidence": {
                "count": len(evidence_records),
                "index_artifact_id": evidence_artifact["id"],
                "kinds": sorted({record["kind"] for record in evidence_records}),
            },
            "quality": {
                "tier": tier,
                "warnings": sorted(set(warnings)),
                "disagreements": disagreements,
                "coverage": coverage,
            },
            "policy": {
                "content_trust": "untrusted",
                "instruction_handling": "never_execute",
                "cloud_egress": "denied",
                "purpose_sha256": purpose_sha256,
            },
        }
        signed_manifest = sign_manifest(manifest, self.store.signing_key())
        validate_manifest_schema(signed_manifest)
        manifest_path = stage / "manifest.json"
        atomic_write_json(manifest_path, signed_manifest)
        staged_manifest = self._load_verified_manifest(manifest_path)
        self._verify_manifest_artifacts(manifest_path, staged_manifest)
        self._verify_final_tree_budget(stage, options["max_output_bytes"])
        self._freeze_tree(stage)
        self._fsync_tree(stage)
        self._verify_frozen_tree(stage)

        final = self.root / "runs" / job["job_id"]
        with self.store.worker_slot("storage"):
            if final.exists():
                raise MediaEvidenceError("integrity_failure", "Final run path already exists")
            os.replace(stage, final)
            directory_fd = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        final_manifest = final / "manifest.json"
        published_manifest = self._load_verified_manifest(final_manifest)
        self._verify_manifest_artifacts(final_manifest, published_manifest)
        self._verify_frozen_tree(final)
        manifest_sha256, _ = hash_file(final_manifest)
        self.store.transition(
            job["job_id"],
            state="completed",
            stage="published",
            manifest_path=str(final_manifest),
            manifest_sha256=manifest_sha256,
            detail={"media_kind": media_kind, "evidence_count": len(evidence_records)},
        )
        return {
            "ok": True,
            "cached": False,
            "job_id": job["job_id"],
            "trace_id": job["trace_id"],
            "source_sha256": source["sha256"],
            "media_kind": media_kind,
            "quality_tier": tier,
            "evidence_count": len(evidence_records),
            "manifest_path": str(final_manifest),
            "queue_wait_ms": queue_wait_ms,
            "duration_ms": duration_ms,
        }

    def _enumerate_stage_files(self, stage: Path, max_output_bytes: int) -> set[str]:
        files: set[str] = set()
        total = 0
        count = 0
        for root, directories, names in os.walk(stage, topdown=True, followlinks=False):
            root_path = Path(root)
            for name in list(directories):
                path = root_path / name
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains a symbolic link")
                if not stat.S_ISDIR(mode):
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains an invalid directory")
            for name in names:
                path = root_path / name
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains a symbolic link")
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains a non-regular file")
                relative = path.relative_to(stage).as_posix()
                files.add(relative)
                total += metadata.st_size
                count += 1
                if count > _MAX_ARTIFACTS or total > max_output_bytes:
                    raise MediaEvidenceError("worker_output_exceeded", "Worker output exceeded its budget")
        return files

    @staticmethod
    def _verify_final_tree_budget(root: Path, max_output_bytes: int) -> None:
        logical_bytes = 0
        allocated_bytes = 0
        entries = 0
        for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
            current = Path(directory)
            directory_names = set(directories)
            for name in [*directories, *files]:
                metadata = (current / name).lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains a symbolic link")
                if name in directory_names and not stat.S_ISDIR(metadata.st_mode):
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains an invalid directory")
                if name not in directory_names and (
                    not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                ):
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains an unsafe file")
                entries += 1
                logical_bytes += metadata.st_size
                allocated_bytes += getattr(metadata, "st_blocks", 0) * 512
                if entries > 5100 or max(logical_bytes, allocated_bytes) > max_output_bytes:
                    raise MediaEvidenceError("worker_output_exceeded", "Final evidence output exceeded its budget")

    @staticmethod
    def _safe_relative_path(value: Any) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 1024
            or "\\" in value
            or "\x00" in value
        ):
            raise MediaEvidenceError("worker_contract_error", "Worker artifact path is invalid")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or len(path.parts) > 32
            or any(part in {"", ".", ".."} or len(part.encode("utf-8")) > 255 for part in path.parts)
        ):
            raise MediaEvidenceError("worker_contract_error", "Worker artifact path escapes its stage")
        return path.as_posix()

    @staticmethod
    def _safe_worker_artifact_path(value: Any) -> str:
        relative = MediaEvidencePipeline._safe_relative_path(value)
        first = PurePosixPath(relative).parts[0]
        if first.startswith(".") or first in {"evidence", "manifest.json", "tmp"}:
            raise MediaEvidenceError("worker_contract_error", "Worker artifact path is reserved")
        return relative

    def _stage_artifact_path(self, stage: Path, relative: str) -> Path:
        path = stage.joinpath(*PurePosixPath(relative).parts)
        current = stage
        for part in PurePosixPath(relative).parts:
            current = current / part
            try:
                mode = current.lstat().st_mode
            except OSError as exc:
                raise MediaEvidenceError("worker_contract_error", "Worker artifact is missing") from exc
            if stat.S_ISLNK(mode):
                raise MediaEvidenceError("worker_output_rejected", "Worker output contains a symbolic link")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise MediaEvidenceError("worker_contract_error", "Worker artifact is not a regular file")
        return path

    @staticmethod
    def _safe_code(value: Any, label: str) -> str:
        if not isinstance(value, str) or not _SAFE_CODE.fullmatch(value):
            raise MediaEvidenceError("worker_contract_error", f"Worker {label} is invalid")
        return value

    def _safe_code_list(self, values: Any, label: str) -> list[str]:
        if not isinstance(values, list) or len(values) > 1000:
            raise MediaEvidenceError("worker_contract_error", f"Worker {label} list is invalid")
        return [self._safe_code(value, label) for value in values]

    def _validate_safe_metadata(self, value: Any, *, depth: int = 0) -> None:
        if depth > 8:
            raise MediaEvidenceError("worker_contract_error", "Worker metadata is too deeply nested")
        if value is None or isinstance(value, (bool, int)):
            return
        if isinstance(value, float):
            if value != value or value in {float("inf"), float("-inf")}:
                raise MediaEvidenceError("worker_contract_error", "Worker metadata contains a non-finite number")
            return
        if isinstance(value, str):
            if not _SAFE_CODE.fullmatch(value):
                raise MediaEvidenceError("worker_contract_error", "Worker metadata string is invalid")
            return
        if isinstance(value, list):
            if len(value) > 5000:
                raise MediaEvidenceError("worker_contract_error", "Worker metadata list is too large")
            for item in value:
                self._validate_safe_metadata(item, depth=depth + 1)
            return
        if isinstance(value, dict):
            if len(value) > 500:
                raise MediaEvidenceError("worker_contract_error", "Worker metadata object is too large")
            for key, item in value.items():
                if not isinstance(key, str) or not _SAFE_CODE.fullmatch(key):
                    raise MediaEvidenceError("worker_contract_error", "Worker metadata key is invalid")
                self._validate_safe_metadata(item, depth=depth + 1)
            return
        raise MediaEvidenceError("worker_contract_error", "Worker metadata type is invalid")

    @staticmethod
    def _validate_evidence_anchor(
        *,
        kind: str,
        anchor: dict[str, Any],
        artifact_kind: str,
        media_kind: str,
        coverage: dict[str, Any],
        text: str | None,
    ) -> None:
        def reject() -> None:
            raise MediaEvidenceError("worker_contract_error", "Worker evidence anchor is invalid")

        def exact_keys(*keys: str) -> None:
            if set(anchor) != set(keys):
                reject()

        def integer(container: dict[str, Any], name: str, *, minimum: int = 0) -> int:
            value = container.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                reject()
            return value

        def coverage_limit(name: str) -> int:
            return integer(coverage, name, minimum=1)

        def region(value: Any) -> tuple[int, int, int, int]:
            if not isinstance(value, dict) or set(value) != {"x", "y", "width", "height"}:
                reject()
            return (
                integer(value, "x"),
                integer(value, "y"),
                integer(value, "width", minimum=1),
                integer(value, "height", minimum=1),
            )

        if kind not in _EVIDENCE_ARTIFACT_KINDS:
            reject()
        if artifact_kind not in _EVIDENCE_ARTIFACT_KINDS[kind] or media_kind not in _EVIDENCE_MEDIA_KINDS[kind]:
            reject()
        if kind in _TEXT_EVIDENCE_KINDS:
            if not isinstance(text, str) or not text:
                reject()
        elif text is not None:
            reject()

        if kind == "page_text":
            exact_keys("page", "extractor", "char_start", "char_end")
            page = integer(anchor, "page", minimum=1)
            start = integer(anchor, "char_start")
            end = integer(anchor, "char_end", minimum=1)
            if page > coverage_limit("pages_total") or anchor.get("extractor") != "pdftotext":
                reject()
            if end <= start or end - start != len(text or ""):
                reject()
        elif kind == "ocr_text":
            exact_keys("page", "region", "line")
            page = integer(anchor, "page", minimum=1)
            x, y, width, height = region(anchor.get("region"))
            integer(anchor, "line", minimum=1)
            if media_kind == "document" and page > coverage_limit("pages_total"):
                reject()
            if media_kind == "image":
                if page != 1 or x + width > coverage_limit("width") or y + height > coverage_limit("height"):
                    reject()
        elif kind == "image_region":
            exact_keys("x", "y", "width", "height")
            x, y, width, height = region(anchor)
            if x + width > coverage_limit("width") or y + height > coverage_limit("height"):
                reject()
        elif kind == "page_image":
            exact_keys("page", "dpi")
            if integer(anchor, "page", minimum=1) > coverage_limit("pages_total"):
                reject()
            integer(anchor, "dpi", minimum=1)
        elif kind in {"audio_waveform", "transcript_segment"}:
            expected = ("start_ms", "end_ms") if kind == "audio_waveform" else ("segment", "start_ms", "end_ms")
            exact_keys(*expected)
            if kind == "transcript_segment":
                integer(anchor, "segment", minimum=1)
            start = integer(anchor, "start_ms")
            end = integer(anchor, "end_ms", minimum=1)
            if end <= start or end > coverage_limit("duration_ms") + 1000:
                reject()
        elif kind in {"video_frame", "frame_ocr"}:
            expected = ("timestamp_ms", "sample_type")
            if kind == "frame_ocr":
                expected += ("region", "line")
            exact_keys(*expected)
            timestamp = integer(anchor, "timestamp_ms")
            if timestamp > coverage_limit("duration_ms") + 1000 or anchor.get("sample_type") not in {"interval", "scene"}:
                reject()
            if kind == "frame_ocr":
                region(anchor.get("region"))
                integer(anchor, "line", minimum=1)

    def _structured_records(
        self,
        stage: Path,
        artifact: dict[str, Any],
        cache: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        relative = artifact["path"]
        if relative in cache:
            return cache[relative]
        path = self._stage_artifact_path(stage, relative)
        if path.stat().st_size > _MAX_STRUCTURED_ARTIFACT_BYTES:
            raise MediaEvidenceError("worker_contract_error", "Structured artifact exceeds its verification budget")
        records: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if len(line.encode("utf-8")) > 2 * 1024 * 1024 or len(records) >= _MAX_EVIDENCE:
                        raise MediaEvidenceError(
                            "worker_contract_error",
                            "Structured artifact exceeds its verification budget",
                        )
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError
                    records.append(record)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            if isinstance(exc, MediaEvidenceError):
                raise
            raise MediaEvidenceError("worker_contract_error", "Structured artifact is invalid") from exc
        cache[relative] = records
        return records

    def _json_artifact(self, stage: Path, artifact: dict[str, Any]) -> dict[str, Any]:
        path = self._stage_artifact_path(stage, artifact["path"])
        if path.stat().st_size > 4 * 1024 * 1024:
            raise MediaEvidenceError("worker_contract_error", "Metadata artifact exceeds its verification budget")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MediaEvidenceError("worker_contract_error", "Metadata artifact is invalid") from exc
        if not isinstance(value, dict):
            raise MediaEvidenceError("worker_contract_error", "Metadata artifact is invalid")
        return value

    def _verify_worker_coverage(
        self,
        *,
        stage: Path,
        artifacts: list[dict[str, Any]],
        media_kind: str,
        coverage: dict[str, Any],
        cache: dict[str, list[dict[str, Any]]],
    ) -> None:
        def by_kind(kind: str) -> list[dict[str, Any]]:
            return [artifact for artifact in artifacts if artifact["kind"] == kind]

        def one(kind: str) -> dict[str, Any]:
            matches = by_kind(kind)
            if len(matches) != 1:
                raise MediaEvidenceError("worker_contract_error", "Worker coverage artifacts are invalid")
            return matches[0]

        def integer(name: str, *, minimum: int = 0) -> int:
            value = coverage.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise MediaEvidenceError("worker_contract_error", "Worker coverage is invalid")
            return value

        if media_kind == "image":
            if set(coverage) != {"width", "height", "tiles", "ocr_lines"}:
                raise MediaEvidenceError("worker_contract_error", "Worker image coverage is invalid")
            sanitized = self._stage_artifact_path(stage, one("sanitized_image")["path"])
            try:
                with sanitized.open("rb") as handle:
                    header = handle.read(24)
            except OSError as exc:
                raise MediaEvidenceError("worker_contract_error", "Sanitized image is invalid") from exc
            if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
                raise MediaEvidenceError("worker_contract_error", "Sanitized image is invalid")
            width, height = struct.unpack(">II", header[16:24])
            if integer("width", minimum=1) != width or integer("height", minimum=1) != height:
                raise MediaEvidenceError("worker_contract_error", "Worker image coverage does not match its artifact")
            if integer("tiles") != len(by_kind("image_tile")):
                raise MediaEvidenceError("worker_contract_error", "Worker image coverage does not match its artifacts")
            ocr_records = [
                record
                for artifact in by_kind("ocr_text")
                for record in self._structured_records(stage, artifact, cache)
            ]
            if integer("ocr_lines") != len(ocr_records):
                raise MediaEvidenceError("worker_contract_error", "Worker image coverage does not match its OCR")
            return

        if media_kind == "document":
            expected = {"pages_total", "pages_native_text", "pages_rendered", "ocr_lines"}
            if set(coverage) != expected:
                raise MediaEvidenceError("worker_contract_error", "Worker document coverage is invalid")
            probe = self._json_artifact(stage, one("document_probe"))
            pages = probe.get("pages")
            if isinstance(pages, bool) or not isinstance(pages, int) or pages < 1 or integer("pages_total", minimum=1) != pages:
                raise MediaEvidenceError("worker_contract_error", "Worker document coverage does not match its probe")
            native_records = self._structured_records(stage, one("native_text"), cache)
            if [record.get("page") for record in native_records] != list(range(1, pages + 1)):
                raise MediaEvidenceError("worker_contract_error", "Native text artifact has invalid pages")
            if integer("pages_native_text") != sum(bool(record.get("text")) for record in native_records):
                raise MediaEvidenceError("worker_contract_error", "Worker document coverage does not match native text")
            if integer("pages_rendered") != len(by_kind("page_image")):
                raise MediaEvidenceError("worker_contract_error", "Worker document coverage does not match page images")
            ocr_records = [
                record
                for artifact in by_kind("ocr_text")
                for record in self._structured_records(stage, artifact, cache)
            ]
            if integer("ocr_lines") != len(ocr_records):
                raise MediaEvidenceError("worker_contract_error", "Worker document coverage does not match OCR")
            return

        expected = {"duration_ms", "transcript_segments"}
        if media_kind == "video":
            expected |= {"sampled_frames", "scene_frames"}
        if set(coverage) != expected:
            raise MediaEvidenceError("worker_contract_error", "Worker timed-media coverage is invalid")
        probe = self._json_artifact(stage, one("media_probe"))
        values: list[float] = []
        raw_format = probe.get("format") if isinstance(probe.get("format"), dict) else {}
        streams = probe.get("streams") if isinstance(probe.get("streams"), list) else []
        candidates = [raw_format.get("duration")]
        candidates.extend(stream.get("duration") for stream in streams if isinstance(stream, dict))
        for candidate in candidates:
            try:
                value = float(candidate)
            except (TypeError, ValueError):
                continue
            if math.isfinite(value) and value > 0:
                values.append(value)
        if not values or integer("duration_ms", minimum=1) != int(max(values) * 1000):
            raise MediaEvidenceError("worker_contract_error", "Worker duration does not match its probe")
        transcript_records = [
            record
            for artifact in by_kind("structured_transcript")
            for record in self._structured_records(stage, artifact, cache)
        ]
        if integer("transcript_segments") != len(transcript_records):
            raise MediaEvidenceError("worker_contract_error", "Worker coverage does not match its transcript")
        if media_kind == "video":
            if integer("sampled_frames") != len(by_kind("sampled_frame")):
                raise MediaEvidenceError("worker_contract_error", "Worker coverage does not match sampled frames")
            if integer("scene_frames") != len(by_kind("scene_frame")):
                raise MediaEvidenceError("worker_contract_error", "Worker coverage does not match scene frames")

    def _verify_text_evidence(
        self,
        *,
        stage: Path,
        artifact: dict[str, Any],
        kind: str,
        anchor: dict[str, Any],
        text: str,
        cache: dict[str, list[dict[str, Any]]],
    ) -> None:
        records = self._structured_records(stage, artifact, cache)
        if kind == "page_text":
            matches = [record for record in records if record.get("page") == anchor["page"]]
            valid = (
                len(matches) == 1
                and isinstance(matches[0].get("text"), str)
                and matches[0]["text"][anchor["char_start"] : anchor["char_end"]] == text
            )
        elif kind == "ocr_text":
            valid = any(
                record.get("page", 1) == anchor["page"]
                and record.get("line") == anchor["line"]
                and record.get("region") == anchor["region"]
                and record.get("text") == text
                for record in records
            )
        elif kind == "transcript_segment":
            valid = any(
                record.get("segment") == anchor["segment"]
                and record.get("start_ms") == anchor["start_ms"]
                and record.get("end_ms") == anchor["end_ms"]
                and record.get("text") == text
                for record in records
            )
        else:
            valid = any(
                record.get("timestamp_ms") == anchor["timestamp_ms"]
                and record.get("sample_type") == anchor["sample_type"]
                and record.get("line") == anchor["line"]
                and record.get("region") == anchor["region"]
                and record.get("text") == text
                for record in records
            )
        if not valid:
            raise MediaEvidenceError("worker_contract_error", "Evidence text does not match its artifact")

    def _verify_manifest_artifacts(
        self,
        manifest_path: Path,
        manifest: dict[str, Any],
        artifact_ids: set[str] | None = None,
    ) -> None:
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list):
            raise MediaEvidenceError("integrity_failure", "Manifest artifact inventory is invalid")
        available_ids = {artifact.get("id") for artifact in artifacts if isinstance(artifact, dict)}
        selected = available_ids if artifact_ids is None else artifact_ids
        if not selected.issubset(available_ids):
            raise MediaEvidenceError("integrity_failure", "Manifest references an unknown artifact")
        for artifact in artifacts:
            if not isinstance(artifact, dict) or artifact.get("id") not in selected:
                continue
            path = self._manifest_artifact_path(manifest_path.parent, artifact.get("path"))
            try:
                digest, size = hash_file(path)
            except OSError as exc:
                raise MediaEvidenceError("integrity_failure", "Manifest artifact could not be verified") from exc
            if digest != artifact.get("sha256") or size != artifact.get("bytes"):
                raise MediaEvidenceError("integrity_failure", "Manifest artifact hash mismatch")

    @staticmethod
    def _runtime_identity() -> dict[str, Any]:
        commit_path = Path("/opt/hermes-agent.commit")
        commit = "unknown"
        try:
            candidate = commit_path.read_text(encoding="utf-8").strip()
            if re.fullmatch(r"[0-9a-f]{40}", candidate):
                commit = candidate
        except OSError:
            pass
        sbom_sha256 = "unknown"
        try:
            candidate = Path("/opt/hermes-runtime.cdx.sha256").read_text(encoding="utf-8").split()[0]
            if re.fullmatch(r"[0-9a-f]{64}", candidate):
                sbom_sha256 = candidate
        except (OSError, IndexError):
            pass
        return {
            "python": platform.python_version(),
            "platform": platform.system().lower(),
            "machine": platform.machine().lower(),
            "hermes_commit": commit,
            "sbom_sha256": sbom_sha256,
            "runtime_commit": MediaEvidencePipeline._bounded_runtime_identifier(
                os.getenv("RAILWAY_GIT_COMMIT_SHA"),
                pattern=r"[0-9a-f]{40}",
            ),
            "deployment_id": MediaEvidencePipeline._bounded_runtime_identifier(
                os.getenv("RAILWAY_DEPLOYMENT_ID"),
                pattern=r"[a-zA-Z0-9_-]{1,128}",
            ),
            "image_digest": MediaEvidencePipeline._bounded_runtime_identifier(
                os.getenv("RAILWAY_IMAGE_DIGEST"),
                pattern=r"sha256:[0-9a-f]{64}",
            ),
        }

    @staticmethod
    def _bounded_runtime_identifier(value: str | None, *, pattern: str) -> str:
        candidate = (value or "").strip()
        return candidate if re.fullmatch(pattern, candidate) else "unknown"

    @staticmethod
    def _declared_suffix_mismatch(suffix: str, actual_mime: str) -> bool:
        expected = {
            ".aac": {"audio/aac", "audio/x-aac"},
            ".flac": {"audio/flac", "audio/x-flac"},
            ".jpeg": {"image/jpeg"},
            ".jpg": {"image/jpeg"},
            ".m4a": {"audio/mp4", "video/mp4"},
            ".mkv": {"video/x-matroska"},
            ".mov": {"video/quicktime"},
            ".mp3": {"audio/mpeg"},
            ".mp4": {"video/mp4", "audio/mp4"},
            ".ogg": {"audio/ogg", "video/ogg", "application/ogg"},
            ".pdf": {"application/pdf"},
            ".png": {"image/png"},
            ".wav": {"audio/x-wav", "audio/wav"},
            ".webm": {"video/webm", "audio/webm"},
            ".webp": {"image/webp"},
        }
        return bool(suffix and suffix in expected and actual_mime not in expected[suffix])

    def _freeze_tree(self, root: Path) -> None:
        for directory, directories, files in os.walk(root, topdown=False, followlinks=False):
            for name in files:
                path = Path(directory) / name
                self._freeze_ownership(path)
                os.chmod(path, 0o440)
            for name in directories:
                path = Path(directory) / name
                self._freeze_ownership(path)
                os.chmod(path, 0o550)
        self._freeze_ownership(root)
        os.chmod(root, 0o550)

    def _verify_frozen_tree(self, root: Path) -> None:
        expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
        expected_gid = self.store.worker_gid if os.geteuid() == 0 else None
        paths = [root]
        for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
            current = Path(directory)
            paths.extend(current / name for name in directories)
            paths.extend(current / name for name in files)
        for path in paths:
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise MediaEvidenceError("integrity_failure", "Published evidence metadata is unavailable") from exc
            is_directory = stat.S_ISDIR(metadata.st_mode)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or (not is_directory and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1))
                or stat.S_IMODE(metadata.st_mode) != (0o550 if is_directory else 0o440)
                or metadata.st_uid != expected_uid
                or (expected_gid is not None and metadata.st_gid != expected_gid)
            ):
                raise MediaEvidenceError("integrity_failure", "Published evidence permissions are invalid")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _fsync_tree(self, root: Path) -> None:
        directories: list[Path] = []
        for directory, child_directories, files in os.walk(root, topdown=False, followlinks=False):
            current = Path(directory)
            directories.append(current)
            for name in child_directories:
                path = current / name
                if path.is_symlink():
                    raise MediaEvidenceError("worker_output_rejected", "Worker output contains a symbolic link")
            for name in files:
                path = current / name
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise MediaEvidenceError("worker_output_rejected", "Worker output contains an unsafe file")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        for directory in directories:
            self._fsync_directory(directory)

    def _freeze_ownership(self, path: Path) -> None:
        if self.store.worker_gid is not None and os.geteuid() == 0:
            os.chown(path, 0, self.store.worker_gid)

    @staticmethod
    def _manifest_artifact_path(run_root: Path, relative: str) -> Path:
        safe = MediaEvidencePipeline._safe_relative_path(relative)
        path = run_root.joinpath(*PurePosixPath(safe).parts)
        current = run_root
        try:
            root_metadata = current.lstat()
        except OSError as exc:
            raise MediaEvidenceError("integrity_failure", "Manifest run directory is missing") from exc
        if current.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            raise MediaEvidenceError("integrity_failure", "Manifest run directory is invalid")
        for part in PurePosixPath(safe).parts:
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise MediaEvidenceError("integrity_failure", "Manifest artifact is missing") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise MediaEvidenceError("integrity_failure", "Manifest artifact path contains a link")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise MediaEvidenceError("integrity_failure", "Manifest artifact is missing")
        return path

    @staticmethod
    def _normalize_quote(value: str) -> str:
        return " ".join(value.split())

    def _validate_claim(
        self,
        raw_claim: Any,
        evidence: dict[str, dict[str, Any]],
        job_id: str,
    ) -> tuple[dict[str, Any], bool]:
        reasons: list[str] = []
        if not isinstance(raw_claim, dict):
            raw_claim = {}
            reasons.append("claim_not_object")
        claim = raw_claim.get("claim")
        if not isinstance(claim, str) or not claim.strip() or len(claim) > 10_000:
            claim = ""
            reasons.append("claim_text_invalid")
        evidence_ids = raw_claim.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= 20:
            evidence_ids = []
            reasons.append("evidence_ids_invalid")
        elif any(not isinstance(item, str) for item in evidence_ids):
            evidence_ids = []
            reasons.append("evidence_ids_invalid")
        else:
            evidence_ids = list(dict.fromkeys(evidence_ids))
            if any(item not in evidence for item in evidence_ids):
                reasons.append("evidence_id_unknown")

        quotations = raw_claim.get("quotations", [])
        normalized_quotations: list[dict[str, str]] = []
        if not isinstance(quotations, list) or len(quotations) > 20:
            reasons.append("quotations_invalid")
            quotations = []
        for quotation in quotations:
            if not isinstance(quotation, dict):
                reasons.append("quotation_invalid")
                continue
            evidence_id = quotation.get("evidence_id")
            quote = quotation.get("quote")
            if (
                not isinstance(evidence_id, str)
                or not isinstance(quote, str)
                or not quote.strip()
                or len(quote) > 10_000
            ):
                reasons.append("quotation_invalid")
                continue
            if evidence_id not in evidence_ids or evidence_id not in evidence:
                reasons.append("quotation_evidence_unknown")
                continue
            source_text = evidence[evidence_id].get("text")
            if not isinstance(source_text, str) or self._normalize_quote(quote) not in self._normalize_quote(source_text):
                reasons.append("quotation_not_found")
                continue
            normalized_quotations.append({"evidence_id": evidence_id, "quote": quote})

        quoted_evidence = {quotation["evidence_id"] for quotation in normalized_quotations}
        for evidence_id in evidence_ids:
            cited = evidence.get(evidence_id)
            if isinstance(cited, dict) and isinstance(cited.get("text"), str) and evidence_id not in quoted_evidence:
                reasons.append("quotation_required")

        identity = {
            "job_id": job_id,
            "claim": claim.strip(),
            "evidence_ids": evidence_ids,
            "quotations": normalized_quotations,
        }
        valid = not reasons
        validation_identity = {
            **identity,
            "status": "citation_valid" if valid else "rejected",
            "reasons": sorted(set(reasons)),
        }
        record = {
            "schema": "media-evidence-claim/v1",
            "claim_id": f"claim_{sha256_bytes(canonical_json_bytes(validation_identity))[:24]}",
            "job_id": job_id,
            "claim": claim.strip(),
            "evidence_ids": evidence_ids,
            "quotations": normalized_quotations,
            "status": "citation_valid" if valid else "rejected",
            "reasons": sorted(set(reasons)),
            "validated_at": utc_now(),
        }
        return record, valid
