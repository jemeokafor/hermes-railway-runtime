# Media Evidence v1 Operations

## Service Levels

The first release is a single-host CPU worker and exposes queue and total latency in every signed manifest and local telemetry event. Initial service-level objectives are:

- At least 99% of accepted jobs reach a terminal state without an internal error over 30 days.
- At least 95% of jobs begin worker execution within 60 seconds over 24 hours.
- No failed or killed job publishes a final run directory.
- No remote source is parsed unless malware screening completed with current definitions.
- No parser process opens a network socket or reads outside its Landlock allowlist.

Alert when the 15-minute internal-error ratio exceeds 5%, queue wait exceeds 300 seconds, free workspace storage falls below 10%, malware definitions are not current, or a sandbox capability reports unavailable.

When enabling the plugin in staging or production, set `MEDIA_EVIDENCE_REQUIRE_READY=true`. Bootstrap then fails closed before Railway readiness unless the evidence store, input roots, dedicated identity, delegated cgroup-v2 aggregate resource controls, seccomp, Landlock, required binaries, current ClamAV definitions, and pinned offline Whisper model are available. Monitor `/data/.hermes/media-evidence-readiness.json` and the normal health endpoint continuously after deployment.

## Telemetry

`telemetry/events.jsonl` is an append-only, content-free event stream. Events carry a 32-hex trace ID, 16-hex span ID, job ID, stage outcome, queue wait, total duration, media kind, and bounded error code. Source names, URLs, purpose text, extracted text, claims, credentials, and parser diagnostics are excluded.

The local stream is the source for an eventual OpenTelemetry collector. Export remains disabled by default and must not be enabled until the destination, retention, privacy classification, and egress policy are approved.

## Recovery

- File locks are released automatically when an orchestrator process exits.
- A retry with the same source and normalized parameters reuses the job ID, removes stale stage directories, and starts from the CAS object.
- Runs become visible only after schema validation, signature generation, permission freezing, and one atomic rename.
- A completed job whose manifest signature, schema, job ID, or database hash fails validation is an integrity incident; do not regenerate it in place.

## Scanner Maintenance

The image build refreshes ClamAV definitions and fails if a non-empty daily database is unavailable. Runtime screening treats definitions older than 14 days, missing definitions, and future-dated definitions as invalid. Remote acquisition always uses `scan_policy=required` and cannot override it, so stale or unavailable definitions fail closed before parsing.

## Capacity And Rollback

Distinct jobs share one durable CPU worker slot. Capacity expansion should add resource-class-specific worker processes without changing `media-evidence/v1`. Rollback disables `media-evidence` in `plugins.enabled`, uses the certified supervised restart wrapper, and preserves CAS, manifests, ledgers, jobs, and telemetry for audit.

Acquisitions are serialized and admission preserves the larger of `MEDIA_EVIDENCE_MIN_FREE_BYTES` (512 MiB by default) or 10% of the filesystem capped at 2 GiB before source copying and worker execution. Default per-job budgets are 512 MiB of source and 1 GiB of output. Size the Railway volume for retained CAS/runs plus Ollama models and logs; admission is not retention, so production still requires an approved archival and deletion policy. The root broker requires a private writable cgroup-v2 subtree at `MEDIA_EVIDENCE_CGROUP_ROOT` (default `/sys/fs/cgroup/hermes-media`) with `cpu`, `memory`, and `pids` controllers enabled. If that delegation is absent, media evidence readiness remains failed and production activation must not proceed.

## Certifying A Candidate Image

Build the final image with a real source revision, then certify that local image without starting the Hermes service:

```bash
docker build \
  --build-arg RAILWAY_GIT_COMMIT_SHA="$(git rev-parse HEAD)" \
  --tag hermes-railway-runtime:candidate .
npm run certify:p4 -- hermes-railway-runtime:candidate
```

Set `P4_REPORT_PATH` to choose the report destination; the default is `./p4-image-certification.json`. Before checking for the Docker CLI, daemon, or candidate image, the launcher resolves the report's parent directory and deletes any existing file or link at that destination. A failed preflight therefore cannot leave an earlier passed report at the requested path. The launcher resolves the supplied image reference once and executes the resulting immutable image ID. It uses `docker run --rm --cgroupns private --network none --read-only`, overrides the entrypoint with `/opt/hermes-venv/bin/python`, passes `-I`, mounts `test/p4` read-only, and writes only to tmpfs plus a temporary report mount. It does not run the application entrypoint, expose ports, mount the Docker socket, push an image, change service configuration, or invoke a deployment tool.

Fixtures are generated after container start with the candidate's pinned Pillow/font, `espeak-ng`, and FFmpeg utilities. The four corpus records use distinct visual or speech phrases and are hashed after byte-contract checks. The canonical scanner-negative canary is assembled from split fragments only at runtime and is not part of the retained four-file corpus. The corpus, canary, and evidence store live only in `/p4-work` tmpfs. Neither fixture bytes, the Python certifier, nor the host launcher are copied into any production image layer; the Dockerfile enumerates the production scripts explicitly.

Treat any non-zero exit as a failed certification. The certifier validates every final passed or failed report before its atomic write. If a nominally passed report fails validation, it is downgraded, finalized, and validated again; malformed failed or post-downgrade output is not written. The launcher then performs a second host-side canonical and shape validation and retains a report only when its status agrees with the container exit. In-container preflight or lane failures can therefore retain a valid failure report. Host preflight failures before a container starts, such as an unavailable Docker daemon, missing image, or unknown source-revision label, leave no report at `P4_REPORT_PATH`. Do not relabel, rebuild, or retag a report onto another image: rerun certification against that image ID.

CI first runs Python unit/syntax checks and shell syntax checks that require neither Docker nor media binaries. It then builds with `RAILWAY_GIT_COMMIT_SHA=${{ github.sha }}`, loads the result into the runner's Docker image store, runs the candidate harness, and uploads `p4-image-certification.json`, including any validated failure report. CI remains build-and-test only; it has no push or deploy step.

The report's SHA-256 binding provides integrity, not signer authenticity or promotion authority. Preserve the exact immutable image digest named by the report. Promotion requires an external signed attestation over that exact retained image digest under the separately approved release trust policy; the report alone must never be treated as authorization.
