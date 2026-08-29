# Media Evidence v1 Architecture

## Boundary

`media-evidence/v1` converts an untrusted local or explicitly authorized HTTPS source into a signed, content-addressed evidence packet. Extracted text is data, never instructions. The tool does not make interpretation claims and does not send source content to a model or cloud service.

The production path has four trust zones:

1. The non-root Hermes gateway validates consent fields and sends a fixed request over an authenticated Unix socket.
2. The root broker authenticates the gateway with peer credentials, securely opens or acquires the source, streams it into quarantine, hashes it, records durable job state, and creates an isolated stage directory.
3. A dedicated non-root worker is launched through a per-job cgroup-v2 subtree covering the supervisor and descendants, then applies per-process file/open-file/address-space/wall-clock limits, Landlock filesystem rules, and a seccomp network denylist before invoking parsers with fixed argument vectors.
4. The broker rejects unexpected files, links, missing evidence anchors, or budget violations, then computes hashes, signs the manifest, atomically promotes the stage, and projects the result onto an operation-specific model-facing allowlist.

Workers cannot publish final runs, mutate the job database, access Hermes credentials, or open network sockets. Failed, killed, or aggregate-limit-exceeded workers leave no visible final run. A retry with the same source hash and normalized parameters resumes under the same idempotency key.

## Storage

The default root is `/data/media-evidence`, outside all user-writable input roots:

```text
cas/sha256/aa/<source-sha256>
jobs.sqlite3
keys/manifest-hmac-v1.key
locks/<job-id>.lock
quarantine/
runs/<job-id>/
telemetry/events.jsonl
```

The SQLite database is metadata only. Source bytes live in the CAS, and a run contains immutable derived artifacts, `evidence/index.jsonl`, and `manifest.json`. Paths and logs use hashes instead of user filenames. The source name, purpose, and URI are represented by hashes in the manifest. The gateway identity cannot traverse this root, and the broker never returns a store, manifest, ledger, or artifact path.

## Evidence Contract

Every evidence record has a deterministic ID, an artifact ID, an exact page/time/region anchor, a content hash, and these fixed trust fields:

```json
{
  "trust": "untrusted",
  "instructional_text": false
}
```

Claims are a separate, bounded HMAC-chained ledger. A claim is citation-valid only when every cited evidence ID exists and every textual citation supplies an exact quotation present after conservative whitespace normalization. Image-only evidence may be cited without a quotation but remains visibly typed as image evidence. Citation validation does not assert semantic entailment.

The four model-facing tools do not provide a packet reader. Analyze and status return only bounded opaque job/provenance metadata; claim validation returns counts and a ledger digest. Evidence IDs and quotations must come from a separately trusted, non-model presentation or review channel. This keeps attacker-controlled OCR and transcript text out of the model instruction stream and out of generic file tools.

For non-public jobs, low-entropy source-name, source-URI, final-URI, and purpose identifiers use domain-separated HMAC-SHA-256 values rather than dictionary-recoverable plain hashes; remote origin text is omitted. Content SHA-256 values remain unkeyed so artifact and CAS integrity stays independently verifiable.

## Queue And Recovery

Version 1 uses a durable single-host CPU queue implemented by a job row plus a per-job advisory file lock. This deliberately proves the required MP4, MP3, PDF, and image slice before introducing distributed infrastructure. The schema includes a resource class and trace ID so the worker can later move to separate CPU and GPU queues without changing evidence packets.

## Activation

The plugin is bundled in the image but opt-in. Building the image does not enable it. Production activation requires all of the following:

- P4 corpus passes in the candidate image.
- The currently certified Ulysses runtime changes are image-persistent.
- `media-evidence` is added to `plugins.enabled`.
- Mutation tools are explicitly classified by Ulysses.
- Exact one-shot approval covers the hashes, config edit, supervised restart, canaries, and rollback.

## P4 Candidate-Image Certification

P4 is one indivisible, fail-closed certification of the exact final Docker image that could be promoted. It consists of four real parser lanes generated and processed inside that image:

| Lane | Source contract | Required derived evidence |
| --- | --- | --- |
| image | metadata-free PNG, detected as `image/png` | sanitized PNG, OCR artifact, image-region and OCR evidence |
| PDF | structurally valid image-only PDF, detected as `application/pdf` | qpdf validation, rendered page, OCR artifact, page-image and OCR evidence |
| MP3 | encoded MP3 speech, detected as `audio/mpeg` and probed as MP3 | normalized audio, waveform, local Whisper transcript and anchored transcript evidence |
| MP4 | MP4 with real video and speech audio streams, detected as `video/mp4` | sampled frames, contact sheet, frame OCR, normalized audio, waveform, local Whisper transcript, and all corresponding anchored evidence |

Every lane uses the production `MediaEvidencePipeline` and its real dedicated `hermes-media` worker identity. The acquisition identity `hermes-acquire` must also exist as a distinct non-root account. The normalized options must contain `scan_policy=required`, `ocr=true`, `transcribe=true`, and `require_qpdf=true`. A lane cannot be skipped, substituted with a mock, downgraded to best effort, or accepted through an unavailable/disabled fallback. Image, PDF, and video use mutually distinct OCR phrases; MP3 and MP4 use separate speech phrases. Acceptance requires all normalized lane-specific expected words, not merely non-empty text or a token shared by fixtures.

Before parser lanes, the harness constructs the canonical 68-byte EICAR scanner canary in memory from split fragments and writes it only under the runtime tmpfs. Required screening must return `malware_detected`; the failed job must have no manifest and no staged or published run. The contiguous canary signature is not stored in the repository or a production image layer.

The harness independently checks each signed `media-evidence/v1` manifest, every declared artifact hash and size, the evidence index and content hashes, expected MIME, scanner definition provenance, offline Whisper repository/revision/model hash, and `seccomp+landlock+uid+cgroupv2`. Required PNG, JPEG, WAV, JSON, and NDJSON artifacts are opened and checked by byte magic or parsers rather than accepted from declared media types. Independent ffprobe calls enforce the fixture container, codec, sample-rate, channel, frame-rate, dimensions, and explicit duration/tolerance contracts and must agree with each emitted probe artifact. Image and PDF must report `complete`; MP3 and MP4 must report `partial` solely because `diarization_unavailable` is expected after successful local transcription. Every lane must report no extraction disagreements. A dedicated identity probe demonstrates that seccomp denies socket creation while Landlock permits only declared reads and writes. An aggregate resource probe demonstrates that a private cgroup-v2 job subtree can enforce `pids.max` and expose CPU/memory/PID event counters. The enclosing container has only loopback, uses a read-only root filesystem, and receives no deployment identity.

The candidate is addressed by the Docker image ID returned by `docker image inspect`, not by the mutable tag supplied by the operator. The OCI source-revision label must be a non-zero 40-hex commit. That same commit is embedded in `/opt/hermes-source.commit` and the CycloneDX application version. `/opt/hermes-runtime.cdx.sha256` must match the embedded SBOM, whose model component must match the model bytes. Per-lane manifests must repeat the source commit, SBOM hash, and image ID.

The output is one canonical, newline-terminated `p4-image-certification/v1` JSON object. Its SHA-256 binding covers the candidate image ID, source commit, SBOM identity, exact mounted harness hash, corpus definition and generated input hashes, preflight provenance, and every lane result. The final object is shape-validated before every write, including failure output and any report downgraded from passed to failed. The report passes only when all four lane statuses are `passed` and the error list is empty.

The report's unkeyed SHA-256 binding is an integrity checksum only. It detects changes to retained report bytes but is not an authenticity signature and does not establish who produced or approved the report. A report is not a deployment approval or deployment action. Promotion requires a separately controlled external signed attestation over the exact immutable image digest that is retained for promotion; a P4 report without that attestation is insufficient.
