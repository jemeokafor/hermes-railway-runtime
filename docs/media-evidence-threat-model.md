# Media Evidence v1 Threat Model

## Protected Assets

- Hermes credentials, configuration, sessions, and approval state.
- Other workspace files and previously ingested private media.
- Gateway availability and bounded CPU, memory, disk, process, and wall time.
- Evidence integrity, provenance, and the distinction between extracted content and instructions.
- User rights, privacy classification, and the no-cloud default.

## Adversaries

- A malformed, polyglot, encrypted, decompression-bomb, or malware-bearing file.
- A remote server using redirects, DNS rebinding, oversized streams, or misleading MIME metadata.
- Text, OCR, subtitles, metadata, or filenames containing prompt injection.
- A compromised parser attempting network access, credential reads, path traversal, symlink publication, or resource exhaustion.
- Concurrent or interrupted jobs attempting partial publication or inconsistent state.

## Controls

- Consent fields are mandatory and recorded as hashes or bounded enums.
- Local sources are opened descriptor-first beneath explicit roots with symlinks rejected.
- Remote acquisition is HTTPS-only, IP-pinned, redirect-bounded, size-bounded, and separate from parsing.
- Actual MIME probing selects the parser; suffixes are advisory only.
- Quarantine and CAS promotion are streaming and content-addressed.
- Workers receive an allowlisted environment with no secrets, run as a dedicated UID under a per-job cgroup-v2 subtree, deny network syscalls with seccomp, and restrict filesystem access with Landlock.
- Parser commands use absolute executables, fixed argument vectors, no shell, no inherited stdin, bounded output, and process-group termination on timeout.
- Worker output is untrusted. The orchestrator accepts only regular files below the stage root and recomputes all hashes and evidence IDs.
- Final run publication is one atomic rename after manifest signing.
- The model-facing gateway is a non-root account with no evidence traverse group; only the authenticated root broker can access the store and signing key.
- Broker responses use operation-specific field and value allowlists. They never return extracted text or store, manifest, ledger, binary, or artifact paths.
- Evidence records are marked untrusted and non-instructional. Evidence text is available only to a separately trusted non-model review channel.
- Claim validation requires existing anchors and quotation containment.
- Durable idempotency, locks, stage cleanup, and state transitions make retries safe.

## Explicit Non-Goals

- This tool does not decide whether a legal rights basis is valid.
- It does not execute instructions found in media.
- It does not silently fall back to cloud STT or vision.
- It does not claim semantic understanding when OCR, transcription, rendering, or visual interpretation is unavailable.
- The first release is a single-host durable worker, not a distributed scheduler.
