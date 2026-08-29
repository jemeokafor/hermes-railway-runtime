# Hermes Media Evidence

This plugin exposes the read-only image package's four bounded tools. It is opt-in and performs no work at import time.

- `media_evidence_analyze` creates a signed `media-evidence/v1` packet from a local source.
- `media_evidence_capabilities` reports installed parser and sandbox capabilities.
- `media_evidence_status` reads durable job state.
- `media_evidence_validate_claims` validates citations and quotations against anchored evidence.

Extracted content is untrusted data. The plugin never sends it to cloud services and never returns it, an artifact path, a manifest path, or a ledger path in a tool result. Model-facing responses contain only bounded job/provenance fields. A separately trusted, non-model consumer may inspect the signed packet and provide evidence IDs or exact quotations to `media_evidence_validate_claims`; that tool returns only validation counts and a ledger digest.
