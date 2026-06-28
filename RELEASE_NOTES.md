# Release Notes

## v3.0.0 - 2026-06-27

- Added `slbit/viz-packet/v3` Meaning Observatory packets.
- Added explicit Memory Capsule, Rootprint branch, and replay fingerprint
  bindings.
- Added typed semantic DAG nodes with authority labels and proof-status text.
- Added deterministic local `MeaningPacket::ask()` for supported packet
  questions.
- Added non-authoritative Markdown context export for external explanation
  tools.
- Added v3 digest verification, semantic mutation rejection, and DAG cycle
  rejection tests.
- Preserved the trust boundary: v3 explains verified memory but never becomes
  proof-system soundness or core identity.

## v0.2.0 - 2026-06-26

- Added `slbit/viz-packet/v2` as the luminous semantic packet foundation.
- Added `LuminousPacket` and `LuminousPacketBuilder`.
- Added deterministic producer metadata, external anchors, semantic DAGs,
  summaries, redactions, signature references, packet IDs, and packet digests.
- Added Power House Rootprint anchor helper.
- Added Markdown audit export.
- Added semantic graph validation for duplicate nodes, missing endpoints, and
  cycles.
- Preserved v1 public API and v1 packet verification compatibility.
- Fixed v1 JSON round serialization for new packets while accepting the legacy
  v0.1.0 digest projection.
- Added 10 v2 reference examples: drone perception, zkML classification,
  financial audit, agent trace, multi-agent governance, medical AI decision,
  smart-contract proof, CI formal verification, supply-chain provenance, and
  human approval workflow.
- Added v2 packet specification and explicit trust-boundary documentation.

## v0.1.0 - 2026-06-14

- Added luminous claims and validated visualization hints.
- Added annotated interactive transcripts with strictly ordered rounds.
- Added zero-dependency SHA-256 seed, payload, transcript, and packet digests.
- Added deterministic visualization packet JSON.
- Added mutation, ordering, escaping, public API, and known-hash tests.
