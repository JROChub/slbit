# SLBIT Visualization Packet v2

Status: draft normative for slbit v0.2.0.

Schema identifier:

```text
slbit/viz-packet/v2
```

## Trust Boundary

An SLBIT packet is a semantic envelope around external verification artifacts.
It is not the proof, not the verifier, and not the source of cryptographic
truth.

SLBIT packets MUST NOT affect:

- proof validity;
- proof soundness;
- proof identity;
- Rootprint branch identity;
- Rootprint replay fingerprints;
- `.pha` fingerprints;
- zk proof equivalence;
- external attestation validity.

SLBIT answers: what happened, why it matters, what it touched, how it should be
displayed, and how another human or machine can inspect the explanation.

## Packet Shape

```json
{
  "schema": "slbit/viz-packet/v2",
  "packet_id": "sha256:...",
  "producer": {},
  "claim": {},
  "anchors": [],
  "transcript": [],
  "semantic_graph": {},
  "visualization": {},
  "summaries": {},
  "redactions": [],
  "signatures": [],
  "digests": {}
}
```

The canonical Rust implementation emits compact JSON with deterministic key
ordering. Arrays that model sets are serialized in sorted deterministic order.
Transcript rounds remain in strictly increasing round order.

## Required Sections

### `producer`

Producer metadata:

- `name`
- `version`
- `environment`
- `metadata`

Metadata is a deterministic key-value object. Implementations MUST reject
duplicate metadata keys.

### `claim`

The semantic claim:

- `id`
- `bit_width`
- `viz_hints`

The claim identifies what the packet explains. It does not identify or validate
the external proof.

### `anchors`

Anchors are deterministic references to external systems. Core SLBIT preserves
the reference; adapters MAY verify the referenced system.

Common anchor types:

- `power-house/rootprint`
- `zk-proof`
- `snark`
- `stark`
- `risc0-receipt`
- `sp1-proof`
- `tee-attestation`
- `model-card`
- `dataset-fingerprint`
- `otel-trace`
- `git-commit`
- `slsa-provenance`
- `human-approval`
- `regulatory-control`

Power House Rootprint anchors SHOULD include:

- `branch_id`
- `replay_fingerprint`
- `sidecar_digest`

### `transcript`

The transcript is a linear explanation path. Each round contains:

- `round`
- `component`
- `note`
- `payload_sha256`

Raw payload bytes are not exported. Payload digests are domain-separated.

### `semantic_graph`

The semantic graph captures non-linear meaning. It is a directed acyclic graph.

```json
{
  "nodes": [
    {"id": "frame-7842", "kind": "input"},
    {"id": "conv3", "kind": "model-layer"},
    {"id": "attention-head-7", "kind": "attention"},
    {"id": "stop-sign-detected", "kind": "decision"}
  ],
  "edges": [
    {"from": "frame-7842", "to": "conv3", "kind": "processed-by"},
    {"from": "conv3", "to": "attention-head-7", "kind": "activated"},
    {"from": "attention-head-7", "to": "stop-sign-detected", "kind": "supports"}
  ]
}
```

Implementations MUST reject duplicate node IDs, duplicate edges, missing edge
endpoints, and cycles.

### `summaries`

Summaries are keyed by audience:

- `developer`
- `auditor`
- `operator`
- `executive`
- `llm_context`

Each summary records whether it is generated, signed, and what source scope it
claims. The core validates structure; it does not verify authorship.

### `redactions`

Redactions preserve integrity without exposing sensitive content:

```json
{
  "redaction_id": "r1",
  "field": "transcript[4].note",
  "reason": "privacy",
  "replacement": "[REDACTED]",
  "original_digest": "sha256:..."
}
```

`original_digest` MUST be a canonical `sha256:` digest.

### `signatures`

Core SLBIT stores signature references. It does not implement signature
verification. Signature adapters MAY verify the referenced scheme.

## Digests

`digests` contains:

- `seed_commitment`
- `transcript`
- `semantic_graph`
- `packet`

`packet_id` is a stable digest over the identity projection:

- claim;
- anchors;
- transcript digest;
- semantic graph digest.

`packet` is a digest over all packet fields except the packet digest itself.

Changing summaries, redactions, or signature references changes the packet
digest. It does not change any external proof identity.

## Compatibility

v1 packets remain supported through the v1 API. v2 does not mutate v1 packet
semantics.

## Conformance Vector Format

Conformance suites SHOULD publish a directory containing:

```text
manifest.json
packet.json
packet.md
mutation/
```

`manifest.json` SHOULD contain:

```json
{
  "schema": "slbit/conformance/v2",
  "slbit_version": "0.2.0",
  "packet_schema": "slbit/viz-packet/v2",
  "packet_id": "sha256:...",
  "packet_digest": "sha256:...",
  "transcript_digest": "sha256:...",
  "semantic_graph_digest": "sha256:...",
  "expected_result": "valid"
}
```

Mutation vectors SHOULD change exactly one semantic field and MUST fail packet
verification unless the packet digest is recomputed by the producer.

## Limits

- claim identifier: 256 UTF-8 bytes;
- labels and identifiers: 128 UTF-8 bytes;
- notes and long references: 4,096 UTF-8 bytes;
- transcript rounds: 1,000,000;
- anchors: 128;
- graph nodes: 100,000;
- graph edges: 250,000;
- summaries: 32;
- redactions: 10,000;
- signature references: 1,000.

Text fields MUST be non-empty and MUST NOT contain control characters.
