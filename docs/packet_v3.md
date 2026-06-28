# SLBIT v3 Meaning Observatory Packet

Status: draft implemented in slbit 3.0.0.

Schema:

```text
slbit/viz-packet/v3
```

SLBIT v3 turns verified proof memory into inspectable meaning. It does not
verify proof-system soundness and does not change Power House `.pha`,
Rootprint, replay, or Memory Capsule identity.

## Core Sections

- `claim`: human-readable claim bound to a Memory Capsule, Rootprint branch, and
  replay fingerprint.
- `transcript`: ordered semantic rounds.
- `semantic_dag`: typed nodes and directed edges.
- `views`: local UI view hints.
- `explanation_constraints`: deterministic limits for local explanation.

## Node Types

Supported node types:

```text
claim evidence round artifact branch merge fork digest warning explanation external_note failure
```

Supported authorities:

```text
core sidecar semantic display generated external
```

UI layers must show authority. A generated or semantic answer is not proof.

## Local Ask Engine

`MeaningPacket::ask()` supports deterministic questions:

```text
what-is-this
what-is-core
what-is-semantic
show-lineage
show-replay
show-failure-boundary
export-llm-context
```

Answers include:

- answer text,
- authority,
- support IDs,
- `not_proven_by_this_answer: true`.

The ask engine is a packet/query engine, not an unconstrained chatbot.

## Digest Rule

`packet_digest` is computed over the deterministic packet JSON with the digest
field excluded. Semantic mutation changes the digest and must be rejected by
`MeaningPacket::verify()`.
