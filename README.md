**slbit**

`slbit` represents the explanatory record associated with a computation: its
annotated transcript, semantic dependencies, and references to externally
verified artifacts. The Rust crate provides deterministic serialization,
packet integrity checks, and graph queries without runtime, build, or
development dependencies.

The distinction between packet integrity and computational validity is part of
the interface. A valid packet establishes that its structure and digest agree.
It does not establish that a referenced proof is sound, that a computation was
executed, or that an explanation is correct. Applications must verify the
underlying artifacts independently. Neither semantic annotations nor their
digests belong in the proof identity, Rootprint lineage, or replay fingerprint
of the computation they describe.

The current v3 representation, `MeaningPacket`, consists of a claim bound to a
Memory Capsule and replay state, an ordered transcript, a directed acyclic
graph of typed annotations, and presentation constraints. Nodes carry explicit
authority labels and may refer to external evidence. These labels are
assertions made by the packet producer; assigning `core` authority does not
authenticate the referenced object. Serialization is deterministic, and packet
verification rejects malformed structure, cyclic dependencies, and digest
mismatches. An annotation change therefore changes the packet digest while leaving
the external computation's identity unchanged. The stable `packet_id` is
derived separately from the claim ID, branch ID, and replay fingerprint.

```toml
[dependencies]
slbit = "3.1.2"
```

The following function constructs a packet from a caller-supplied binding.
Verification of that binding is the caller's responsibility.

```rust
use slbit::{BoundCore, MeaningNode, MeaningPacket, SlbitError};

fn describe_replay(core: BoundCore) -> Result<MeaningPacket, SlbitError> {
    let packet = MeaningPacket::builder("replay-note", "Replay record", "audit", core)
        .node(MeaningNode::new(
            "replay",
            "artifact",
            "Replay state",
            "Reference to the state checked by the application verifier.",
        ).authority("semantic"))
        .node(MeaningNode::new(
            "note",
            "explanation",
            "Audit annotation",
            "This annotation records the producer's interpretation of the replay.",
        ).authority("semantic"))
        .edge("replay", "note", "supports")
        .build()?;

    let report = packet.inspect()?;
    assert!(!report.semantic_changes_affect_core);
    assert_eq!(packet.dependency_chain("note")?, ["replay", "note"]);
    Ok(packet)
}
```

`inspect()` verifies the packet before reporting bindings, authority counts,
unbound nodes, and transcript coverage. `dependency_chain()` returns a
deterministic upstream ordering; `shortest_explanation_path()` returns a
shortest directed path with deterministic tie-breaking. The `ask()` interface
maps supported questions to local packet queries. Its answers carry support identifiers when available and explicitly carry
no proof authority. Most question handlers do not verify packet integrity; call
`verify()` or `inspect()` before treating their support identifiers as checked
packet data. No language model or remote service participates in the query.

Graph validation and dependency traversal use explicit heap storage, so call
stack usage does not grow with graph depth. Shortest-path search retains one
predecessor per reached node instead of copying every partial path. The
[recorded comparison](docs/graph-benchmark-20261018.json) uses the same
2,048-node chain, host, compiler, and packet digest before and after these
changes: path-query time was 426,244 microseconds and 12,399 microseconds,
respectively. These are individual observations, including packet verification,
not statistical estimates or throughput guarantees. A separate 100,000-node
chain run and a 10,000-node regression on a 256 KiB thread stack exercise the
depth boundary. Reproduce the workload with:

```bash
cargo run --release --example meaning_graph_benchmark -- 2048
cargo run --release --example meaning_graph_benchmark -- 100000
cargo test --all-targets --locked
```

The [v3 specification](docs/packet_v3.md) defines the current packet format and
inspection interfaces. [V2](docs/packet_v2.md) retains `LuminousPacket` for
transcripts, external anchors, audience summaries, and redaction records;
[v1](docs/packet_spec.md) remains available for compatibility. Versioned schema
identifiers are independent of the crate version. Changes are recorded in the
[release notes](RELEASE_NOTES.md); complete signatures are in the
[API reference](https://docs.rs/slbit).

Licensed under [AGPL-3.0-only](LICENSE).
