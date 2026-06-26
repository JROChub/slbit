# slbit

`slbit` is a zero-dependency Rust crate for luminous semantic packets: portable,
deterministic explanation artifacts that sit beside proofs, zkML outputs,
agent traces, Rootprint graphs, attestations, and audit logs.

It does not replace proof systems. It answers the question proof systems leave
open: what happened, why did it matter, and how should a human or another
system inspect it?

## Trust Boundary

`slbit` packets are observation and meaning data. They MUST NOT be used as
proof validity, proof soundness, proof identity, Rootprint lineage, replay
fingerprint, or cryptographic equivalence inputs.

Changing an `slbit` packet changes the `slbit` packet digest. It must not
change the identity of the external proof, `.pha` artifact, Rootprint graph,
zk proof, attestation, model output, or agent action it describes.

## What 0.2.0 Adds

- `slbit/viz-packet/v2`
- stable packet IDs;
- producer metadata;
- external anchors such as Power House Rootprint, zk proofs, OpenTelemetry
  traces, SLSA provenance, model cards, and human approvals;
- directed acyclic semantic graphs;
- audience-aware summaries;
- deterministic privacy redaction records;
- external signature references;
- deterministic packet, transcript, and semantic graph digests;
- fluent Rust builder API;
- Markdown audit export;
- v1 verification compatibility.

The crate still has no normal, build, or development dependencies.

## Example

```rust
use slbit::LuminousPacket;

let packet = LuminousPacket::builder("drone-camera-frame-7842", 4096)
    .producer("drone-perception-demo", "2.0.0")
    .layer("perception-conv3")
    .icon("camera")
    .rgb(0, 200, 255)
    .round(0, &[0xde, 0xad, 0xbe, 0xef], "sensor-processing", "Raw frame converted into features")
    .round(1, &[0x42], "attention-head-7", "Stop-sign feature strongly activated")
    .labeled_node("frame-7842", "input", "Camera frame 7842")
    .labeled_node("conv3", "model-layer", "perception-conv3")
    .labeled_node("attention-head-7", "attention", "attention-head-7")
    .labeled_node("stop-sign-detected", "decision", "stop-sign-detected")
    .edge("frame-7842", "conv3", "processed-by")
    .edge("conv3", "attention-head-7", "activated")
    .edge("attention-head-7", "stop-sign-detected", "supports")
    .anchor_rootprint(
        "drone-perception-7842",
        "rootprint-branch-7842",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .summary_for("operator", "The drone detected a stop sign and triggered the stop policy.")
    .build()?;

packet.verify()?;
println!("{}", packet.to_markdown("operator"));
# Ok::<(), slbit::SlbitError>(())
```

## v1 Compatibility

The v1 API remains available:

- `LuminousClaim`
- `BitInteractiveTranscript`
- `SimpleLuminousSumcheck`
- `VizPacket`

`slbit` 0.2.0 emits corrected deterministic v1 JSON and still accepts legacy
v0.1.0 packet digests during verification.

## Documentation

- [`docs/packet_spec.md`](docs/packet_spec.md): v1 compatibility spec.
- [`docs/packet_v2.md`](docs/packet_v2.md): v2 packet standard draft.

## v2 Reference Examples

- `drone_perception_v2`
- `zkml_classification_v2`
- `financial_audit_v2`
- `agent_trace_v2`
- `multi_agent_governance_v2`
- `medical_ai_decision_v2`
- `smart_contract_proof_v2`
- `ci_formal_verification_v2`
- `supply_chain_provenance_v2`
- `human_approval_annotation_v2`

## License

AGPL-3.0-only.
