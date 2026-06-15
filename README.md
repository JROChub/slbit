# slbit

`slbit` is a zero-dependency Rust crate for human-readable semantic layers
around computational proofs.

It provides:

- luminous claims;
- annotated interactive transcript rounds;
- deterministic semantic digests;
- visualization hints;
- canonical visualization packets.

`slbit` does not verify Power House proofs and does not modify proof identity.
It can be used independently or transported beside a Power House `.pha` and
Rootprint graph.

```rust
use slbit::{BitInteractiveTranscript, LuminousClaim, SimpleLuminousSumcheck, VizHints};

let claim = LuminousClaim::new("camera-frame-7842", 4096).with_viz_hints(VizHints {
    color: Some([0, 200, 255]),
    icon: Some("camera".into()),
    layer_name: Some("perception-conv3".into()),
});

let mut transcript = BitInteractiveTranscript::new(b"frame-7842");
transcript.record_round_with_note(
    0,
    &[0xde, 0xad, 0xbe, 0xef],
    "sensor-processing",
    "Raw sensor frame converted into features",
);

let luminous = SimpleLuminousSumcheck { claim, transcript };
let packet = luminous.to_viz_packet()?;
println!("{}", packet.to_json());
# Ok::<(), slbit::SlbitError>(())
```

## Independence

The crate has no normal, build, or development dependencies. Its internal
SHA-256 implementation binds semantic packet content for deterministic
transport; that digest is not a substitute for a cryptographic proof system.

The normative packet format is documented in
[`docs/packet_spec.md`](docs/packet_spec.md).

## License

AGPL-3.0-only.
