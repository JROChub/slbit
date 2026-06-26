use slbit::{LuminousPacket, RedactionRecord, SignatureRef};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("drone-camera-frame-7842", 4096)
        .producer("drone-perception-demo", "2.0.0")
        .environment("testnet")
        .seed(b"drone-seed-7842")
        .layer("perception-conv3")
        .icon("camera")
        .rgb(0, 200, 255)
        .round(
            0,
            &[0xde, 0xad, 0xbe, 0xef],
            "sensor-processing",
            "Raw camera frame converted into features",
        )
        .round(
            1,
            &[0x42],
            "attention-head-7",
            "Stop-sign feature strongly activated",
        )
        .round(
            2,
            &[0x99],
            "safety-policy",
            "Stop-required policy fired",
        )
        .labeled_node("frame-7842", "input", "Camera frame 7842")
        .labeled_node("conv3", "model-layer", "perception-conv3")
        .labeled_node("attention-head-7", "attention", "attention-head-7")
        .labeled_node("stop-sign-detected", "decision", "stop-sign-detected")
        .labeled_node("stop-required", "policy-output", "stop-required")
        .edge("frame-7842", "conv3", "processed-by")
        .edge("conv3", "attention-head-7", "activated")
        .edge("attention-head-7", "stop-sign-detected", "supports")
        .edge("stop-sign-detected", "stop-required", "triggers")
        .anchor_rootprint(
            "drone-perception-7842",
            "rootprint-branch-7842",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .summary_for(
            "operator",
            "The drone detected a stop sign and triggered the stop-required policy.",
        )
        .summary_for(
            "llm_context",
            "A verified perception pipeline observed frame 7842, activated attention-head-7, classified a stop sign, and triggered stop-required.",
        )
        .redaction(RedactionRecord::new(
            "r1",
            "transcript[0].note",
            "privacy",
            "[REDACTED]",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ))
        .signature_ref(SignatureRef::new(
            "safety-officer",
            "external-ed25519",
            "sigref:approval-7842",
        ))
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("operator"));
    Ok(())
}
