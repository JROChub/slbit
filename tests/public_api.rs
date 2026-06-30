use slbit::{
    BitInteractiveTranscript, LuminousClaim, LuminousPacket, RedactionRecord, SignatureRef,
    SimpleLuminousSumcheck, SlbitError, VizHints, VIZ_PACKET_SCHEMA_V2,
};

#[test]
fn guide_api_compiles_and_verifies() {
    let claim = LuminousClaim::new("guide-example", 4096).with_viz_hints(VizHints {
        color: Some([0, 200, 255]),
        icon: Some("camera".into()),
        layer_name: Some("perception-conv3".into()),
    });
    let mut transcript = BitInteractiveTranscript::new(b"guide-seed");
    transcript.record_round_with_note(
        0,
        &[0xde, 0xad, 0xbe, 0xef],
        "sensor-processing",
        "Raw sensor frame converted into features",
    );
    let luminous = SimpleLuminousSumcheck { claim, transcript };
    let metadata = luminous.to_luminous_metadata();
    let packet = luminous.to_viz_packet().unwrap();
    assert_eq!(metadata.round_count, 1);
    packet.verify().unwrap();
}

#[test]
fn v2_builder_creates_verified_rootprint_linked_packet() {
    let packet = LuminousPacket::builder("drone-camera-frame-7842", 4096)
        .producer("drone-perception-demo", "3.1.0")
        .environment("testnet")
        .seed(b"drone-seed-7842")
        .layer("perception-conv3")
        .icon("camera")
        .rgb(0, 200, 255)
        .round(
            0,
            &[0xde, 0xad, 0xbe, 0xef],
            "sensor-processing",
            "Raw frame converted into features",
        )
        .round(
            1,
            &[0x42],
            "attention-head-7",
            "Stop-sign feature strongly activated",
        )
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
        .summary_for(
            "operator",
            "The drone detected a stop sign and triggered the stop policy.",
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
        .build()
        .unwrap();

    assert_eq!(packet.schema, VIZ_PACKET_SCHEMA_V2);
    packet.verify().unwrap();
    assert!(packet
        .to_json()
        .contains("\"schema\":\"slbit/viz-packet/v2\""));
    assert!(packet.to_json().contains("\"power-house/rootprint\""));
    assert!(packet.to_markdown("operator").contains("stop sign"));

    let mut changed = packet.clone();
    let packet_id = changed.packet_id.clone();
    changed.summaries[0].text.push_str(" Mutated.");
    assert_eq!(packet_id, changed.packet_id);
    assert!(matches!(
        changed.verify(),
        Err(SlbitError::PacketDigestMismatch { .. })
    ));
}

#[test]
fn v2_semantic_graph_rejects_cycles() {
    let error = LuminousPacket::builder("cyclic-agent-trace", 64)
        .round(0, &[1, 2, 3], "tool-call", "Tool call observed")
        .node("a", "observation")
        .node("b", "decision")
        .edge("a", "b", "supports")
        .edge("b", "a", "loops")
        .build()
        .unwrap_err();

    assert!(matches!(error, SlbitError::CycleDetected));
}
