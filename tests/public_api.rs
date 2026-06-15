use slbit::{BitInteractiveTranscript, LuminousClaim, SimpleLuminousSumcheck, VizHints};

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
