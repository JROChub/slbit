use slbit::{BitInteractiveTranscript, LuminousClaim, SimpleLuminousSumcheck, VizHints};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let claim = LuminousClaim::new("drone-camera-frame-7842", 4096).with_viz_hints(VizHints {
        color: Some([0, 200, 255]),
        icon: Some("camera".into()),
        layer_name: Some("perception-conv3".into()),
    });

    let mut transcript = BitInteractiveTranscript::new(b"drone-seed-7842");
    transcript.record_round_with_note(
        0,
        &[0xde, 0xad, 0xbe, 0xef],
        "sensor-processing",
        "Raw sensor frame converted into features",
    );
    transcript.record_round_with_note(
        1,
        &[0x42],
        "attention-head-7",
        "Stop-sign feature strongly activated",
    );

    let luminous = SimpleLuminousSumcheck { claim, transcript };
    let metadata = luminous.to_luminous_metadata();
    let packet = luminous.to_viz_packet()?;
    packet.verify()?;

    println!("claim: {}", metadata.claim_id);
    println!("transcript: {}", metadata.transcript_digest);
    println!("{}", packet.to_json());
    Ok(())
}
