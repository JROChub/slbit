use slbit::{ExternalAnchor, LuminousPacket, RedactionRecord};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("medical-triage-decision-884", 4096)
        .producer("medical-ai-demo", "3.1.0")
        .layer("triage-model")
        .icon("brain")
        .rgb(255, 113, 103)
        .round(0, b"vitals", "input-binding", "Patient vitals were committed")
        .round(1, b"model-output", "triage-model", "Risk band elevated")
        .round(
            2,
            b"human-review",
            "clinician-review",
            "Clinician review required before action",
        )
        .labeled_node("vitals", "input", "Committed vitals")
        .labeled_node("model", "model", "Triage model")
        .labeled_node("risk-band", "decision", "Elevated risk band")
        .labeled_node("review", "human-approval", "Clinician review")
        .edge("vitals", "model", "input-to")
        .edge("model", "risk-band", "produces")
        .edge("risk-band", "review", "requires")
        .anchor(
            ExternalAnchor::new("model-card", "triage-model-card")
                .with_reference("models/triage/card.json"),
        )
        .anchor(
            ExternalAnchor::new("regulatory-control", "human-in-the-loop")
                .with_reference("clinical-control-hitl"),
        )
        .summary_for(
            "clinician",
            "The model flagged an elevated risk band and required clinician review before any action.",
        )
        .redaction(RedactionRecord::new(
            "patient-id",
            "claim.id",
            "privacy",
            "[REDACTED]",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("clinician"));
    Ok(())
}
