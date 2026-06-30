use slbit::{ExternalAnchor, LuminousPacket, RedactionRecord};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("risk-model-audit-2026-06", 1024)
        .producer("risk-audit-demo", "3.1.0")
        .layer("credit-risk-model")
        .icon("database")
        .rgb(255, 193, 77)
        .round(
            0,
            b"dataset-fingerprint",
            "dataset-binding",
            "Input portfolio dataset matched approved fingerprint",
        )
        .round(
            1,
            b"risk-score-output",
            "risk-model",
            "Risk score bucket was computed from committed features",
        )
        .round(
            2,
            b"policy-control",
            "regulatory-control",
            "Adverse-action review control was applied",
        )
        .labeled_node("dataset", "dataset", "Approved portfolio dataset")
        .labeled_node("risk-model", "model", "Credit risk model")
        .labeled_node("risk-score", "decision", "Risk score bucket")
        .labeled_node("control", "regulatory-control", "Adverse-action review")
        .edge("dataset", "risk-model", "input-to")
        .edge("risk-model", "risk-score", "produces")
        .edge("risk-score", "control", "checked-by")
        .anchor(
            ExternalAnchor::new("dataset-fingerprint", "portfolio dataset")
                .with_digest("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        )
        .anchor(
            ExternalAnchor::new("regulatory-control", "adverse-action review")
                .with_reference("control-aa-2026-06"),
        )
        .summary_for(
            "auditor",
            "The packet records the dataset binding, model decision path, and regulatory control applied to the risk score.",
        )
        .summary_for(
            "executive",
            "The audit trail shows the risk model used the approved dataset and applied the required control.",
        )
        .redaction(RedactionRecord::new(
            "customer-id",
            "transcript[0].note",
            "privacy",
            "[REDACTED]",
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ))
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("auditor"));
    Ok(())
}
