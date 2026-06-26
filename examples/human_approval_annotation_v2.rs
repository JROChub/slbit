use slbit::{ExternalAnchor, LuminousPacket, SignatureRef};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("human-approval-workflow-5", 256)
        .producer("approval-demo", "2.0.0")
        .layer("approval-workflow")
        .icon("database")
        .rgb(255, 193, 77)
        .round(0, b"change", "change-request", "High-impact change was requested")
        .round(1, b"risk", "risk-review", "Risk review completed")
        .round(2, b"approval", "human-approval", "Safety officer approved the change")
        .labeled_node("change", "proposal", "High-impact change")
        .labeled_node("risk", "policy-check", "Risk review")
        .labeled_node("approval", "human-approval", "Safety officer approval")
        .labeled_node("decision", "decision", "Change approved")
        .edge("change", "risk", "requires")
        .edge("risk", "approval", "requires")
        .edge("approval", "decision", "authorizes")
        .anchor(
            ExternalAnchor::new("human-approval", "safety officer approval")
                .with_reference("approval-5"),
        )
        .signature_ref(SignatureRef::new(
            "safety-officer",
            "external-ed25519",
            "sigref:approval-5",
        ))
        .summary_for(
            "auditor",
            "The approval workflow records the change request, risk review, and externally referenced safety approval.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("auditor"));
    Ok(())
}
