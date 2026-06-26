use slbit::{ExternalAnchor, LuminousPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("multi-agent-governance-vote-12", 2048)
        .producer("governance-demo", "2.0.0")
        .layer("governance-quorum")
        .icon("database")
        .rgb(69, 221, 210)
        .round(0, b"proposal", "proposal", "Treasury parameter update proposed")
        .round(1, b"agent-a", "agent-alpha", "Agent Alpha voted approve")
        .round(2, b"agent-b", "agent-beta", "Agent Beta voted approve")
        .round(3, b"quorum", "quorum-check", "Quorum threshold was satisfied")
        .labeled_node("proposal", "proposal", "Treasury parameter update")
        .labeled_node("agent-alpha", "agent-vote", "Agent Alpha approval")
        .labeled_node("agent-beta", "agent-vote", "Agent Beta approval")
        .labeled_node("quorum", "policy-check", "Quorum threshold")
        .labeled_node("decision", "decision", "Governance update approved")
        .edge("proposal", "agent-alpha", "reviewed-by")
        .edge("proposal", "agent-beta", "reviewed-by")
        .edge("agent-alpha", "quorum", "counts-toward")
        .edge("agent-beta", "quorum", "counts-toward")
        .edge("quorum", "decision", "authorizes")
        .anchor(
            ExternalAnchor::new("human-approval", "governance moderator")
                .with_reference("governance-ticket-12"),
        )
        .summary_for(
            "auditor",
            "Two agents approved the proposal and the quorum policy authorized the governance decision.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("auditor"));
    Ok(())
}
