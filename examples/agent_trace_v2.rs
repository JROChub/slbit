use slbit::{ExternalAnchor, LuminousPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("agent-session-deploy-review-42", 2048)
        .producer("agent-audit-demo", "3.1.0")
        .layer("agent-session")
        .icon("robot")
        .rgb(185, 255, 61)
        .round(
            0,
            b"issue-brief",
            "observation",
            "User requested a production deployment review",
        )
        .round(
            1,
            b"repo-status",
            "tool-call:git-status",
            "Repository status was checked before proposing changes",
        )
        .round(
            2,
            b"ci-result",
            "policy-check",
            "Release gate required tests to pass before merge",
        )
        .round(
            3,
            b"human-approval",
            "human-approval",
            "Human approval was required before publishing",
        )
        .labeled_node("request", "observation", "Deployment review request")
        .labeled_node("git-status", "tool-call", "git status")
        .labeled_node("ci-gate", "policy-check", "CI release gate")
        .labeled_node("approval", "human-approval", "Human approval")
        .labeled_node("decision", "decision", "Proceed after checks")
        .edge("request", "git-status", "requires")
        .edge("git-status", "ci-gate", "feeds")
        .edge("ci-gate", "approval", "requires")
        .edge("approval", "decision", "authorizes")
        .anchor(
            ExternalAnchor::new("git-commit", "reviewed commit")
                .with_reference("f275025")
                .with_metadata("repository", "JROChub/power_house"),
        )
        .anchor(
            ExternalAnchor::new("human-approval", "operator approval")
                .with_reference("approval-ticket-42"),
        )
        .summary_for(
            "auditor",
            "The agent inspected repository state, respected the CI gate, and required human approval before the deployment decision.",
        )
        .summary_for(
            "llm_context",
            "Agent trace with observation, tool call, policy check, human approval, and final decision nodes.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_json());
    Ok(())
}
