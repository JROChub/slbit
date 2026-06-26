use slbit::{ExternalAnchor, LuminousPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("ci-formal-verification-run-20260626", 1024)
        .producer("ci-verification-demo", "2.0.0")
        .layer("release-gate")
        .icon("git-branch")
        .rgb(185, 255, 61)
        .round(0, b"commit", "source-binding", "Release commit was bound")
        .round(1, b"model-check", "formal-verifier", "State model check passed")
        .round(2, b"ci", "ci-gate", "Release gate accepted the verification report")
        .labeled_node("commit", "git-commit", "Release commit")
        .labeled_node("verifier", "formal-verifier", "State model checker")
        .labeled_node("ci", "policy-check", "CI release gate")
        .labeled_node("release", "decision", "Release eligible")
        .edge("commit", "verifier", "checked-by")
        .edge("verifier", "ci", "reported-to")
        .edge("ci", "release", "authorizes")
        .anchor(
            ExternalAnchor::new("git-commit", "release commit").with_reference("release@f275025"),
        )
        .anchor(
            ExternalAnchor::new("slsa-provenance", "build provenance")
                .with_reference("slsa/release-20260626.json"),
        )
        .summary_for(
            "developer",
            "The CI release gate accepted a formal verification report for the bound release commit.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("developer"));
    Ok(())
}
