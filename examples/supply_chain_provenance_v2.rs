use slbit::{ExternalAnchor, LuminousPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("supply-chain-artifact-release-19", 2048)
        .producer("supply-chain-demo", "3.1.0")
        .layer("artifact-provenance")
        .icon("database")
        .rgb(69, 221, 210)
        .round(0, b"source", "source-binding", "Source repository and commit were bound")
        .round(1, b"build", "build-attestation", "Builder attestation was attached")
        .round(2, b"artifact", "artifact-fingerprint", "Release artifact digest was recorded")
        .labeled_node("source", "git-commit", "Source commit")
        .labeled_node("builder", "slsa-provenance", "Builder attestation")
        .labeled_node("artifact", "artifact", "Release artifact")
        .labeled_node("release", "decision", "Artifact release")
        .edge("source", "builder", "built-by")
        .edge("builder", "artifact", "produces")
        .edge("artifact", "release", "qualifies")
        .anchor(
            ExternalAnchor::new("git-commit", "source commit").with_reference("repo@19ab"),
        )
        .anchor(
            ExternalAnchor::new("slsa-provenance", "builder provenance")
                .with_reference("provenance/build-19.slsa.json"),
        )
        .anchor(
            ExternalAnchor::new("dataset-fingerprint", "release artifact")
                .with_digest("sha256:3333333333333333333333333333333333333333333333333333333333333333"),
        )
        .summary_for(
            "operator",
            "The packet links source, builder provenance, and release artifact fingerprint in one audit record.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("operator"));
    Ok(())
}
