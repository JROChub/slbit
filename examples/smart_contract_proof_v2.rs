use slbit::{ExternalAnchor, LuminousPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("smart-contract-invariant-proof-7", 512)
        .producer("contract-proof-demo", "2.0.0")
        .layer("invariant-check")
        .icon("database")
        .rgb(120, 170, 255)
        .round(
            0,
            b"bytecode",
            "bytecode-binding",
            "Contract bytecode matched the audited commit",
        )
        .round(
            1,
            b"invariant",
            "formal-check",
            "Supply conservation invariant was checked",
        )
        .round(
            2,
            b"proof",
            "proof-anchor",
            "External proof artifact was attached as an anchor",
        )
        .labeled_node("bytecode", "input", "Contract bytecode")
        .labeled_node("invariant", "formal-property", "Supply conservation")
        .labeled_node("proof", "zk-proof", "Invariant proof")
        .labeled_node("result", "decision", "Invariant holds")
        .edge("bytecode", "invariant", "checked-for")
        .edge("invariant", "proof", "proven-by")
        .edge("proof", "result", "supports")
        .anchor(
            ExternalAnchor::new("git-commit", "audited source")
                .with_reference("contract-repo@abc123"),
        )
        .anchor(
            ExternalAnchor::new("snark", "supply invariant proof")
                .with_reference("proofs/supply-invariant.snark")
                .with_digest("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
        )
        .summary_for(
            "developer",
            "The packet explains that audited bytecode was checked against a supply conservation invariant and linked to an external proof.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_json());
    Ok(())
}
