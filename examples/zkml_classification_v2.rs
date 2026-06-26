use slbit::{ExternalAnchor, LuminousPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = LuminousPacket::builder("zkml-image-classification-17", 8192)
        .producer("zkml-demo", "2.0.0")
        .layer("classifier-transformer")
        .icon("brain")
        .rgb(130, 180, 255)
        .round(
            0,
            b"embedding-digest",
            "embedding",
            "Image embedding committed with fixed-point activations",
        )
        .round(
            1,
            b"attention-digest",
            "attention-head-3",
            "Vehicle-like feature cluster received strongest attention",
        )
        .round(
            2,
            b"classification-digest",
            "classification",
            "Classification output selected vehicle with confidence band 9200/10000",
        )
        .labeled_node("image-17", "input", "Image 17")
        .labeled_node("embedding", "embedding", "Fixed-point embedding")
        .labeled_node("attention-head-3", "attention", "attention-head-3")
        .labeled_node("vehicle", "classification", "vehicle")
        .edge("image-17", "embedding", "encoded-as")
        .edge("embedding", "attention-head-3", "attended-by")
        .edge("attention-head-3", "vehicle", "supports")
        .anchor(
            ExternalAnchor::new("zk-proof", "classification proof")
                .with_reference("proofs/classification-17.zk")
                .with_digest(
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                ),
        )
        .anchor(
            ExternalAnchor::new("model-card", "classifier-transformer-v4")
                .with_reference("models/classifier-transformer-v4/card.json"),
        )
        .summary_for(
            "developer",
            "The packet explains a zkML image classification without changing the zk proof.",
        )
        .summary_for(
            "operator",
            "The verified model classified the image as vehicle with confidence band 9200/10000.",
        )
        .build()?;

    packet.verify()?;
    println!("{}", packet.to_markdown("operator"));
    Ok(())
}
