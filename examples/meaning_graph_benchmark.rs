//! Reproducible deep-chain traversal benchmark; timings are local observations.
use slbit::{BoundCore, MeaningNode, MeaningPacket};
use std::time::Instant;

fn main() {
    let count = std::env::args()
        .nth(1)
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(2048);
    assert!((2..=100_000).contains(&count));
    let mut builder = MeaningPacket::builder(
        "benchmark",
        "Traversal",
        "benchmark",
        BoundCore::new(
            "capsule",
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        ),
    );
    for index in 0..count {
        let id = format!("node-{index:06}");
        builder = builder.node(MeaningNode::new(
            &id,
            "evidence",
            "Evidence",
            "Benchmark node",
        ));
        if index > 0 {
            builder = builder.edge(format!("node-{:06}", index - 1), &id, "depends-on");
        }
    }
    let start = Instant::now();
    let packet = builder.build().unwrap();
    let build = start.elapsed();
    let last = format!("node-{:06}", count - 1);
    let start = Instant::now();
    let path = packet
        .shortest_explanation_path("node-000000", &last)
        .unwrap();
    let path_time = start.elapsed();
    assert_eq!(path.len(), count);
    let start = Instant::now();
    let dependencies = packet.dependency_chain(&last).unwrap();
    let dependency_time = start.elapsed();
    assert_eq!(path, dependencies);
    println!("{{\"nodes\":{count},\"build_us\":{},\"path_us\":{},\"dependency_us\":{},\"packet_digest\":\"{}\"}}", build.as_micros(), path_time.as_micros(), dependency_time.as_micros(), packet.packet_digest);
}
