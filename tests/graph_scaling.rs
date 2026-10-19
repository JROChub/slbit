use slbit::{BoundCore, MeaningNode, MeaningPacket, SlbitError};

fn graph(count: usize, edges: &[(usize, usize)]) -> MeaningPacket {
    let mut builder = MeaningPacket::builder(
        "scaling",
        "Graph",
        "test",
        BoundCore::new(
            "capsule",
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        ),
    );
    for index in 0..count {
        builder = builder.node(MeaningNode::new(
            format!("n{index:06}"),
            "evidence",
            "Evidence",
            "Node",
        ));
    }
    for &(from, to) in edges {
        builder = builder.edge(format!("n{from:06}"), format!("n{to:06}"), "depends-on");
    }
    builder.build().unwrap()
}

#[test]
fn long_chain_uses_heap_instead_of_recursive_thread_stack() {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let count = 10_000;
            let edges: Vec<_> = (1..count).map(|n| (n - 1, n)).collect();
            let packet = graph(count, &edges);
            let expected: Vec<_> = (0..count).map(|n| format!("n{n:06}")).collect();
            assert_eq!(packet.dependency_chain("n009999").unwrap(), expected);
            assert_eq!(
                packet
                    .shortest_explanation_path("n000000", "n009999")
                    .unwrap(),
                expected
            );
            let mut cycle = packet;
            cycle
                .semantic_dag
                .edges
                .push(slbit::MeaningEdge::new("n009999", "n000000", "cycle"));
            assert!(matches!(cycle.verify(), Err(SlbitError::CycleDetected)));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn diamond_ties_and_dependency_order_are_stable_under_permutation() {
    let edges = [(0, 2), (0, 1), (1, 3), (2, 3), (3, 4), (0, 5)];
    let first = graph(7, &edges);
    let mut reversed = edges;
    reversed.reverse();
    let second = graph(7, &reversed);
    assert_eq!(first.packet_digest, second.packet_digest);
    assert_eq!(
        first
            .shortest_explanation_path("n000000", "n000004")
            .unwrap(),
        ["n000000", "n000001", "n000003", "n000004"]
    );
    assert_eq!(
        first.dependency_chain("n000004").unwrap(),
        ["n000000", "n000001", "n000002", "n000003", "n000004"]
    );
    assert_eq!(
        first.dependency_chain("n000004").unwrap(),
        second.dependency_chain("n000004").unwrap()
    );
    assert_eq!(
        first
            .shortest_explanation_path("n000000", "n000004")
            .unwrap(),
        second
            .shortest_explanation_path("n000000", "n000004")
            .unwrap()
    );
    assert!(first
        .shortest_explanation_path("n000000", "n000006")
        .is_err());
    assert_eq!(
        first
            .shortest_explanation_path("n000006", "n000006")
            .unwrap(),
        ["n000006"]
    );
}

#[test]
fn distinct_edge_kinds_do_not_create_false_cycles() {
    let mut packet = graph(2, &[(0, 1)]);
    packet.semantic_dag.edges.push(slbit::MeaningEdge::new(
        "n000000",
        "n000001",
        "explained-by",
    ));
    // A graph with two edge kinds is acyclic; only the now-stale digest fails.
    assert!(matches!(
        packet.verify(),
        Err(SlbitError::PacketDigestMismatch { .. })
    ));
}
