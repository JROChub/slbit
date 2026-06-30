use slbit::{BoundCore, MeaningNode, MeaningPacket, NodeBinding, SlbitError, VIZ_PACKET_SCHEMA_V3};

fn packet() -> MeaningPacket {
    let core = BoundCore::new(
        "phm_earth-001",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    MeaningPacket::builder("claim_earth_001", "EARTH-001", "proof-memory", core)
        .node(
            MeaningNode::new(
                "node_core_001",
                "artifact",
                "Verified core artifact",
                "Power House core verification completed before semantic rendering.",
            )
            .authority("core")
            .binding(
                NodeBinding::new(
                    "rootprint_branch",
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .with_digest(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ),
        )
        .node(MeaningNode::new(
            "node_semantic_001",
            "explanation",
            "Human meaning",
            "Semantic text explains the verified memory but does not change proof identity.",
        ))
        .edge("node_core_001", "node_semantic_001", "explained-by")
        .round(
            0,
            "node_core_001",
            "Core verification",
            "The core artifact and replay fingerprint were checked.",
            b"core",
        )
        .timeline("node_core_001")
        .timeline("node_semantic_001")
        .claim_card("node_semantic_001")
        .graph_view("meaning")
        .build()
        .unwrap()
}

#[test]
fn v3_meaning_packet_verifies_and_answers_questions() {
    let packet = packet();
    assert_eq!(packet.schema, VIZ_PACKET_SCHEMA_V3);
    packet.verify().unwrap();
    assert!(packet
        .to_json()
        .contains("\"schema\":\"slbit/viz-packet/v3\""));

    let answer = packet.ask("what is core truth?");
    assert!(answer.answer.contains("Core truth"));
    assert_eq!(answer.authority, "semantic_summary");
    assert!(answer.not_proven_by_this_answer);
    assert!(!answer.support.is_empty());

    let proved = packet.ask("what did it prove?");
    assert!(proved.answer.contains("semantic packet integrity"));
    assert!(proved.not_proven_by_this_answer);
}

#[test]
fn v3_packet_digest_rejects_semantic_mutation() {
    let mut packet = packet();
    packet.semantic_dag.nodes[1].body.push_str(" Tampered.");
    assert!(matches!(
        packet.verify(),
        Err(SlbitError::PacketDigestMismatch { .. })
    ));
}

#[test]
fn v3_inspection_reports_truth_boundary_and_dependencies() {
    let packet = packet();
    let report = packet.inspect().unwrap();
    assert_eq!(report.semantic_nodes, 2);
    assert_eq!(report.semantic_edges, 1);
    assert_eq!(report.transcript_rounds, 1);
    assert!(report.transcript_nodes_resolved);
    assert!(!report.semantic_changes_affect_core);
    assert!(report.generated_text_is_non_authoritative);
    assert_eq!(report.authority_counts[0].authority, "core");
    assert_eq!(
        packet.dependency_chain("node_semantic_001").unwrap(),
        vec!["node_core_001".to_string(), "node_semantic_001".to_string()]
    );
    assert_eq!(
        packet
            .shortest_explanation_path("node_core_001", "node_semantic_001")
            .unwrap(),
        vec!["node_core_001".to_string(), "node_semantic_001".to_string()]
    );

    let answer = packet.ask("show shortest valid explanation");
    assert_eq!(answer.support.len(), 2);
}

#[test]
fn v3_inspection_rejects_missing_path() {
    let packet = packet();
    let error = packet
        .shortest_explanation_path("node_semantic_001", "node_core_001")
        .unwrap_err();
    assert!(matches!(error, SlbitError::InvalidReference { .. }));
}

#[test]
fn v3_semantic_dag_rejects_cycles() {
    let core = BoundCore::new(
        "phm_cycle",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let error = MeaningPacket::builder("claim_cycle", "Cycle", "test", core)
        .node(MeaningNode::new("a", "claim", "A", "A"))
        .node(MeaningNode::new("b", "evidence", "B", "B"))
        .edge("a", "b", "supports")
        .edge("b", "a", "supports")
        .build()
        .unwrap_err();

    assert!(matches!(error, SlbitError::CycleDetected));
}
