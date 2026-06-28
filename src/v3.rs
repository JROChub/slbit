//! Version 3 Meaning Observatory packets.

use crate::{
    digest_with_domain, push_json_key, push_json_string, validate_sha256, validate_text,
    SlbitError, MAX_LABEL_BYTES, MAX_NOTE_BYTES, MAX_ROUNDS, VIZ_PACKET_SCHEMA_V3,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const PACKET_DOMAIN_V3: &[u8] = b"SLBIT-PACKET-v3\0";
const PAYLOAD_DOMAIN_V3: &[u8] = b"SLBIT-PAYLOAD-v3\0";
const MAX_NODES: usize = 100_000;
const MAX_EDGES: usize = 250_000;
const MAX_BINDINGS: usize = 64;

/// Core proof-memory binding referenced by a semantic claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundCore {
    /// Bound Memory Capsule identifier.
    pub capsule_id: String,
    /// Bound Rootprint branch identifier.
    pub branch_id: String,
    /// Bound replay fingerprint.
    pub replay_fingerprint: String,
}

impl BoundCore {
    /// Creates a core binding.
    pub fn new(
        capsule_id: impl Into<String>,
        branch_id: impl Into<String>,
        replay_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            capsule_id: capsule_id.into(),
            branch_id: branch_id.into(),
            replay_fingerprint: replay_fingerprint.into(),
        }
    }
}

/// Meaning claim carried by a v3 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningClaim {
    /// Claim identifier.
    pub claim_id: String,
    /// Human-readable label.
    pub label: String,
    /// Claim domain.
    pub domain: String,
    /// Claim status.
    pub status: String,
    /// Bound core memory state.
    pub bound_core: BoundCore,
}

/// Binding from a semantic node to a core or external object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBinding {
    /// Binding kind.
    pub kind: String,
    /// Binding identifier.
    pub id: String,
    /// Optional digest.
    pub digest: Option<String>,
}

impl NodeBinding {
    /// Creates a binding without a digest.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            digest: None,
        }
    }

    /// Adds a digest.
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }
}

/// One v3 transcript round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningRound {
    /// Round index.
    pub round: u64,
    /// Supporting node identifier.
    pub node_id: String,
    /// Round title.
    pub title: String,
    /// Round body.
    pub body: String,
    /// Payload digest.
    pub payload_sha256: String,
}

/// Transcript section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeaningTranscript {
    /// Transcript rounds.
    pub rounds: Vec<MeaningRound>,
}

/// Typed semantic DAG node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningNode {
    /// Stable node identifier.
    pub id: String,
    /// Node type.
    pub node_type: String,
    /// Display label.
    pub label: String,
    /// Human-readable body.
    pub body: String,
    /// Core or external bindings.
    pub bindings: Vec<NodeBinding>,
    /// Authority class.
    pub authority: String,
    /// Proof status label.
    pub proof_status: String,
}

impl MeaningNode {
    /// Creates a semantic node.
    pub fn new(
        id: impl Into<String>,
        node_type: impl Into<String>,
        label: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            node_type: node_type.into(),
            label: label.into(),
            body: body.into(),
            bindings: Vec::new(),
            authority: "semantic".to_string(),
            proof_status: "explains_verified_core".to_string(),
        }
    }

    /// Sets the authority.
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = authority.into();
        self
    }

    /// Adds a binding.
    pub fn binding(mut self, binding: NodeBinding) -> Self {
        self.bindings.push(binding);
        self
    }
}

/// Directed semantic DAG edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningEdge {
    /// Source node.
    pub from: String,
    /// Target node.
    pub to: String,
    /// Edge kind.
    pub kind: String,
}

impl MeaningEdge {
    /// Creates an edge.
    pub fn new(from: impl Into<String>, to: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
        }
    }
}

/// Semantic DAG section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeaningDag {
    /// Nodes.
    pub nodes: Vec<MeaningNode>,
    /// Edges.
    pub edges: Vec<MeaningEdge>,
}

/// UI view descriptors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeaningViews {
    /// Timeline node IDs.
    pub timeline: Vec<String>,
    /// Claim-card node IDs.
    pub claim_cards: Vec<String>,
    /// Graph view names.
    pub graphs: Vec<String>,
    /// Diff view names.
    pub diffs: Vec<String>,
}

/// Explanation constraints for local deterministic answering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplanationConstraints {
    /// Allowed sources for explanations.
    pub allowed_sources: Vec<String>,
    /// Forbid claims not bound to packet data.
    pub forbid_unbound_claims: bool,
    /// Mark generated text as non-authoritative.
    pub mark_generated_text_non_authoritative: bool,
}

impl Default for ExplanationConstraints {
    fn default() -> Self {
        Self {
            allowed_sources: vec![
                "packet_nodes".to_string(),
                "transcript_rounds".to_string(),
                "bound_core_metadata".to_string(),
            ],
            forbid_unbound_claims: true,
            mark_generated_text_non_authoritative: true,
        }
    }
}

/// Structured support item for local answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningSupport {
    /// Support kind.
    pub kind: String,
    /// Support identifier.
    pub id: String,
}

/// Deterministic answer returned by the local ask engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningAnswer {
    /// Answer text.
    pub answer: String,
    /// Answer authority.
    pub authority: String,
    /// Supporting packet identifiers.
    pub support: Vec<MeaningSupport>,
    /// Whether this answer is not itself a proof.
    pub not_proven_by_this_answer: bool,
}

/// SLBIT v3 Meaning Observatory packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningPacket {
    /// Packet schema.
    pub schema: &'static str,
    /// Stable packet identifier.
    pub packet_id: String,
    /// Packet digest.
    pub packet_digest: String,
    /// Human-readable claim.
    pub claim: MeaningClaim,
    /// Transcript.
    pub transcript: MeaningTranscript,
    /// Semantic DAG.
    pub semantic_dag: MeaningDag,
    /// UI views.
    pub views: MeaningViews,
    /// Explanation constraints.
    pub explanation_constraints: ExplanationConstraints,
}

impl MeaningPacket {
    /// Starts a v3 packet builder.
    pub fn builder(
        claim_id: impl Into<String>,
        label: impl Into<String>,
        domain: impl Into<String>,
        bound_core: BoundCore,
    ) -> MeaningPacketBuilder {
        MeaningPacketBuilder::new(claim_id, label, domain, bound_core)
    }

    /// Serializes the packet as deterministic compact JSON.
    pub fn to_json(&self) -> String {
        self.packet_json(true)
    }

    /// Verifies structure, graph integrity, and packet digest.
    pub fn verify(&self) -> Result<(), SlbitError> {
        if self.schema != VIZ_PACKET_SCHEMA_V3 {
            return Err(SlbitError::UnsupportedSchema(self.schema.to_string()));
        }
        validate_packet_v3(self)?;
        let expected = digest_with_domain(PACKET_DOMAIN_V3, self.core_json().as_bytes());
        if expected != self.packet_digest {
            return Err(SlbitError::PacketDigestMismatch {
                expected,
                found: self.packet_digest.clone(),
            });
        }
        Ok(())
    }

    /// Deterministic local query engine.
    pub fn ask(&self, question: &str) -> MeaningAnswer {
        let normalized = normalize_question(question);
        match normalized.as_str() {
            "what-is-this" => self.answer(
                format!(
                    "This is a SLBIT v3 semantic packet for {} in domain {}.",
                    self.claim.label, self.claim.domain
                ),
                vec![support("claim", &self.claim.claim_id)],
            ),
            "what-is-core" | "what-is-core-truth" => self.answer(
                "Core truth is the bound Memory Capsule, Rootprint branch, and replay fingerprint referenced by this packet."
                    .to_string(),
                vec![
                    support("capsule", &self.claim.bound_core.capsule_id),
                    support("branch", &self.claim.bound_core.branch_id),
                ],
            ),
            "what-is-semantic" => self.answer(
                "Semantic meaning is the transcript, typed DAG, and views in this packet; it does not alter proof identity."
                    .to_string(),
                self.semantic_dag
                    .nodes
                    .iter()
                    .map(|node| support("node", &node.id))
                    .collect(),
            ),
            "show-lineage" | "show-replay" => self.answer(
                format!(
                    "Replay is bound to {} on branch {}.",
                    self.claim.bound_core.replay_fingerprint, self.claim.bound_core.branch_id
                ),
                vec![support("replay_fingerprint", &self.claim.bound_core.replay_fingerprint)],
            ),
            "show-failure-boundary" => self.answer(
                "If semantic text changes, the packet digest changes; core proof identity remains external and unchanged."
                    .to_string(),
                vec![support("packet_digest", &self.packet_digest)],
            ),
            "export-llm-context" => self.answer(
                self.to_markdown_context(),
                self.semantic_dag
                    .nodes
                    .iter()
                    .map(|node| support("node", &node.id))
                    .collect(),
            ),
            _ => self.answer(
                "Unsupported deterministic question. Supported questions include what-is-this, what-is-core, what-is-semantic, show-lineage, show-replay, show-failure-boundary, and export-llm-context."
                    .to_string(),
                Vec::new(),
            ),
        }
    }

    /// Exports a Markdown context block for a non-authoritative explanation layer.
    pub fn to_markdown_context(&self) -> String {
        let mut output = String::new();
        output.push_str("# SLBIT v3 Meaning Packet\n\n");
        output.push_str(&format!("- Claim: `{}`\n", self.claim.label));
        output.push_str("- Authority: `semantic`\n");
        output.push_str(&format!(
            "- Bound capsule: `{}`\n",
            self.claim.bound_core.capsule_id
        ));
        output.push_str(&format!(
            "- Bound branch: `{}`\n",
            self.claim.bound_core.branch_id
        ));
        output.push_str(&format!(
            "- Replay fingerprint: `{}`\n\n",
            self.claim.bound_core.replay_fingerprint
        ));
        output.push_str("## Nodes\n\n");
        for node in &self.semantic_dag.nodes {
            output.push_str(&format!(
                "- `{}` `{}`: {}\n",
                node.id, node.authority, node.label
            ));
        }
        output
    }

    fn answer(&self, answer: String, support: Vec<MeaningSupport>) -> MeaningAnswer {
        MeaningAnswer {
            answer,
            authority: "semantic_summary".to_string(),
            support,
            not_proven_by_this_answer: true,
        }
    }

    fn core_json(&self) -> String {
        self.packet_json(false)
    }

    fn packet_json(&self, include_digest: bool) -> String {
        let mut out = String::from("{");
        push_json_key(&mut out, "schema");
        push_json_string(&mut out, self.schema);
        out.push(',');
        push_json_key(&mut out, "packet_id");
        push_json_string(&mut out, &self.packet_id);
        if include_digest {
            out.push(',');
            push_json_key(&mut out, "packet_digest");
            push_json_string(&mut out, &self.packet_digest);
        }
        out.push(',');
        push_json_key(&mut out, "claim");
        push_claim_json(&mut out, &self.claim);
        out.push(',');
        push_json_key(&mut out, "transcript");
        push_transcript_json(&mut out, &self.transcript);
        out.push(',');
        push_json_key(&mut out, "semantic_dag");
        push_dag_json(&mut out, &self.semantic_dag);
        out.push(',');
        push_json_key(&mut out, "views");
        push_views_json(&mut out, &self.views);
        out.push(',');
        push_json_key(&mut out, "explanation_constraints");
        push_constraints_json(&mut out, &self.explanation_constraints);
        out.push('}');
        out
    }
}

impl fmt::Display for MeaningPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_json())
    }
}

/// Builder for SLBIT v3 Meaning Observatory packets.
#[derive(Debug, Clone)]
pub struct MeaningPacketBuilder {
    claim_id: String,
    label: String,
    domain: String,
    status: String,
    bound_core: BoundCore,
    transcript: MeaningTranscript,
    semantic_dag: MeaningDag,
    views: MeaningViews,
    explanation_constraints: ExplanationConstraints,
}

impl MeaningPacketBuilder {
    /// Creates a builder.
    pub fn new(
        claim_id: impl Into<String>,
        label: impl Into<String>,
        domain: impl Into<String>,
        bound_core: BoundCore,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            label: label.into(),
            domain: domain.into(),
            status: "explained".to_string(),
            bound_core,
            transcript: MeaningTranscript::default(),
            semantic_dag: MeaningDag::default(),
            views: MeaningViews::default(),
            explanation_constraints: ExplanationConstraints::default(),
        }
    }

    /// Sets claim status.
    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.status = status.into();
        self
    }

    /// Adds a transcript round.
    pub fn round(
        mut self,
        round: u64,
        node_id: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        payload: &[u8],
    ) -> Self {
        self.transcript.rounds.push(MeaningRound {
            round,
            node_id: node_id.into(),
            title: title.into(),
            body: body.into(),
            payload_sha256: digest_with_domain(PAYLOAD_DOMAIN_V3, payload),
        });
        self
    }

    /// Adds a semantic node.
    pub fn node(mut self, node: MeaningNode) -> Self {
        self.semantic_dag.nodes.push(node);
        self
    }

    /// Adds a semantic edge.
    pub fn edge(
        mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        self.semantic_dag
            .edges
            .push(MeaningEdge::new(from, to, kind));
        self
    }

    /// Adds a timeline node reference.
    pub fn timeline(mut self, node_id: impl Into<String>) -> Self {
        self.views.timeline.push(node_id.into());
        self
    }

    /// Builds and verifies the packet.
    pub fn build(self) -> Result<MeaningPacket, SlbitError> {
        let mut packet = MeaningPacket {
            schema: VIZ_PACKET_SCHEMA_V3,
            packet_id: String::new(),
            packet_digest: String::new(),
            claim: MeaningClaim {
                claim_id: self.claim_id,
                label: self.label,
                domain: self.domain,
                status: self.status,
                bound_core: self.bound_core,
            },
            transcript: self.transcript,
            semantic_dag: self.semantic_dag,
            views: self.views,
            explanation_constraints: self.explanation_constraints,
        };
        validate_packet_v3(&packet)?;
        packet.packet_id = digest_with_domain(
            b"SLBIT-PACKET-ID-v3\0",
            format!(
                "{}\0{}\0{}",
                packet.claim.claim_id,
                packet.claim.bound_core.branch_id,
                packet.claim.bound_core.replay_fingerprint
            )
            .as_bytes(),
        );
        packet.packet_digest = digest_with_domain(PACKET_DOMAIN_V3, packet.core_json().as_bytes());
        packet.verify()?;
        Ok(packet)
    }
}

fn validate_packet_v3(packet: &MeaningPacket) -> Result<(), SlbitError> {
    if !packet.packet_id.is_empty() {
        validate_sha256(&packet.packet_id)?;
    }
    if !packet.packet_digest.is_empty() {
        validate_sha256(&packet.packet_digest)?;
    }
    validate_text("claim.claim_id", &packet.claim.claim_id, MAX_LABEL_BYTES)?;
    validate_text("claim.label", &packet.claim.label, MAX_LABEL_BYTES)?;
    validate_text("claim.domain", &packet.claim.domain, MAX_LABEL_BYTES)?;
    validate_text("claim.status", &packet.claim.status, MAX_LABEL_BYTES)?;
    validate_text(
        "claim.bound_core.capsule_id",
        &packet.claim.bound_core.capsule_id,
        MAX_LABEL_BYTES,
    )?;
    validate_text(
        "claim.bound_core.branch_id",
        &packet.claim.bound_core.branch_id,
        MAX_NOTE_BYTES,
    )?;
    validate_sha256(&packet.claim.bound_core.replay_fingerprint)?;
    validate_rounds_v3(&packet.transcript)?;
    validate_dag_v3(&packet.semantic_dag)?;
    validate_views(&packet.views, &packet.semantic_dag)?;
    Ok(())
}

fn validate_rounds_v3(transcript: &MeaningTranscript) -> Result<(), SlbitError> {
    if transcript.rounds.len() > MAX_ROUNDS {
        return Err(SlbitError::TooManyRounds(transcript.rounds.len()));
    }
    let mut previous = None;
    for round in &transcript.rounds {
        if let Some(previous) = previous {
            if round.round <= previous {
                return Err(SlbitError::NonMonotonicRound {
                    previous,
                    current: round.round,
                });
            }
        }
        previous = Some(round.round);
        validate_text("transcript.node_id", &round.node_id, MAX_LABEL_BYTES)?;
        validate_text("transcript.title", &round.title, MAX_LABEL_BYTES)?;
        validate_text("transcript.body", &round.body, MAX_NOTE_BYTES)?;
        validate_sha256(&round.payload_sha256)?;
    }
    Ok(())
}

fn validate_dag_v3(dag: &MeaningDag) -> Result<(), SlbitError> {
    if dag.nodes.len() > MAX_NODES {
        return Err(SlbitError::TooManyItems {
            field: "semantic_dag.nodes",
            count: dag.nodes.len(),
        });
    }
    if dag.edges.len() > MAX_EDGES {
        return Err(SlbitError::TooManyItems {
            field: "semantic_dag.edges",
            count: dag.edges.len(),
        });
    }
    let mut ids = BTreeSet::new();
    for node in &dag.nodes {
        validate_text("semantic_dag.node.id", &node.id, MAX_LABEL_BYTES)?;
        validate_node_type(&node.node_type)?;
        validate_text("semantic_dag.node.label", &node.label, MAX_LABEL_BYTES)?;
        validate_text("semantic_dag.node.body", &node.body, MAX_NOTE_BYTES)?;
        validate_authority(&node.authority)?;
        validate_text(
            "semantic_dag.node.proof_status",
            &node.proof_status,
            MAX_LABEL_BYTES,
        )?;
        if node.bindings.len() > MAX_BINDINGS {
            return Err(SlbitError::TooManyItems {
                field: "semantic_dag.node.bindings",
                count: node.bindings.len(),
            });
        }
        for binding in &node.bindings {
            validate_text(
                "semantic_dag.node.binding.kind",
                &binding.kind,
                MAX_LABEL_BYTES,
            )?;
            validate_text("semantic_dag.node.binding.id", &binding.id, MAX_NOTE_BYTES)?;
            if let Some(digest) = &binding.digest {
                validate_sha256(digest)?;
            }
        }
        if !ids.insert(node.id.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "semantic_dag.nodes",
                id: node.id.clone(),
            });
        }
    }
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut edges = BTreeSet::new();
    for edge in &dag.edges {
        if !ids.contains(&edge.from) {
            return Err(SlbitError::InvalidReference {
                field: "semantic_dag.edge.from",
                reference: edge.from.clone(),
            });
        }
        if !ids.contains(&edge.to) {
            return Err(SlbitError::InvalidReference {
                field: "semantic_dag.edge.to",
                reference: edge.to.clone(),
            });
        }
        validate_text("semantic_dag.edge.kind", &edge.kind, MAX_LABEL_BYTES)?;
        let identity = format!("{}\0{}\0{}", edge.from, edge.to, edge.kind);
        if !edges.insert(identity.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "semantic_dag.edges",
                id: identity,
            });
        }
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    reject_cycles(&ids, &adjacency)
}

fn reject_cycles(
    ids: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<String>>,
) -> Result<(), SlbitError> {
    fn visit(
        node: &str,
        adjacency: &BTreeMap<String, Vec<String>>,
        temporary: &mut BTreeSet<String>,
        permanent: &mut BTreeSet<String>,
    ) -> Result<(), SlbitError> {
        if permanent.contains(node) {
            return Ok(());
        }
        if !temporary.insert(node.to_string()) {
            return Err(SlbitError::CycleDetected);
        }
        if let Some(children) = adjacency.get(node) {
            for child in children {
                visit(child, adjacency, temporary, permanent)?;
            }
        }
        temporary.remove(node);
        permanent.insert(node.to_string());
        Ok(())
    }

    let mut temporary = BTreeSet::new();
    let mut permanent = BTreeSet::new();
    for id in ids {
        visit(id, adjacency, &mut temporary, &mut permanent)?;
    }
    Ok(())
}

fn validate_views(views: &MeaningViews, dag: &MeaningDag) -> Result<(), SlbitError> {
    let ids = dag
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    for id in views.timeline.iter().chain(views.claim_cards.iter()) {
        validate_text("views.node_ref", id, MAX_LABEL_BYTES)?;
        if !ids.contains(id.as_str()) {
            return Err(SlbitError::InvalidReference {
                field: "views.node_ref",
                reference: id.clone(),
            });
        }
    }
    for value in views.graphs.iter().chain(views.diffs.iter()) {
        validate_text("views.name", value, MAX_LABEL_BYTES)?;
    }
    Ok(())
}

fn validate_node_type(value: &str) -> Result<(), SlbitError> {
    const TYPES: &[&str] = &[
        "claim",
        "evidence",
        "round",
        "artifact",
        "branch",
        "merge",
        "fork",
        "digest",
        "warning",
        "explanation",
        "external_note",
        "failure",
    ];
    if TYPES.contains(&value) {
        Ok(())
    } else {
        Err(SlbitError::InvalidReference {
            field: "semantic_dag.node.type",
            reference: value.to_string(),
        })
    }
}

fn validate_authority(value: &str) -> Result<(), SlbitError> {
    const AUTHORITIES: &[&str] = &[
        "core",
        "sidecar",
        "semantic",
        "display",
        "generated",
        "external",
    ];
    if AUTHORITIES.contains(&value) {
        Ok(())
    } else {
        Err(SlbitError::InvalidReference {
            field: "semantic_dag.node.authority",
            reference: value.to_string(),
        })
    }
}

fn normalize_question(question: &str) -> String {
    let mut normalized = String::new();
    let mut previous_dash = false;
    for character in question.trim().chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            normalized.push(character);
            previous_dash = false;
        } else if (character.is_whitespace() || character == '-' || character == '_')
            && !normalized.is_empty()
            && !previous_dash
        {
            normalized.push('-');
            previous_dash = true;
        }
    }
    if normalized.ends_with('-') {
        normalized.pop();
    }
    normalized
}

fn support(kind: &str, id: &str) -> MeaningSupport {
    MeaningSupport {
        kind: kind.to_string(),
        id: id.to_string(),
    }
}

fn push_claim_json(out: &mut String, claim: &MeaningClaim) {
    out.push('{');
    push_json_key(out, "claim_id");
    push_json_string(out, &claim.claim_id);
    out.push(',');
    push_json_key(out, "label");
    push_json_string(out, &claim.label);
    out.push(',');
    push_json_key(out, "domain");
    push_json_string(out, &claim.domain);
    out.push(',');
    push_json_key(out, "status");
    push_json_string(out, &claim.status);
    out.push(',');
    push_json_key(out, "bound_core");
    push_bound_core_json(out, &claim.bound_core);
    out.push('}');
}

fn push_bound_core_json(out: &mut String, core: &BoundCore) {
    out.push('{');
    push_json_key(out, "capsule_id");
    push_json_string(out, &core.capsule_id);
    out.push(',');
    push_json_key(out, "branch_id");
    push_json_string(out, &core.branch_id);
    out.push(',');
    push_json_key(out, "replay_fingerprint");
    push_json_string(out, &core.replay_fingerprint);
    out.push('}');
}

fn push_transcript_json(out: &mut String, transcript: &MeaningTranscript) {
    out.push('{');
    push_json_key(out, "rounds");
    out.push('[');
    for (index, round) in transcript.rounds.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_key(out, "round");
        out.push_str(&round.round.to_string());
        out.push(',');
        push_json_key(out, "node_id");
        push_json_string(out, &round.node_id);
        out.push(',');
        push_json_key(out, "title");
        push_json_string(out, &round.title);
        out.push(',');
        push_json_key(out, "body");
        push_json_string(out, &round.body);
        out.push(',');
        push_json_key(out, "payload_sha256");
        push_json_string(out, &round.payload_sha256);
        out.push('}');
    }
    out.push_str("]}");
}

fn push_dag_json(out: &mut String, dag: &MeaningDag) {
    out.push('{');
    push_json_key(out, "nodes");
    out.push('[');
    for (index, node) in sorted_nodes(&dag.nodes).into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_node_json(out, node);
    }
    out.push_str("],");
    push_json_key(out, "edges");
    out.push('[');
    for (index, edge) in sorted_edges(&dag.edges).into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_key(out, "from");
        push_json_string(out, &edge.from);
        out.push(',');
        push_json_key(out, "to");
        push_json_string(out, &edge.to);
        out.push(',');
        push_json_key(out, "kind");
        push_json_string(out, &edge.kind);
        out.push('}');
    }
    out.push_str("]}");
}

fn push_node_json(out: &mut String, node: &MeaningNode) {
    out.push('{');
    push_json_key(out, "id");
    push_json_string(out, &node.id);
    out.push(',');
    push_json_key(out, "type");
    push_json_string(out, &node.node_type);
    out.push(',');
    push_json_key(out, "label");
    push_json_string(out, &node.label);
    out.push(',');
    push_json_key(out, "body");
    push_json_string(out, &node.body);
    out.push(',');
    push_json_key(out, "bindings");
    out.push('[');
    for (index, binding) in node.bindings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_key(out, "kind");
        push_json_string(out, &binding.kind);
        out.push(',');
        push_json_key(out, "id");
        push_json_string(out, &binding.id);
        if let Some(digest) = &binding.digest {
            out.push(',');
            push_json_key(out, "digest");
            push_json_string(out, digest);
        }
        out.push('}');
    }
    out.push_str("],");
    push_json_key(out, "authority");
    push_json_string(out, &node.authority);
    out.push(',');
    push_json_key(out, "proof_status");
    push_json_string(out, &node.proof_status);
    out.push('}');
}

fn push_views_json(out: &mut String, views: &MeaningViews) {
    out.push('{');
    push_json_key(out, "timeline");
    push_string_array(out, &views.timeline);
    out.push(',');
    push_json_key(out, "claim_cards");
    push_string_array(out, &views.claim_cards);
    out.push(',');
    push_json_key(out, "graphs");
    push_string_array(out, &views.graphs);
    out.push(',');
    push_json_key(out, "diffs");
    push_string_array(out, &views.diffs);
    out.push('}');
}

fn push_constraints_json(out: &mut String, constraints: &ExplanationConstraints) {
    out.push('{');
    push_json_key(out, "allowed_sources");
    push_string_array(out, &constraints.allowed_sources);
    out.push(',');
    push_json_key(out, "forbid_unbound_claims");
    out.push_str(if constraints.forbid_unbound_claims {
        "true"
    } else {
        "false"
    });
    out.push(',');
    push_json_key(out, "mark_generated_text_non_authoritative");
    out.push_str(if constraints.mark_generated_text_non_authoritative {
        "true"
    } else {
        "false"
    });
    out.push('}');
}

fn push_string_array(out: &mut String, values: &[String]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(out, value);
    }
    out.push(']');
}

fn sorted_nodes(nodes: &[MeaningNode]) -> Vec<&MeaningNode> {
    let mut items = nodes.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| left.id.cmp(&right.id));
    items
}

fn sorted_edges(edges: &[MeaningEdge]) -> Vec<&MeaningEdge> {
    let mut items = edges.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.to.cmp(&right.to))
            .then(left.kind.cmp(&right.kind))
    });
    items
}
