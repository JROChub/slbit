//! Version 2 luminous packet structures.

use crate::{
    absorb, digest_with_domain, push_hints_json, push_json_key, push_json_string, validate_sha256,
    validate_text, LuminousClaim, SlbitError, VizHints, VizRound, MAX_CLAIM_ID_BYTES,
    MAX_LABEL_BYTES, MAX_NOTE_BYTES, MAX_ROUNDS, VIZ_PACKET_SCHEMA_V2,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const SEED_DOMAIN_V2: &[u8] = b"slbit:transcript-seed:v2\0";
const PAYLOAD_DOMAIN_V2: &[u8] = b"slbit:round-payload:v2\0";
const TRANSCRIPT_DOMAIN_V2: &[u8] = b"slbit:transcript:v2\0";
const SEMANTIC_GRAPH_DOMAIN_V2: &[u8] = b"slbit:semantic-graph:v2\0";
const PACKET_ID_DOMAIN_V2: &[u8] = b"slbit:packet-id:v2\0";
const PACKET_DOMAIN_V2: &[u8] = b"slbit:viz-packet:v2\0";

const MAX_METADATA_FIELDS: usize = 64;
const MAX_ANCHORS: usize = 128;
const MAX_GRAPH_NODES: usize = 100_000;
const MAX_GRAPH_EDGES: usize = 250_000;
const MAX_SUMMARIES: usize = 32;
const MAX_REDACTIONS: usize = 10_000;
const MAX_SIGNATURES: usize = 1_000;

/// Deterministic key-value metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataField {
    /// Metadata key.
    pub key: String,
    /// Metadata value.
    pub value: String,
}

impl MetadataField {
    /// Creates a key-value metadata field.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Packet producer metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Producer {
    /// Producer name.
    pub name: String,
    /// Producer version.
    pub version: String,
    /// Optional deployment environment.
    pub environment: Option<String>,
    /// Additional deterministic metadata.
    pub metadata: Vec<MetadataField>,
}

impl Default for Producer {
    fn default() -> Self {
        Self {
            name: "slbit".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            environment: None,
            metadata: Vec::new(),
        }
    }
}

impl Producer {
    /// Creates producer metadata.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            ..Self::default()
        }
    }
}

/// Deterministic reference to an external verification, provenance, or audit system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalAnchor {
    /// Anchor type, such as `power-house/rootprint`, `zk-proof`, or `otel-trace`.
    pub anchor_type: String,
    /// Human-readable anchor label.
    pub label: String,
    /// Optional stable external identifier, branch, trace, proof, or URI.
    pub reference: Option<String>,
    /// Optional digest or fingerprint associated with the external system.
    pub digest: Option<String>,
    /// Additional deterministic anchor metadata.
    pub metadata: Vec<MetadataField>,
}

impl ExternalAnchor {
    /// Creates a generic external anchor.
    pub fn new(anchor_type: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            anchor_type: anchor_type.into(),
            label: label.into(),
            ..Self::default()
        }
    }

    /// Sets the external reference.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Sets the external digest or fingerprint.
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    /// Adds deterministic anchor metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push(MetadataField::new(key, value));
        self
    }

    /// Creates a Power House Rootprint anchor.
    pub fn rootprint(
        label: impl Into<String>,
        branch_id: impl Into<String>,
        replay_fingerprint: impl Into<String>,
        sidecar_digest: impl Into<String>,
    ) -> Self {
        let branch_id = branch_id.into();
        let replay_fingerprint = replay_fingerprint.into();
        let sidecar_digest = sidecar_digest.into();
        Self::new("power-house/rootprint", label)
            .with_reference(branch_id.clone())
            .with_digest(replay_fingerprint.clone())
            .with_metadata("branch_id", branch_id)
            .with_metadata("replay_fingerprint", replay_fingerprint)
            .with_metadata("sidecar_digest", sidecar_digest)
    }
}

/// A semantic graph node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticNode {
    /// Stable node identifier.
    pub id: String,
    /// Node kind, such as `input`, `model-layer`, `attention`, or `decision`.
    pub kind: String,
    /// Optional display label.
    pub label: Option<String>,
    /// Optional digest or fingerprint bound to the node.
    pub digest: Option<String>,
}

impl SemanticNode {
    /// Creates a semantic graph node.
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            ..Self::default()
        }
    }

    /// Sets a display label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Sets a node digest or fingerprint.
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }
}

/// A directed semantic graph edge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticEdge {
    /// Source node identifier.
    pub from: String,
    /// Destination node identifier.
    pub to: String,
    /// Edge kind, such as `processed-by`, `supports`, or `approved-by`.
    pub kind: String,
    /// Optional display label.
    pub label: Option<String>,
}

impl SemanticEdge {
    /// Creates a directed semantic graph edge.
    pub fn new(from: impl Into<String>, to: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
            label: None,
        }
    }

    /// Sets a display label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Directed acyclic semantic graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticGraph {
    /// Graph nodes.
    pub nodes: Vec<SemanticNode>,
    /// Directed graph edges.
    pub edges: Vec<SemanticEdge>,
}

impl SemanticGraph {
    /// Adds a node.
    pub fn add_node(&mut self, node: SemanticNode) {
        self.nodes.push(node);
    }

    /// Adds an edge.
    pub fn add_edge(&mut self, edge: SemanticEdge) {
        self.edges.push(edge);
    }
}

/// Audience-aware packet summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LuminousSummary {
    /// Audience identifier, such as `developer`, `auditor`, or `llm_context`.
    pub audience: String,
    /// Summary text.
    pub text: String,
    /// Optional author or producing agent.
    pub author: Option<String>,
    /// Whether the summary was machine generated.
    pub generated: bool,
    /// Whether the summary has an external signature reference.
    pub signed: bool,
    /// Source scope, such as `transcript-only` or `transcript-plus-anchors`.
    pub source_scope: String,
}

impl LuminousSummary {
    /// Creates a human-authored transcript-only summary.
    pub fn new(audience: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            text: text.into(),
            source_scope: "transcript-only".to_string(),
            ..Self::default()
        }
    }

    /// Marks the summary as machine generated.
    pub fn generated(mut self, generated: bool) -> Self {
        self.generated = generated;
        self
    }

    /// Marks the summary as externally signed.
    pub fn signed(mut self, signed: bool) -> Self {
        self.signed = signed;
        self
    }

    /// Sets the author.
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Sets the source scope.
    pub fn source_scope(mut self, source_scope: impl Into<String>) -> Self {
        self.source_scope = source_scope.into();
        self
    }
}

/// Deterministic privacy redaction record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionRecord {
    /// Stable redaction identifier.
    pub redaction_id: String,
    /// Redacted field path.
    pub field: String,
    /// Redaction reason.
    pub reason: String,
    /// Replacement text.
    pub replacement: String,
    /// Digest of the original hidden value.
    pub original_digest: String,
}

impl RedactionRecord {
    /// Creates a deterministic redaction record.
    pub fn new(
        redaction_id: impl Into<String>,
        field: impl Into<String>,
        reason: impl Into<String>,
        replacement: impl Into<String>,
        original_digest: impl Into<String>,
    ) -> Self {
        Self {
            redaction_id: redaction_id.into(),
            field: field.into(),
            reason: reason.into(),
            replacement: replacement.into(),
            original_digest: original_digest.into(),
        }
    }
}

/// Reference to an external signature or approval.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureRef {
    /// Signer identifier.
    pub signer: String,
    /// Signature scheme or reference type.
    pub signature_type: String,
    /// Signature value or external signature reference.
    pub signature: String,
}

impl SignatureRef {
    /// Creates a signature reference.
    pub fn new(
        signer: impl Into<String>,
        signature_type: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            signer: signer.into(),
            signature_type: signature_type.into(),
            signature: signature.into(),
        }
    }
}

/// Packet digest section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketDigests {
    /// Domain-separated transcript seed commitment.
    pub seed_commitment: String,
    /// Deterministic transcript digest.
    pub transcript_digest: String,
    /// Deterministic semantic graph digest.
    pub semantic_graph_digest: String,
    /// Deterministic packet digest over all packet fields except this field.
    pub packet_digest: String,
}

/// SLBIT v2 semantic packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuminousPacket {
    /// Packet schema.
    pub schema: &'static str,
    /// Stable packet identifier over the semantic identity projection.
    pub packet_id: String,
    /// Producer metadata.
    pub producer: Producer,
    /// Semantic claim.
    pub claim: LuminousClaim,
    /// External proof, trace, provenance, or approval anchors.
    pub anchors: Vec<ExternalAnchor>,
    /// Human-readable transcript projection.
    pub transcript: Vec<VizRound>,
    /// Directed acyclic semantic graph.
    pub semantic_graph: SemanticGraph,
    /// Packet visualization hints.
    pub visualization: VizHints,
    /// Audience-aware summaries.
    pub summaries: Vec<LuminousSummary>,
    /// Deterministic redaction records.
    pub redactions: Vec<RedactionRecord>,
    /// External signature references.
    pub signatures: Vec<SignatureRef>,
    /// Deterministic packet digests.
    pub digests: PacketDigests,
}

impl LuminousPacket {
    /// Starts a v2 packet builder.
    pub fn builder(claim_id: impl Into<String>, bit_width: u64) -> LuminousPacketBuilder {
        LuminousPacketBuilder::new(claim_id, bit_width)
    }

    /// Serializes the packet as deterministic compact JSON.
    pub fn to_json(&self) -> String {
        self.packet_json(true)
    }

    /// Exports a compact Markdown audit report.
    pub fn to_markdown(&self, audience: &str) -> String {
        let summary = self
            .summaries
            .iter()
            .find(|item| item.audience == audience)
            .or_else(|| self.summaries.first());
        let mut output = String::new();
        output.push_str("# SLBIT Luminous Packet\n\n");
        output.push_str(&format!("- Schema: `{}`\n", self.schema));
        output.push_str(&format!("- Packet ID: `{}`\n", self.packet_id));
        output.push_str(&format!("- Claim: `{}`\n", self.claim.id()));
        output.push_str(&format!("- Bit width: `{}`\n", self.claim.bit_width()));
        output.push_str(&format!(
            "- Transcript digest: `{}`\n",
            self.digests.transcript_digest
        ));
        output.push_str(&format!(
            "- Semantic graph digest: `{}`\n",
            self.digests.semantic_graph_digest
        ));
        output.push_str(&format!(
            "- Packet digest: `{}`\n\n",
            self.digests.packet_digest
        ));
        if let Some(summary) = summary {
            output.push_str("## Summary\n\n");
            output.push_str(&summary.text);
            output.push_str("\n\n");
        }
        output.push_str("## Transcript\n\n");
        for round in &self.transcript {
            output.push_str(&format!(
                "- Round {} `{}`: {}\n",
                round.round, round.component, round.note
            ));
        }
        if !self.anchors.is_empty() {
            output.push_str("\n## Anchors\n\n");
            for anchor in sorted_anchors(&self.anchors) {
                output.push_str(&format!("- `{}`: {}", anchor.anchor_type, anchor.label));
                if let Some(reference) = &anchor.reference {
                    output.push_str(&format!(" (`{reference}`)"));
                }
                output.push('\n');
            }
        }
        output
    }

    /// Verifies structure, DAG validity, and deterministic digests.
    pub fn verify(&self) -> Result<(), SlbitError> {
        if self.schema != VIZ_PACKET_SCHEMA_V2 {
            return Err(SlbitError::UnsupportedSchema(self.schema.to_string()));
        }
        validate_packet(self)?;
        let expected_transcript =
            transcript_digest_v2(&self.digests.seed_commitment, &self.transcript);
        if expected_transcript != self.digests.transcript_digest {
            return Err(SlbitError::TranscriptDigestMismatch {
                expected: expected_transcript,
                found: self.digests.transcript_digest.clone(),
            });
        }
        let expected_graph = digest_with_domain(
            SEMANTIC_GRAPH_DOMAIN_V2,
            semantic_graph_json(&self.semantic_graph).as_bytes(),
        );
        if expected_graph != self.digests.semantic_graph_digest {
            return Err(SlbitError::PacketDigestMismatch {
                expected: expected_graph,
                found: self.digests.semantic_graph_digest.clone(),
            });
        }
        let expected_id = digest_with_domain(PACKET_ID_DOMAIN_V2, self.identity_json().as_bytes());
        if expected_id != self.packet_id {
            return Err(SlbitError::PacketDigestMismatch {
                expected: expected_id,
                found: self.packet_id.clone(),
            });
        }
        let expected_packet = digest_with_domain(PACKET_DOMAIN_V2, self.core_json().as_bytes());
        if expected_packet != self.digests.packet_digest {
            return Err(SlbitError::PacketDigestMismatch {
                expected: expected_packet,
                found: self.digests.packet_digest.clone(),
            });
        }
        Ok(())
    }

    fn core_json(&self) -> String {
        self.packet_json(false)
    }

    fn packet_json(&self, include_packet_digest: bool) -> String {
        let mut output = String::from("{");
        push_json_key(&mut output, "schema");
        push_json_string(&mut output, self.schema);
        output.push(',');
        push_json_key(&mut output, "packet_id");
        push_json_string(&mut output, &self.packet_id);
        output.push(',');
        push_json_key(&mut output, "producer");
        push_producer_json(&mut output, &self.producer);
        output.push(',');
        push_json_key(&mut output, "claim");
        push_claim_json(&mut output, &self.claim);
        output.push(',');
        push_json_key(&mut output, "anchors");
        push_anchor_array_json(&mut output, &self.anchors);
        output.push(',');
        push_json_key(&mut output, "transcript");
        push_transcript_json(&mut output, &self.transcript);
        output.push(',');
        push_json_key(&mut output, "semantic_graph");
        output.push_str(&semantic_graph_json(&self.semantic_graph));
        output.push(',');
        push_json_key(&mut output, "visualization");
        push_hints_json(&mut output, &self.visualization);
        output.push(',');
        push_json_key(&mut output, "summaries");
        push_summary_object_json(&mut output, &self.summaries);
        output.push(',');
        push_json_key(&mut output, "redactions");
        push_redaction_array_json(&mut output, &self.redactions);
        output.push(',');
        push_json_key(&mut output, "signatures");
        push_signature_array_json(&mut output, &self.signatures);
        output.push(',');
        push_json_key(&mut output, "digests");
        push_digests_json(&mut output, &self.digests, include_packet_digest);
        output.push('}');
        output
    }

    fn identity_json(&self) -> String {
        let mut output = String::from("{");
        push_json_key(&mut output, "claim");
        push_claim_json(&mut output, &self.claim);
        output.push(',');
        push_json_key(&mut output, "anchors");
        push_anchor_array_json(&mut output, &self.anchors);
        output.push(',');
        push_json_key(&mut output, "semantic_graph_digest");
        push_json_string(&mut output, &self.digests.semantic_graph_digest);
        output.push(',');
        push_json_key(&mut output, "transcript_digest");
        push_json_string(&mut output, &self.digests.transcript_digest);
        output.push('}');
        output
    }
}

impl fmt::Display for LuminousPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_json())
    }
}

/// Fluent builder for SLBIT v2 packets.
#[derive(Debug, Clone)]
pub struct LuminousPacketBuilder {
    claim_id: String,
    bit_width: u64,
    seed_commitment: String,
    visualization: VizHints,
    producer: Producer,
    anchors: Vec<ExternalAnchor>,
    transcript: Vec<VizRound>,
    semantic_graph: SemanticGraph,
    summaries: Vec<LuminousSummary>,
    redactions: Vec<RedactionRecord>,
    signatures: Vec<SignatureRef>,
}

impl LuminousPacketBuilder {
    /// Creates a new packet builder.
    pub fn new(claim_id: impl Into<String>, bit_width: u64) -> Self {
        let claim_id = claim_id.into();
        Self {
            seed_commitment: digest_with_domain(SEED_DOMAIN_V2, claim_id.as_bytes()),
            claim_id,
            bit_width,
            visualization: VizHints::default(),
            producer: Producer::default(),
            anchors: Vec::new(),
            transcript: Vec::new(),
            semantic_graph: SemanticGraph::default(),
            summaries: Vec::new(),
            redactions: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Binds the transcript to an explicit seed commitment.
    pub fn seed(mut self, seed: &[u8]) -> Self {
        self.seed_commitment = digest_with_domain(SEED_DOMAIN_V2, seed);
        self
    }

    /// Sets producer metadata.
    pub fn producer(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.producer = Producer::new(name, version);
        self
    }

    /// Sets producer environment metadata.
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.producer.environment = Some(environment.into());
        self
    }

    /// Adds producer metadata.
    pub fn producer_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.producer.metadata.push(MetadataField::new(key, value));
        self
    }

    /// Sets the visualization layer name.
    pub fn layer(mut self, layer_name: impl Into<String>) -> Self {
        self.visualization.layer_name = Some(layer_name.into());
        self
    }

    /// Sets the visualization icon.
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.visualization.icon = Some(icon.into());
        self
    }

    /// Sets the visualization RGB color.
    pub fn rgb(mut self, red: u8, green: u8, blue: u8) -> Self {
        self.visualization.color = Some([red, green, blue]);
        self
    }

    /// Adds an annotated transcript round.
    pub fn round(
        mut self,
        round: u64,
        payload: &[u8],
        component: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        self.transcript.push(VizRound {
            round,
            component: component.into(),
            note: note.into(),
            payload_sha256: digest_with_domain(PAYLOAD_DOMAIN_V2, payload),
        });
        self
    }

    /// Adds a semantic graph node.
    pub fn node(mut self, id: impl Into<String>, kind: impl Into<String>) -> Self {
        self.semantic_graph.add_node(SemanticNode::new(id, kind));
        self
    }

    /// Adds a labeled semantic graph node.
    pub fn labeled_node(
        mut self,
        id: impl Into<String>,
        kind: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        self.semantic_graph
            .add_node(SemanticNode::new(id, kind).with_label(label));
        self
    }

    /// Adds a semantic graph edge.
    pub fn edge(
        mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        self.semantic_graph
            .add_edge(SemanticEdge::new(from, to, kind));
        self
    }

    /// Adds a decision node.
    pub fn decision(self, decision_id: impl Into<String>) -> Self {
        self.node(decision_id, "decision")
    }

    /// Adds a generic external anchor.
    pub fn anchor(mut self, anchor: ExternalAnchor) -> Self {
        self.anchors.push(anchor);
        self
    }

    /// Adds a Power House Rootprint anchor.
    pub fn anchor_rootprint(
        self,
        label: impl Into<String>,
        branch_id: impl Into<String>,
        replay_fingerprint: impl Into<String>,
        sidecar_digest: impl Into<String>,
    ) -> Self {
        self.anchor(ExternalAnchor::rootprint(
            label,
            branch_id,
            replay_fingerprint,
            sidecar_digest,
        ))
    }

    /// Adds an audience-aware summary.
    pub fn summary_for(mut self, audience: impl Into<String>, text: impl Into<String>) -> Self {
        self.summaries.push(LuminousSummary::new(audience, text));
        self
    }

    /// Adds a redaction record.
    pub fn redaction(mut self, redaction: RedactionRecord) -> Self {
        self.redactions.push(redaction);
        self
    }

    /// Adds a signature reference.
    pub fn signature_ref(mut self, signature: SignatureRef) -> Self {
        self.signatures.push(signature);
        self
    }

    /// Builds and verifies the v2 packet.
    pub fn build(self) -> Result<LuminousPacket, SlbitError> {
        let claim = LuminousClaim::new(self.claim_id, self.bit_width)
            .with_viz_hints(self.visualization.clone());
        let transcript_digest = transcript_digest_v2(&self.seed_commitment, &self.transcript);
        let semantic_graph_digest = digest_with_domain(
            SEMANTIC_GRAPH_DOMAIN_V2,
            semantic_graph_json(&self.semantic_graph).as_bytes(),
        );
        let mut packet = LuminousPacket {
            schema: VIZ_PACKET_SCHEMA_V2,
            packet_id: String::new(),
            producer: self.producer,
            claim,
            anchors: self.anchors,
            transcript: self.transcript,
            semantic_graph: self.semantic_graph,
            visualization: self.visualization,
            summaries: self.summaries,
            redactions: self.redactions,
            signatures: self.signatures,
            digests: PacketDigests {
                seed_commitment: self.seed_commitment,
                transcript_digest,
                semantic_graph_digest,
                packet_digest: String::new(),
            },
        };
        validate_packet(&packet)?;
        packet.packet_id =
            digest_with_domain(PACKET_ID_DOMAIN_V2, packet.identity_json().as_bytes());
        packet.digests.packet_digest =
            digest_with_domain(PACKET_DOMAIN_V2, packet.core_json().as_bytes());
        packet.verify()?;
        Ok(packet)
    }
}

fn transcript_digest_v2(seed_commitment: &str, rounds: &[VizRound]) -> String {
    let mut bytes = Vec::new();
    absorb(&mut bytes, seed_commitment.as_bytes());
    absorb(&mut bytes, &(rounds.len() as u64).to_be_bytes());
    for round in rounds {
        absorb(&mut bytes, &round.round.to_be_bytes());
        absorb(&mut bytes, round.component.as_bytes());
        absorb(&mut bytes, round.note.as_bytes());
        absorb(&mut bytes, round.payload_sha256.as_bytes());
    }
    digest_with_domain(TRANSCRIPT_DOMAIN_V2, &bytes)
}

fn validate_packet(packet: &LuminousPacket) -> Result<(), SlbitError> {
    validate_claim_v2(&packet.claim)?;
    validate_hints(&packet.visualization)?;
    if packet.claim.viz_hints() != &packet.visualization {
        return Err(SlbitError::InvalidReference {
            field: "visualization",
            reference: "claim.viz_hints mismatch".to_string(),
        });
    }
    validate_producer(&packet.producer)?;
    validate_items("anchors", packet.anchors.len(), MAX_ANCHORS)?;
    validate_items("transcript", packet.transcript.len(), MAX_ROUNDS)?;
    validate_items("summaries", packet.summaries.len(), MAX_SUMMARIES)?;
    validate_items("redactions", packet.redactions.len(), MAX_REDACTIONS)?;
    validate_items("signatures", packet.signatures.len(), MAX_SIGNATURES)?;
    validate_viz_rounds_v2(&packet.transcript)?;
    validate_anchors(&packet.anchors)?;
    validate_graph(&packet.semantic_graph)?;
    validate_summaries(&packet.summaries)?;
    validate_redactions(&packet.redactions)?;
    validate_signatures(&packet.signatures)?;
    if !packet.packet_id.is_empty() {
        validate_sha256(&packet.packet_id)?;
    }
    validate_sha256(&packet.digests.seed_commitment)?;
    validate_sha256(&packet.digests.transcript_digest)?;
    validate_sha256(&packet.digests.semantic_graph_digest)?;
    if !packet.digests.packet_digest.is_empty() {
        validate_sha256(&packet.digests.packet_digest)?;
    }
    Ok(())
}

fn validate_claim_v2(claim: &LuminousClaim) -> Result<(), SlbitError> {
    validate_text("claim.id", claim.id(), MAX_CLAIM_ID_BYTES)?;
    if claim.bit_width() == 0 {
        return Err(SlbitError::InvalidBitWidth);
    }
    validate_hints(claim.viz_hints())
}

fn validate_hints(hints: &VizHints) -> Result<(), SlbitError> {
    if let Some(icon) = &hints.icon {
        validate_text("visualization.icon", icon, MAX_LABEL_BYTES)?;
        if !icon
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(SlbitError::InvalidIcon(icon.clone()));
        }
    }
    if let Some(layer) = &hints.layer_name {
        validate_text("visualization.layer_name", layer, MAX_LABEL_BYTES)?;
    }
    Ok(())
}

fn validate_producer(producer: &Producer) -> Result<(), SlbitError> {
    validate_text("producer.name", &producer.name, MAX_LABEL_BYTES)?;
    validate_text("producer.version", &producer.version, MAX_LABEL_BYTES)?;
    if let Some(environment) = &producer.environment {
        validate_text("producer.environment", environment, MAX_LABEL_BYTES)?;
    }
    validate_metadata("producer.metadata", &producer.metadata)
}

fn validate_metadata(field: &'static str, metadata: &[MetadataField]) -> Result<(), SlbitError> {
    validate_items(field, metadata.len(), MAX_METADATA_FIELDS)?;
    let mut keys = BTreeSet::new();
    for item in metadata {
        validate_text(field, &item.key, MAX_LABEL_BYTES)?;
        validate_text(field, &item.value, MAX_NOTE_BYTES)?;
        if !keys.insert(item.key.clone()) {
            return Err(SlbitError::DuplicateId {
                field,
                id: item.key.clone(),
            });
        }
    }
    Ok(())
}

fn validate_viz_rounds_v2(rounds: &[VizRound]) -> Result<(), SlbitError> {
    let mut previous = None;
    for round in rounds {
        if let Some(previous) = previous {
            if round.round <= previous {
                return Err(SlbitError::NonMonotonicRound {
                    previous,
                    current: round.round,
                });
            }
        }
        previous = Some(round.round);
        validate_text("transcript.component", &round.component, MAX_LABEL_BYTES)?;
        validate_text("transcript.note", &round.note, MAX_NOTE_BYTES)?;
        validate_sha256(&round.payload_sha256)?;
    }
    Ok(())
}

fn validate_anchors(anchors: &[ExternalAnchor]) -> Result<(), SlbitError> {
    let mut seen = BTreeSet::new();
    for anchor in anchors {
        validate_text("anchor.anchor_type", &anchor.anchor_type, MAX_LABEL_BYTES)?;
        validate_text("anchor.label", &anchor.label, MAX_LABEL_BYTES)?;
        if let Some(reference) = &anchor.reference {
            validate_text("anchor.reference", reference, MAX_NOTE_BYTES)?;
        }
        if let Some(digest) = &anchor.digest {
            validate_text("anchor.digest", digest, MAX_NOTE_BYTES)?;
        }
        validate_metadata("anchor.metadata", &anchor.metadata)?;
        let identity = format!(
            "{}\0{}\0{}",
            anchor.anchor_type,
            anchor.label,
            anchor.reference.as_deref().unwrap_or("")
        );
        if !seen.insert(identity.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "anchors",
                id: identity,
            });
        }
    }
    Ok(())
}

fn validate_graph(graph: &SemanticGraph) -> Result<(), SlbitError> {
    validate_items("semantic_graph.nodes", graph.nodes.len(), MAX_GRAPH_NODES)?;
    validate_items("semantic_graph.edges", graph.edges.len(), MAX_GRAPH_EDGES)?;
    let mut ids = BTreeSet::new();
    for node in &graph.nodes {
        validate_text("semantic_graph.node.id", &node.id, MAX_LABEL_BYTES)?;
        validate_text("semantic_graph.node.kind", &node.kind, MAX_LABEL_BYTES)?;
        if let Some(label) = &node.label {
            validate_text("semantic_graph.node.label", label, MAX_LABEL_BYTES)?;
        }
        if let Some(digest) = &node.digest {
            validate_text("semantic_graph.node.digest", digest, MAX_NOTE_BYTES)?;
        }
        if !ids.insert(node.id.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "semantic_graph.nodes",
                id: node.id.clone(),
            });
        }
    }
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut edges = BTreeSet::new();
    for edge in &graph.edges {
        validate_text("semantic_graph.edge.from", &edge.from, MAX_LABEL_BYTES)?;
        validate_text("semantic_graph.edge.to", &edge.to, MAX_LABEL_BYTES)?;
        validate_text("semantic_graph.edge.kind", &edge.kind, MAX_LABEL_BYTES)?;
        if let Some(label) = &edge.label {
            validate_text("semantic_graph.edge.label", label, MAX_LABEL_BYTES)?;
        }
        if !ids.contains(&edge.from) {
            return Err(SlbitError::InvalidReference {
                field: "semantic_graph.edge.from",
                reference: edge.from.clone(),
            });
        }
        if !ids.contains(&edge.to) {
            return Err(SlbitError::InvalidReference {
                field: "semantic_graph.edge.to",
                reference: edge.to.clone(),
            });
        }
        let identity = format!("{}\0{}\0{}", edge.from, edge.to, edge.kind);
        if !edges.insert(identity.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "semantic_graph.edges",
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

fn validate_summaries(summaries: &[LuminousSummary]) -> Result<(), SlbitError> {
    let mut audiences = BTreeSet::new();
    for summary in summaries {
        validate_text("summary.audience", &summary.audience, MAX_LABEL_BYTES)?;
        validate_text("summary.text", &summary.text, MAX_NOTE_BYTES)?;
        validate_text(
            "summary.source_scope",
            &summary.source_scope,
            MAX_LABEL_BYTES,
        )?;
        if let Some(author) = &summary.author {
            validate_text("summary.author", author, MAX_LABEL_BYTES)?;
        }
        if !audiences.insert(summary.audience.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "summaries",
                id: summary.audience.clone(),
            });
        }
    }
    Ok(())
}

fn validate_redactions(redactions: &[RedactionRecord]) -> Result<(), SlbitError> {
    let mut ids = BTreeSet::new();
    for redaction in redactions {
        validate_text(
            "redaction.redaction_id",
            &redaction.redaction_id,
            MAX_LABEL_BYTES,
        )?;
        validate_text("redaction.field", &redaction.field, MAX_NOTE_BYTES)?;
        validate_text("redaction.reason", &redaction.reason, MAX_LABEL_BYTES)?;
        validate_text(
            "redaction.replacement",
            &redaction.replacement,
            MAX_LABEL_BYTES,
        )?;
        validate_sha256(&redaction.original_digest)?;
        if !ids.insert(redaction.redaction_id.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "redactions",
                id: redaction.redaction_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_signatures(signatures: &[SignatureRef]) -> Result<(), SlbitError> {
    let mut ids = BTreeSet::new();
    for signature in signatures {
        validate_text("signature.signer", &signature.signer, MAX_LABEL_BYTES)?;
        validate_text(
            "signature.signature_type",
            &signature.signature_type,
            MAX_LABEL_BYTES,
        )?;
        validate_text("signature.signature", &signature.signature, MAX_NOTE_BYTES)?;
        let identity = format!(
            "{}\0{}\0{}",
            signature.signer, signature.signature_type, signature.signature
        );
        if !ids.insert(identity.clone()) {
            return Err(SlbitError::DuplicateId {
                field: "signatures",
                id: identity,
            });
        }
    }
    Ok(())
}

fn validate_items(field: &'static str, count: usize, max: usize) -> Result<(), SlbitError> {
    if count > max {
        Err(SlbitError::TooManyItems { field, count })
    } else {
        Ok(())
    }
}

fn sorted_metadata(metadata: &[MetadataField]) -> Vec<&MetadataField> {
    let mut items = metadata.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| left.key.cmp(&right.key).then(left.value.cmp(&right.value)));
    items
}

fn sorted_anchors(anchors: &[ExternalAnchor]) -> Vec<&ExternalAnchor> {
    let mut items = anchors.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.anchor_type
            .cmp(&right.anchor_type)
            .then(left.label.cmp(&right.label))
            .then(left.reference.cmp(&right.reference))
            .then(left.digest.cmp(&right.digest))
    });
    items
}

fn sorted_nodes(nodes: &[SemanticNode]) -> Vec<&SemanticNode> {
    let mut items = nodes.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| left.id.cmp(&right.id).then(left.kind.cmp(&right.kind)));
    items
}

fn sorted_edges(edges: &[SemanticEdge]) -> Vec<&SemanticEdge> {
    let mut items = edges.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.to.cmp(&right.to))
            .then(left.kind.cmp(&right.kind))
    });
    items
}

fn sorted_summaries(summaries: &[LuminousSummary]) -> Vec<&LuminousSummary> {
    let mut items = summaries.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| left.audience.cmp(&right.audience));
    items
}

fn sorted_redactions(redactions: &[RedactionRecord]) -> Vec<&RedactionRecord> {
    let mut items = redactions.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| left.redaction_id.cmp(&right.redaction_id));
    items
}

fn sorted_signatures(signatures: &[SignatureRef]) -> Vec<&SignatureRef> {
    let mut items = signatures.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.signer
            .cmp(&right.signer)
            .then(left.signature_type.cmp(&right.signature_type))
            .then(left.signature.cmp(&right.signature))
    });
    items
}

fn push_optional_string(output: &mut String, key: &str, value: &Option<String>, wrote: &mut bool) {
    if let Some(value) = value {
        if *wrote {
            output.push(',');
        }
        push_json_key(output, key);
        push_json_string(output, value);
        *wrote = true;
    }
}

fn push_metadata_json(output: &mut String, metadata: &[MetadataField]) {
    output.push('{');
    for (index, item) in sorted_metadata(metadata).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_key(output, &item.key);
        push_json_string(output, &item.value);
    }
    output.push('}');
}

fn push_producer_json(output: &mut String, producer: &Producer) {
    output.push('{');
    push_json_key(output, "environment");
    if let Some(environment) = &producer.environment {
        push_json_string(output, environment);
    } else {
        output.push_str("null");
    }
    output.push(',');
    push_json_key(output, "metadata");
    push_metadata_json(output, &producer.metadata);
    output.push(',');
    push_json_key(output, "name");
    push_json_string(output, &producer.name);
    output.push(',');
    push_json_key(output, "version");
    push_json_string(output, &producer.version);
    output.push('}');
}

fn push_claim_json(output: &mut String, claim: &LuminousClaim) {
    output.push('{');
    push_json_key(output, "bit_width");
    output.push_str(&claim.bit_width().to_string());
    output.push(',');
    push_json_key(output, "id");
    push_json_string(output, claim.id());
    output.push(',');
    push_json_key(output, "viz_hints");
    push_hints_json(output, claim.viz_hints());
    output.push('}');
}

fn push_anchor_json(output: &mut String, anchor: &ExternalAnchor) {
    output.push('{');
    push_json_key(output, "anchor_type");
    push_json_string(output, &anchor.anchor_type);
    output.push(',');
    push_json_key(output, "digest");
    if let Some(digest) = &anchor.digest {
        push_json_string(output, digest);
    } else {
        output.push_str("null");
    }
    output.push(',');
    push_json_key(output, "label");
    push_json_string(output, &anchor.label);
    output.push(',');
    push_json_key(output, "metadata");
    push_metadata_json(output, &anchor.metadata);
    output.push(',');
    push_json_key(output, "reference");
    if let Some(reference) = &anchor.reference {
        push_json_string(output, reference);
    } else {
        output.push_str("null");
    }
    output.push('}');
}

fn push_anchor_array_json(output: &mut String, anchors: &[ExternalAnchor]) {
    output.push('[');
    for (index, anchor) in sorted_anchors(anchors).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_anchor_json(output, anchor);
    }
    output.push(']');
}

fn push_transcript_json(output: &mut String, rounds: &[VizRound]) {
    output.push('[');
    for (index, round) in rounds.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('{');
        push_json_key(output, "component");
        push_json_string(output, &round.component);
        output.push(',');
        push_json_key(output, "note");
        push_json_string(output, &round.note);
        output.push(',');
        push_json_key(output, "payload_sha256");
        push_json_string(output, &round.payload_sha256);
        output.push(',');
        push_json_key(output, "round");
        output.push_str(&round.round.to_string());
        output.push('}');
    }
    output.push(']');
}

fn semantic_graph_json(graph: &SemanticGraph) -> String {
    let mut output = String::from("{");
    push_json_key(&mut output, "edges");
    output.push('[');
    for (index, edge) in sorted_edges(&graph.edges).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('{');
        push_json_key(&mut output, "from");
        push_json_string(&mut output, &edge.from);
        output.push(',');
        push_json_key(&mut output, "kind");
        push_json_string(&mut output, &edge.kind);
        let mut wrote = true;
        push_optional_string(&mut output, "label", &edge.label, &mut wrote);
        output.push(',');
        push_json_key(&mut output, "to");
        push_json_string(&mut output, &edge.to);
        output.push('}');
    }
    output.push(']');
    output.push(',');
    push_json_key(&mut output, "nodes");
    output.push('[');
    for (index, node) in sorted_nodes(&graph.nodes).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('{');
        push_json_key(&mut output, "id");
        push_json_string(&mut output, &node.id);
        output.push(',');
        push_json_key(&mut output, "kind");
        push_json_string(&mut output, &node.kind);
        let mut wrote = true;
        push_optional_string(&mut output, "label", &node.label, &mut wrote);
        push_optional_string(&mut output, "digest", &node.digest, &mut wrote);
        output.push('}');
    }
    output.push(']');
    output.push('}');
    output
}

fn push_summary_object_json(output: &mut String, summaries: &[LuminousSummary]) {
    output.push('{');
    for (index, summary) in sorted_summaries(summaries).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_key(output, &summary.audience);
        output.push('{');
        push_json_key(output, "author");
        if let Some(author) = &summary.author {
            push_json_string(output, author);
        } else {
            output.push_str("null");
        }
        output.push(',');
        push_json_key(output, "generated");
        output.push_str(if summary.generated { "true" } else { "false" });
        output.push(',');
        push_json_key(output, "signed");
        output.push_str(if summary.signed { "true" } else { "false" });
        output.push(',');
        push_json_key(output, "source_scope");
        push_json_string(output, &summary.source_scope);
        output.push(',');
        push_json_key(output, "text");
        push_json_string(output, &summary.text);
        output.push('}');
    }
    output.push('}');
}

fn push_redaction_array_json(output: &mut String, redactions: &[RedactionRecord]) {
    output.push('[');
    for (index, redaction) in sorted_redactions(redactions).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('{');
        push_json_key(output, "field");
        push_json_string(output, &redaction.field);
        output.push(',');
        push_json_key(output, "original_digest");
        push_json_string(output, &redaction.original_digest);
        output.push(',');
        push_json_key(output, "reason");
        push_json_string(output, &redaction.reason);
        output.push(',');
        push_json_key(output, "redaction_id");
        push_json_string(output, &redaction.redaction_id);
        output.push(',');
        push_json_key(output, "replacement");
        push_json_string(output, &redaction.replacement);
        output.push('}');
    }
    output.push(']');
}

fn push_signature_array_json(output: &mut String, signatures: &[SignatureRef]) {
    output.push('[');
    for (index, signature) in sorted_signatures(signatures).iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('{');
        push_json_key(output, "signature");
        push_json_string(output, &signature.signature);
        output.push(',');
        push_json_key(output, "signature_type");
        push_json_string(output, &signature.signature_type);
        output.push(',');
        push_json_key(output, "signer");
        push_json_string(output, &signature.signer);
        output.push('}');
    }
    output.push(']');
}

fn push_digests_json(output: &mut String, digests: &PacketDigests, include_packet_digest: bool) {
    output.push('{');
    if include_packet_digest {
        push_json_key(output, "packet");
        push_json_string(output, &digests.packet_digest);
        output.push(',');
    }
    push_json_key(output, "seed_commitment");
    push_json_string(output, &digests.seed_commitment);
    output.push(',');
    push_json_key(output, "semantic_graph");
    push_json_string(output, &digests.semantic_graph_digest);
    output.push(',');
    push_json_key(output, "transcript");
    push_json_string(output, &digests.transcript_digest);
    output.push('}');
}
