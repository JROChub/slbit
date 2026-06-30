#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Human-readable semantic transcripts and visualization metadata.
//!
//! `slbit` is deliberately independent of proof systems. It observes and
//! annotates proof execution without changing proof identity or validity.

mod v2;
mod v3;

use std::error::Error;
use std::fmt;

pub use v2::{
    ExternalAnchor, LuminousPacket, LuminousPacketBuilder, LuminousSummary, MetadataField,
    PacketDigests, Producer, RedactionRecord, SemanticEdge, SemanticGraph, SemanticNode,
    SignatureRef,
};
pub use v3::{
    AuthorityCount, BoundCore, ExplanationConstraints, MeaningAnswer, MeaningBoundaryReport,
    MeaningClaim, MeaningDag, MeaningEdge, MeaningNode, MeaningPacket, MeaningPacketBuilder,
    MeaningRound, MeaningSupport, MeaningTranscript, MeaningViews, NodeBinding,
};

/// Schema identifier for luminous metadata.
pub const LUMINOUS_METADATA_SCHEMA_V1: &str = "slbit/luminous-metadata/v1";
/// Schema identifier for visualization packets.
pub const VIZ_PACKET_SCHEMA_V1: &str = "slbit/viz-packet/v1";
/// Schema identifier for version 2 luminous visualization packets.
pub const VIZ_PACKET_SCHEMA_V2: &str = "slbit/viz-packet/v2";
/// Schema identifier for version 3 Meaning Observatory packets.
pub const VIZ_PACKET_SCHEMA_V3: &str = "slbit/viz-packet/v3";
/// Schema identifier for append-only annotation sidecars.
pub const ANNOTATION_SIDECAR_SCHEMA_V1: &str = "slbit/annotation-sidecar/v1";

const SEED_DOMAIN: &[u8] = b"slbit:transcript-seed:v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"slbit:round-payload:v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"slbit:transcript:v1\0";
const PACKET_DOMAIN: &[u8] = b"slbit:viz-packet:v1\0";
pub(crate) const MAX_CLAIM_ID_BYTES: usize = 256;
pub(crate) const MAX_LABEL_BYTES: usize = 128;
pub(crate) const MAX_NOTE_BYTES: usize = 4096;
pub(crate) const MAX_ROUNDS: usize = 1_000_000;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Optional presentation hints for a luminous claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VizHints {
    /// RGB node color.
    pub color: Option<[u8; 3]>,
    /// Lowercase icon identifier such as `camera` or `database`.
    pub icon: Option<String>,
    /// Human-readable computational layer name.
    pub layer_name: Option<String>,
}

/// A semantic claim that can be visualized independently of proof validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuminousClaim {
    id: String,
    bit_width: u64,
    viz_hints: VizHints,
}

impl LuminousClaim {
    /// Creates a claim with no visualization hints.
    pub fn new(id: impl Into<String>, bit_width: u64) -> Self {
        Self {
            id: id.into(),
            bit_width,
            viz_hints: VizHints::default(),
        }
    }

    /// Returns a claim carrying the supplied visualization hints.
    pub fn with_viz_hints(mut self, viz_hints: VizHints) -> Self {
        self.viz_hints = viz_hints;
        self
    }

    /// Returns the stable semantic claim identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the logical claim width in bits.
    pub fn bit_width(&self) -> u64 {
        self.bit_width
    }

    /// Returns visualization hints.
    pub fn viz_hints(&self) -> &VizHints {
        &self.viz_hints
    }
}

/// One annotated transcript round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptRound {
    round: u64,
    payload: Vec<u8>,
    component: String,
    note: String,
}

impl TranscriptRound {
    /// Returns the round number.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Returns the opaque round payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the producing component or layer.
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the human-readable round annotation.
    pub fn note(&self) -> &str {
        &self.note
    }
}

/// An ordered transcript with semantic annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitInteractiveTranscript {
    seed_commitment: String,
    rounds: Vec<TranscriptRound>,
}

impl BitInteractiveTranscript {
    /// Creates an empty transcript bound to a private or public seed.
    ///
    /// Only the domain-separated seed commitment appears in exported packets.
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed_commitment: digest_with_domain(SEED_DOMAIN, seed),
            rounds: Vec::new(),
        }
    }

    /// Records an annotated round and returns the transcript for chaining.
    ///
    /// Structural limits and ordering are checked by
    /// [`SimpleLuminousSumcheck::to_viz_packet`].
    pub fn record_round_with_note(
        &mut self,
        round: u64,
        payload: &[u8],
        component: impl Into<String>,
        note: impl Into<String>,
    ) -> &mut Self {
        self.rounds.push(TranscriptRound {
            round,
            payload: payload.to_vec(),
            component: component.into(),
            note: note.into(),
        });
        self
    }

    /// Returns the domain-separated seed commitment.
    pub fn seed_commitment(&self) -> &str {
        &self.seed_commitment
    }

    /// Returns all recorded transcript rounds.
    pub fn rounds(&self) -> &[TranscriptRound] {
        &self.rounds
    }
}

/// A minimal luminous sum-check observation.
///
/// This structure annotates an external proof workflow. It does not implement
/// or claim proof-system soundness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleLuminousSumcheck {
    /// Semantic claim.
    pub claim: LuminousClaim,
    /// Human-readable interactive transcript.
    pub transcript: BitInteractiveTranscript,
}

impl SimpleLuminousSumcheck {
    /// Produces deterministic summary metadata.
    pub fn to_luminous_metadata(&self) -> LuminousMetadata {
        let rounds = projected_rounds(&self.transcript.rounds);
        LuminousMetadata {
            schema: LUMINOUS_METADATA_SCHEMA_V1,
            claim_id: self.claim.id.clone(),
            bit_width: self.claim.bit_width,
            viz_hints: self.claim.viz_hints.clone(),
            round_count: rounds.len(),
            transcript_digest: transcript_digest(&self.transcript.seed_commitment, &rounds),
        }
    }

    /// Validates the observation and creates a canonical visualization packet.
    pub fn to_viz_packet(&self) -> Result<VizPacket, SlbitError> {
        validate_claim(&self.claim)?;
        validate_rounds(&self.transcript.rounds)?;
        let rounds = projected_rounds(&self.transcript.rounds);
        let transcript_digest = transcript_digest(&self.transcript.seed_commitment, &rounds);
        let mut packet = VizPacket {
            schema: VIZ_PACKET_SCHEMA_V1,
            claim_id: self.claim.id.clone(),
            bit_width: self.claim.bit_width,
            viz_hints: self.claim.viz_hints.clone(),
            seed_commitment: self.transcript.seed_commitment.clone(),
            transcript_digest,
            packet_digest: String::new(),
            rounds,
        };
        packet.packet_digest = digest_with_domain(PACKET_DOMAIN, packet.core_json().as_bytes());
        Ok(packet)
    }
}

/// Compact metadata suitable for logs, indexes, and selectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuminousMetadata {
    /// Metadata schema.
    pub schema: &'static str,
    /// Semantic claim identifier.
    pub claim_id: String,
    /// Logical claim width.
    pub bit_width: u64,
    /// Presentation hints.
    pub viz_hints: VizHints,
    /// Number of annotated rounds.
    pub round_count: usize,
    /// Deterministic transcript digest.
    pub transcript_digest: String,
}

/// Public transcript round included in a visualization packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VizRound {
    /// Round number.
    pub round: u64,
    /// Producing component or semantic layer.
    pub component: String,
    /// Human-readable annotation.
    pub note: String,
    /// Domain-separated digest of the opaque round payload.
    pub payload_sha256: String,
}

/// Canonical semantic packet consumed by visualization layers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VizPacket {
    /// Packet schema.
    pub schema: &'static str,
    /// Semantic claim identifier.
    pub claim_id: String,
    /// Logical claim width.
    pub bit_width: u64,
    /// Presentation hints.
    pub viz_hints: VizHints,
    /// Domain-separated transcript seed commitment.
    pub seed_commitment: String,
    /// Digest of the ordered semantic transcript.
    pub transcript_digest: String,
    /// Digest of packet content excluding this field.
    pub packet_digest: String,
    /// Human-readable rounds.
    pub rounds: Vec<VizRound>,
}

impl VizPacket {
    /// Serializes the packet as compact deterministic JSON.
    pub fn to_json(&self) -> String {
        self.packet_json(true)
    }

    /// Verifies packet structure and deterministic packet digest.
    pub fn verify(&self) -> Result<(), SlbitError> {
        if self.schema != VIZ_PACKET_SCHEMA_V1 {
            return Err(SlbitError::UnsupportedSchema(self.schema.to_string()));
        }
        let claim = LuminousClaim {
            id: self.claim_id.clone(),
            bit_width: self.bit_width,
            viz_hints: self.viz_hints.clone(),
        };
        validate_claim(&claim)?;
        validate_viz_rounds(&self.rounds)?;
        validate_sha256(&self.seed_commitment)?;
        validate_sha256(&self.transcript_digest)?;
        validate_sha256(&self.packet_digest)?;
        let expected_transcript = transcript_digest(&self.seed_commitment, &self.rounds);
        if expected_transcript != self.transcript_digest {
            return Err(SlbitError::TranscriptDigestMismatch {
                expected: expected_transcript,
                found: self.transcript_digest.clone(),
            });
        }
        let expected = digest_with_domain(PACKET_DOMAIN, self.core_json().as_bytes());
        if expected != self.packet_digest {
            let legacy = digest_with_domain(PACKET_DOMAIN, self.legacy_core_json().as_bytes());
            if legacy != self.packet_digest {
                return Err(SlbitError::PacketDigestMismatch {
                    expected,
                    found: self.packet_digest.clone(),
                });
            }
        }
        Ok(())
    }

    fn core_json(&self) -> String {
        self.packet_json(false)
    }

    fn legacy_core_json(&self) -> String {
        self.packet_json_with_round_writer(false, push_legacy_round_json)
    }

    fn packet_json(&self, include_packet_digest: bool) -> String {
        self.packet_json_with_round_writer(include_packet_digest, push_round_json)
    }

    fn packet_json_with_round_writer(
        &self,
        include_packet_digest: bool,
        round_writer: fn(&mut String, &VizRound),
    ) -> String {
        let mut json = String::from("{");
        push_json_key(&mut json, "bit_width");
        json.push_str(&self.bit_width.to_string());
        json.push(',');
        push_json_key(&mut json, "claim_id");
        push_json_string(&mut json, &self.claim_id);
        if include_packet_digest {
            json.push(',');
            push_json_key(&mut json, "packet_digest");
            push_json_string(&mut json, &self.packet_digest);
        }
        json.push(',');
        push_json_key(&mut json, "rounds");
        json.push('[');
        for (index, round) in self.rounds.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            round_writer(&mut json, round);
        }
        json.push(']');
        json.push(',');
        push_json_key(&mut json, "schema");
        push_json_string(&mut json, self.schema);
        json.push(',');
        push_json_key(&mut json, "seed_commitment");
        push_json_string(&mut json, &self.seed_commitment);
        json.push(',');
        push_json_key(&mut json, "transcript_digest");
        push_json_string(&mut json, &self.transcript_digest);
        json.push(',');
        push_json_key(&mut json, "viz_hints");
        push_hints_json(&mut json, &self.viz_hints);
        json.push('}');
        json
    }
}

impl fmt::Display for VizPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_json())
    }
}

/// Errors returned by semantic packet validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlbitError {
    /// A text field is empty, oversized, or contains control characters.
    InvalidText {
        /// Field name.
        field: &'static str,
        /// Validation detail.
        message: String,
    },
    /// Claim bit width must be nonzero.
    InvalidBitWidth,
    /// Transcript contains too many rounds.
    TooManyRounds(usize),
    /// Transcript rounds are not strictly increasing.
    NonMonotonicRound {
        /// Previous round.
        previous: u64,
        /// Current round.
        current: u64,
    },
    /// A round payload exceeds the transport limit.
    PayloadTooLarge {
        /// Round number.
        round: u64,
        /// Payload size.
        bytes: usize,
    },
    /// Icon names must be lowercase ASCII identifiers.
    InvalidIcon(String),
    /// Packet schema is unsupported.
    UnsupportedSchema(String),
    /// A digest is malformed.
    InvalidDigest(String),
    /// Exported transcript content does not match its digest.
    TranscriptDigestMismatch {
        /// Recalculated digest.
        expected: String,
        /// Stored digest.
        found: String,
    },
    /// Packet content does not match its digest.
    PacketDigestMismatch {
        /// Recalculated digest.
        expected: String,
        /// Stored digest.
        found: String,
    },
    /// A collection contains too many entries.
    TooManyItems {
        /// Field name.
        field: &'static str,
        /// Entry count.
        count: usize,
    },
    /// An identifier appears more than once.
    DuplicateId {
        /// Field name.
        field: &'static str,
        /// Duplicated identifier.
        id: String,
    },
    /// A graph edge or semantic reference points at a missing item.
    InvalidReference {
        /// Field name.
        field: &'static str,
        /// Missing reference.
        reference: String,
    },
    /// A semantic graph contains a directed cycle.
    CycleDetected,
}

impl fmt::Display for SlbitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText { field, message } => {
                write!(formatter, "invalid {field}: {message}")
            }
            Self::InvalidBitWidth => formatter.write_str("bit width must be nonzero"),
            Self::TooManyRounds(count) => write!(formatter, "too many transcript rounds: {count}"),
            Self::NonMonotonicRound { previous, current } => write!(
                formatter,
                "transcript rounds must increase strictly: {previous} then {current}"
            ),
            Self::PayloadTooLarge { round, bytes } => {
                write!(
                    formatter,
                    "round {round} payload is too large: {bytes} bytes"
                )
            }
            Self::InvalidIcon(icon) => write!(formatter, "invalid icon identifier: {icon}"),
            Self::UnsupportedSchema(schema) => write!(formatter, "unsupported schema: {schema}"),
            Self::InvalidDigest(digest) => write!(formatter, "invalid SHA-256 digest: {digest}"),
            Self::TranscriptDigestMismatch { expected, found } => write!(
                formatter,
                "transcript digest mismatch: expected {expected}, found {found}"
            ),
            Self::PacketDigestMismatch { expected, found } => {
                write!(
                    formatter,
                    "packet digest mismatch: expected {expected}, found {found}"
                )
            }
            Self::TooManyItems { field, count } => {
                write!(formatter, "too many entries in {field}: {count}")
            }
            Self::DuplicateId { field, id } => {
                write!(formatter, "duplicate identifier in {field}: {id}")
            }
            Self::InvalidReference { field, reference } => {
                write!(formatter, "invalid reference in {field}: {reference}")
            }
            Self::CycleDetected => formatter.write_str("semantic graph contains a cycle"),
        }
    }
}

impl Error for SlbitError {}

fn validate_claim(claim: &LuminousClaim) -> Result<(), SlbitError> {
    validate_text("claim_id", &claim.id, MAX_CLAIM_ID_BYTES)?;
    if claim.bit_width == 0 {
        return Err(SlbitError::InvalidBitWidth);
    }
    if let Some(icon) = &claim.viz_hints.icon {
        validate_text("viz_hints.icon", icon, MAX_LABEL_BYTES)?;
        if !icon
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(SlbitError::InvalidIcon(icon.clone()));
        }
    }
    if let Some(layer) = &claim.viz_hints.layer_name {
        validate_text("viz_hints.layer_name", layer, MAX_LABEL_BYTES)?;
    }
    Ok(())
}

fn validate_rounds(rounds: &[TranscriptRound]) -> Result<(), SlbitError> {
    if rounds.len() > MAX_ROUNDS {
        return Err(SlbitError::TooManyRounds(rounds.len()));
    }
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
        validate_text("round.component", &round.component, MAX_LABEL_BYTES)?;
        validate_text("round.note", &round.note, MAX_NOTE_BYTES)?;
        if round.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(SlbitError::PayloadTooLarge {
                round: round.round,
                bytes: round.payload.len(),
            });
        }
    }
    Ok(())
}

fn validate_viz_rounds(rounds: &[VizRound]) -> Result<(), SlbitError> {
    if rounds.len() > MAX_ROUNDS {
        return Err(SlbitError::TooManyRounds(rounds.len()));
    }
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
        validate_text("round.component", &round.component, MAX_LABEL_BYTES)?;
        validate_text("round.note", &round.note, MAX_NOTE_BYTES)?;
        validate_sha256(&round.payload_sha256)?;
    }
    Ok(())
}

pub(crate) fn validate_text(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), SlbitError> {
    if value.trim().is_empty() {
        return Err(SlbitError::InvalidText {
            field,
            message: "must not be empty".to_string(),
        });
    }
    if value.len() > max {
        return Err(SlbitError::InvalidText {
            field,
            message: format!("must be at most {max} UTF-8 bytes"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(SlbitError::InvalidText {
            field,
            message: "must not contain control characters".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str) -> Result<(), SlbitError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SlbitError::InvalidDigest(value.to_string()));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SlbitError::InvalidDigest(value.to_string()));
    }
    Ok(())
}

fn projected_rounds(rounds: &[TranscriptRound]) -> Vec<VizRound> {
    rounds
        .iter()
        .map(|round| VizRound {
            round: round.round,
            component: round.component.clone(),
            note: round.note.clone(),
            payload_sha256: digest_with_domain(PAYLOAD_DOMAIN, &round.payload),
        })
        .collect()
}

pub(crate) fn transcript_digest(seed_commitment: &str, rounds: &[VizRound]) -> String {
    let mut bytes = Vec::new();
    absorb(&mut bytes, seed_commitment.as_bytes());
    absorb(&mut bytes, &(rounds.len() as u64).to_be_bytes());
    for round in rounds {
        absorb(&mut bytes, &round.round.to_be_bytes());
        absorb(&mut bytes, round.component.as_bytes());
        absorb(&mut bytes, round.note.as_bytes());
        absorb(&mut bytes, round.payload_sha256.as_bytes());
    }
    digest_with_domain(TRANSCRIPT_DOMAIN, &bytes)
}

pub(crate) fn absorb(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

pub(crate) fn push_json_key(output: &mut String, key: &str) {
    push_json_string(output, key);
    output.push(':');
}

pub(crate) fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

pub(crate) fn push_hints_json(output: &mut String, hints: &VizHints) {
    output.push('{');
    let mut wrote = false;
    if let Some(color) = hints.color {
        push_json_key(output, "color");
        output.push('[');
        output.push_str(&format!("{},{},{}", color[0], color[1], color[2]));
        output.push(']');
        wrote = true;
    }
    if let Some(icon) = &hints.icon {
        if wrote {
            output.push(',');
        }
        push_json_key(output, "icon");
        push_json_string(output, icon);
        wrote = true;
    }
    if let Some(layer) = &hints.layer_name {
        if wrote {
            output.push(',');
        }
        push_json_key(output, "layer_name");
        push_json_string(output, layer);
    }
    output.push('}');
}

fn push_round_json(output: &mut String, round: &VizRound) {
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

fn push_legacy_round_json(output: &mut String, round: &VizRound) {
    output.push('{');
    push_json_key(output, "component");
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

pub(crate) fn digest_with_domain(domain: &[u8], value: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(domain.len() + value.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(value);
    format!("sha256:{}", hex_encode(&sha256(&bytes)))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
        output.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("hex digit"));
    }
    output
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminous() -> SimpleLuminousSumcheck {
        let claim = LuminousClaim::new("drone-camera-frame-7842", 4096).with_viz_hints(VizHints {
            color: Some([0, 200, 255]),
            icon: Some("camera".to_string()),
            layer_name: Some("perception-conv3".to_string()),
        });
        let mut transcript = BitInteractiveTranscript::new(b"drone-seed-7842");
        transcript.record_round_with_note(
            0,
            &[0xde, 0xad, 0xbe, 0xef],
            "sensor-processing",
            "Raw sensor frame converted into features",
        );
        transcript.record_round_with_note(
            1,
            &[0x42],
            "attention-head-7",
            "Stop-sign feature strongly activated",
        );
        SimpleLuminousSumcheck { claim, transcript }
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn packets_are_deterministic_and_hide_raw_payloads() {
        let first = luminous().to_viz_packet().unwrap();
        let second = luminous().to_viz_packet().unwrap();
        assert_eq!(first, second);
        assert!(first.verify().is_ok());
        assert!(!first.to_json().contains("deadbeef"));
        assert!(first
            .to_json()
            .contains("Stop-sign feature strongly activated"));
        assert!(first.to_json().contains("\",\"rounds\":"));
        assert!(!first.to_json().contains("\"component\":\"component\":"));
    }

    #[test]
    fn legacy_v1_packet_digest_still_verifies() {
        let mut packet = luminous().to_viz_packet().unwrap();
        packet.packet_digest =
            digest_with_domain(PACKET_DOMAIN, packet.legacy_core_json().as_bytes());
        packet.verify().unwrap();
    }

    #[test]
    fn semantic_mutation_changes_digest() {
        let original = luminous().to_viz_packet().unwrap();
        let mut changed = luminous();
        changed.transcript.rounds[1].note = "Different annotation".to_string();
        let changed = changed.to_viz_packet().unwrap();
        assert_ne!(original.packet_digest, changed.packet_digest);
    }

    #[test]
    fn packet_digest_rejects_mutation() {
        let mut packet = luminous().to_viz_packet().unwrap();
        packet.rounds[0].note = "mutated".to_string();
        assert!(matches!(
            packet.verify(),
            Err(SlbitError::TranscriptDigestMismatch { .. })
        ));
    }

    #[test]
    fn invalid_round_order_is_rejected() {
        let mut value = luminous();
        value.transcript.rounds[1].round = 0;
        assert!(matches!(
            value.to_viz_packet(),
            Err(SlbitError::NonMonotonicRound { .. })
        ));
    }

    #[test]
    fn json_escaping_is_deterministic() {
        let mut value = luminous();
        value.transcript.rounds[0].note = "camera \"accepted\" \\\\ path".to_string();
        let json = value.to_viz_packet().unwrap().to_json();
        assert!(json.contains("camera \\\"accepted\\\" \\\\\\\\ path"));
    }
}
