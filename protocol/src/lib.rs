//! Strict, bounded event and evidence types shared across process boundaries.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u16 = 1;
pub const FRAME_PREFIX: &str = "REPROIT/1 ";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 512;
pub const MAX_BATCH_FRAMES: usize = 5_000;
pub const MAX_BATCH_GRAPHS: usize = 256;
pub const MAX_ARTIFACT_NODES: usize = 4_096;
pub const MAX_TOKEN_BYTES: usize = 128;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_CONTEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventBatch {
    pub version: u16,
    pub batch_id: String,
    pub app_id: String,
    pub frames: Vec<EventFrame>,
    pub evidence: Vec<EvidenceGraph>,
}

impl EventBatch {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != VERSION {
            return Err(ProtocolError::new(ReasonCode::UnsupportedVersion));
        }
        validate_token(&self.batch_id)?;
        validate_token(&self.app_id)?;
        if self.frames.len() > MAX_BATCH_FRAMES {
            return Err(ProtocolError::new(ReasonCode::BatchTooLarge));
        }
        if self.evidence.len() > MAX_BATCH_GRAPHS {
            return Err(ProtocolError::new(ReasonCode::BatchTooLarge));
        }
        if self.frames.is_empty() && self.evidence.is_empty() {
            return Err(ProtocolError::new(ReasonCode::InvalidEvent));
        }
        let mut last_sequence = None;
        for frame in &self.frames {
            frame.validate()?;
            if last_sequence.is_some_and(|last| frame.sequence <= last) {
                return Err(ProtocolError::new(ReasonCode::InvalidSequence));
            }
            last_sequence = Some(frame.sequence);
        }
        for graph in &self.evidence {
            graph.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventFrame {
    pub run_id: String,
    pub sequence: u64,
    pub scope: EvidenceScope,
    pub event: Event,
}

impl EventFrame {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_token(&self.run_id)?;
        self.scope.validate()?;
        self.event.validate()?;
        let encoded = serde_json::to_vec(&self.event)
            .map_err(|_| ProtocolError::new(ReasonCode::InvalidEvent))?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::scoped(
                ReasonCode::FrameTooLarge,
                self.scope.clone(),
            ));
        }
        Ok(())
    }

    pub fn encode_line(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        let (domain, subject) = self.scope.header_parts();
        let event = serde_json::to_string(&self.event)
            .map_err(|_| ProtocolError::new(ReasonCode::InvalidEvent))?;
        let line = format!(
            "REPROIT/1 {domain} {subject} {} {} {event}",
            self.sequence, self.run_id
        );
        if line.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::scoped(
                ReasonCode::FrameTooLarge,
                self.scope.clone(),
            ));
        }
        Ok(line)
    }
}

pub fn decode_frame_line(line: &str) -> Result<EventFrame, StreamDefect> {
    let header = bounded_prefix(line, MAX_HEADER_BYTES);
    if line.len() > MAX_FRAME_BYTES {
        return Err(StreamDefect {
            reason: ReasonCode::FrameTooLarge,
            scope: header_scope(header).unwrap_or(EvidenceScope::Shared),
            sequence: header_sequence(header),
        });
    }
    if !line.starts_with(FRAME_PREFIX) {
        let reason = if line.starts_with("REPROIT/") {
            ReasonCode::UnsupportedVersion
        } else {
            ReasonCode::MalformedFrame
        };
        return Err(StreamDefect::shared(reason));
    }
    let mut parts = line.splitn(6, ' ');
    let magic = parts.next();
    let domain = parts.next();
    let subject = parts.next();
    let sequence_text = parts.next();
    let run_id = parts.next();
    let event_json = parts.next();
    if magic != Some("REPROIT/1") {
        return Err(StreamDefect::shared(ReasonCode::MalformedFrame));
    }
    let Some(scope) = parse_scope(domain.unwrap_or_default(), subject.unwrap_or_default()) else {
        return Err(StreamDefect::shared(ReasonCode::MalformedFrame));
    };
    let Some(sequence) = sequence_text.and_then(|value| value.parse::<u64>().ok()) else {
        return Err(StreamDefect {
            reason: ReasonCode::InvalidSequence,
            scope,
            sequence: None,
        });
    };
    let (Some(run_id), Some(event_json)) = (run_id, event_json) else {
        return Err(StreamDefect {
            reason: ReasonCode::MalformedFrame,
            scope,
            sequence: Some(sequence),
        });
    };
    if validate_token(run_id).is_err() {
        return Err(StreamDefect {
            reason: ReasonCode::InvalidEvent,
            scope,
            sequence: Some(sequence),
        });
    }
    let event = serde_json::from_str(event_json).map_err(|_| StreamDefect {
        reason: ReasonCode::InvalidEvent,
        scope: scope.clone(),
        sequence: Some(sequence),
    })?;
    let frame = EventFrame {
        run_id: run_id.to_string(),
        sequence,
        scope,
        event,
    };
    frame.validate().map_err(|error| StreamDefect {
        reason: error.reason,
        scope: error.scope.unwrap_or_else(|| frame.scope.clone()),
        sequence: Some(sequence),
    })?;
    Ok(frame)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "domain", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EvidenceScope {
    Shared,
    Backend,
    Contract { contract_hash: Option<String> },
}

impl EvidenceScope {
    pub fn affects_contract(&self, contract_hash: &str) -> bool {
        match self {
            Self::Shared => true,
            Self::Backend => false,
            Self::Contract {
                contract_hash: affected,
            } => affected
                .as_deref()
                .is_none_or(|affected| affected == contract_hash),
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if let Self::Contract {
            contract_hash: Some(contract_hash),
        } = self
        {
            if !valid_hash(contract_hash, 16) {
                return Err(ProtocolError::new(ReasonCode::InvalidScope));
            }
        }
        Ok(())
    }

    fn header_parts(&self) -> (&'static str, &str) {
        match self {
            Self::Shared => ("shared", "-"),
            Self::Backend => ("backend", "-"),
            Self::Contract {
                contract_hash: Some(contract_hash),
            } => ("contract", contract_hash),
            Self::Contract {
                contract_hash: None,
            } => ("contract", "-"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Event {
    Action {
        actor: Option<String>,
        action: String,
    },
    Observation {
        actor: Option<String>,
        state: Option<String>,
        route: Option<String>,
        visible_text: Vec<String>,
        counts: BTreeMap<String, u64>,
        oracle_signals: Vec<String>,
        network_statuses: Vec<u16>,
        response_shapes: Vec<String>,
    },
    Backend {
        evidence: Value,
    },
    GraphEdge {
        from: String,
        action: String,
        to: String,
    },
    Finding {
        signature: String,
        message: String,
        identity: FindingIdentity,
        path: Vec<PathStep>,
        context: BTreeMap<String, Value>,
    },
    StreamDefect {
        reason: ReasonCode,
    },
}

impl Event {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Action { actor, action } => {
                validate_optional_token(actor)?;
                validate_text(action, MAX_TEXT_BYTES)
            }
            Self::Observation {
                actor,
                state,
                route,
                visible_text,
                counts,
                oracle_signals,
                response_shapes,
                ..
            } => {
                validate_optional_token(actor)?;
                validate_optional_text(state, MAX_TEXT_BYTES)?;
                validate_optional_text(route, MAX_TEXT_BYTES)?;
                validate_strings(visible_text, 1_024, MAX_TEXT_BYTES)?;
                validate_strings(oracle_signals, 256, MAX_TOKEN_BYTES)?;
                validate_strings(response_shapes, 256, MAX_TEXT_BYTES)?;
                if counts.len() > 4_096 {
                    return Err(ProtocolError::new(ReasonCode::InvalidEvent));
                }
                for key in counts.keys() {
                    validate_text(key, MAX_TOKEN_BYTES)?;
                }
                Ok(())
            }
            Self::Backend { evidence } => validate_value(evidence, MAX_CONTEXT_BYTES),
            Self::GraphEdge { from, action, to } => {
                validate_text(from, MAX_TEXT_BYTES)?;
                validate_text(action, MAX_TEXT_BYTES)?;
                validate_text(to, MAX_TEXT_BYTES)
            }
            Self::Finding {
                signature,
                message,
                identity,
                path,
                context,
            } => {
                validate_text(signature, MAX_TEXT_BYTES)?;
                validate_text(message, MAX_TEXT_BYTES)?;
                identity.validate()?;
                if path.len() > 256 {
                    return Err(ProtocolError::new(ReasonCode::InvalidEvent));
                }
                for step in path {
                    step.validate()?;
                }
                validate_value(
                    &serde_json::to_value(context).unwrap_or(Value::Null),
                    MAX_CONTEXT_BYTES,
                )
            }
            Self::StreamDefect { .. } => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdentity {
    pub oracle: String,
    pub invariant: String,
    pub kind: String,
    pub message: String,
    pub frame: String,
    pub trigger: String,
    pub boundary: Option<String>,
}

impl FindingIdentity {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_lower_token(&self.oracle)?;
        for value in [
            &self.invariant,
            &self.kind,
            &self.message,
            &self.frame,
            &self.trigger,
        ] {
            validate_text(value, MAX_TEXT_BYTES)?;
        }
        validate_optional_text(&self.boundary, MAX_TEXT_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathStep {
    pub signature: String,
    pub action: String,
    pub label: Option<String>,
}

impl PathStep {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text(&self.signature, MAX_TEXT_BYTES)?;
        validate_text(&self.action, MAX_TEXT_BYTES)?;
        validate_optional_text(&self.label, MAX_TEXT_BYTES)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationStatus {
    Satisfied,
    Violation,
    Abstain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evaluation {
    pub contract_id: String,
    pub contract_hash: String,
    pub status: EvaluationStatus,
    pub reasons: Vec<ReasonCode>,
    pub findings: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthoritySource {
    AuthoredContract,
    RuntimeDiagnosis,
    ApprovedBaseline,
    PublishedStandard,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmationStatus {
    NotAttempted,
    Reproduced,
    NotReproduced,
    Flaky,
    Stale,
    CouldNotReplay,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MinimizationStatus {
    NotAttempted,
    Preserved,
    CouldNotConfirm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionStatus {
    Candidate,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionBlocker {
    MissingAuthority,
    NoViolation,
    EvaluationAbstained,
    ReplayNotReproduced,
    ReplayIdentityMismatch,
    MinimizationNotPreserved,
}

impl PromotionBlocker {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingAuthority => "missing-authority",
            Self::NoViolation => "no-violation",
            Self::EvaluationAbstained => "evaluation-abstained",
            Self::ReplayNotReproduced => "replay-not-reproduced",
            Self::ReplayIdentityMismatch => "replay-identity-mismatch",
            Self::MinimizationNotPreserved => "minimization-not-preserved",
        }
    }
}

/// Immutable projection of the proof stages required to promote a candidate.
/// Search and detector output cannot construct a confirmed ledger by itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofLedger {
    pub finding_identities: Vec<String>,
    pub authority: Vec<AuthoritySource>,
    pub evaluation: EvaluationStatus,
    pub evaluation_reasons: Vec<ReasonCode>,
    pub confirmation: ConfirmationStatus,
    pub replay_identity_matched: bool,
    pub minimization: MinimizationStatus,
    pub promotion: PromotionStatus,
    pub blockers: Vec<PromotionBlocker>,
}

impl ProofLedger {
    pub fn from_stages(
        mut finding_identities: Vec<String>,
        mut authority: Vec<AuthoritySource>,
        evaluation: EvaluationStatus,
        mut evaluation_reasons: Vec<ReasonCode>,
        confirmation: ConfirmationStatus,
        replay_identity_matched: bool,
        minimization: MinimizationStatus,
    ) -> Result<Self, ProtocolError> {
        finding_identities.sort();
        finding_identities.dedup();
        authority.sort();
        authority.dedup();
        evaluation_reasons.sort();
        evaluation_reasons.dedup();
        let (promotion, blockers) = Self::derive_promotion(
            &authority,
            evaluation,
            confirmation,
            replay_identity_matched,
            minimization,
        );
        let ledger = Self {
            finding_identities,
            authority,
            evaluation,
            evaluation_reasons,
            confirmation,
            replay_identity_matched,
            minimization,
            promotion,
            blockers,
        };
        ledger.validate()?;
        Ok(ledger)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.finding_identities.is_empty() || self.finding_identities.len() > 256 {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        for identity in &self.finding_identities {
            validate_text(identity, MAX_TEXT_BYTES)?;
        }
        if self.authority.len() > 8 || self.evaluation_reasons.len() > 256 {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        if self.evaluation == EvaluationStatus::Abstain && self.evaluation_reasons.is_empty() {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        if !is_strictly_sorted(&self.finding_identities)
            || !is_strictly_sorted(&self.authority)
            || !is_strictly_sorted(&self.evaluation_reasons)
        {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        let expected = Self::derive_promotion(
            &self.authority,
            self.evaluation,
            self.confirmation,
            self.replay_identity_matched,
            self.minimization,
        );
        if self.promotion != expected.0 || self.blockers != expected.1 {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        Ok(())
    }

    fn derive_promotion(
        authority: &[AuthoritySource],
        evaluation: EvaluationStatus,
        confirmation: ConfirmationStatus,
        replay_identity_matched: bool,
        minimization: MinimizationStatus,
    ) -> (PromotionStatus, Vec<PromotionBlocker>) {
        let mut blockers = BTreeSet::new();
        if authority.is_empty() {
            blockers.insert(PromotionBlocker::MissingAuthority);
        }
        match evaluation {
            EvaluationStatus::Violation => {}
            EvaluationStatus::Satisfied => {
                blockers.insert(PromotionBlocker::NoViolation);
            }
            EvaluationStatus::Abstain => {
                blockers.insert(PromotionBlocker::EvaluationAbstained);
            }
        }
        if confirmation != ConfirmationStatus::Reproduced {
            blockers.insert(PromotionBlocker::ReplayNotReproduced);
        }
        if !replay_identity_matched {
            blockers.insert(PromotionBlocker::ReplayIdentityMismatch);
        }
        if minimization != MinimizationStatus::Preserved {
            blockers.insert(PromotionBlocker::MinimizationNotPreserved);
        }
        let blockers = blockers.into_iter().collect::<Vec<_>>();
        let promotion = if blockers.is_empty() {
            PromotionStatus::Confirmed
        } else {
            PromotionStatus::Candidate
        };
        (promotion, blockers)
    }
}

fn is_strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonCode {
    FrameTooLarge,
    BatchTooLarge,
    MalformedFrame,
    UnsupportedVersion,
    InvalidScope,
    InvalidSequence,
    InvalidEvent,
    IncompleteStream,
    NoObservations,
    AuthorityUnavailable,
    InvalidArtifact,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrameTooLarge => "frame-too-large",
            Self::BatchTooLarge => "batch-too-large",
            Self::MalformedFrame => "malformed-frame",
            Self::UnsupportedVersion => "unsupported-version",
            Self::InvalidScope => "invalid-scope",
            Self::InvalidSequence => "invalid-sequence",
            Self::InvalidEvent => "invalid-event",
            Self::IncompleteStream => "incomplete-stream",
            Self::NoObservations => "no-observations",
            Self::AuthorityUnavailable => "authority-unavailable",
            Self::InvalidArtifact => "invalid-artifact",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamDefect {
    pub reason: ReasonCode,
    pub scope: EvidenceScope,
    pub sequence: Option<u64>,
}

impl StreamDefect {
    pub fn shared(reason: ReasonCode) -> Self {
        Self {
            reason,
            scope: EvidenceScope::Shared,
            sequence: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    RawCapture,
    NormalizedTrace,
    Evaluation,
    Replay,
    MinimizedTrace,
    ProofLedger,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RawCapture => "raw-capture",
            Self::NormalizedTrace => "normalized-trace",
            Self::Evaluation => "evaluation",
            Self::Replay => "replay",
            Self::MinimizedTrace => "minimized-trace",
            Self::ProofLedger => "proof-ledger",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactNode {
    pub id: String,
    pub kind: ArtifactKind,
    pub parents: Vec<String>,
    pub payload: Value,
}

impl ArtifactNode {
    pub fn new(
        kind: ArtifactKind,
        parents: Vec<String>,
        payload: Value,
    ) -> Result<Self, ProtocolError> {
        let id = artifact_id(kind, &parents, &payload)?;
        Ok(Self {
            id,
            kind,
            parents,
            payload,
        })
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.id != artifact_id(self.kind, &self.parents, &self.payload)? {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        if self.kind == ArtifactKind::ProofLedger {
            let ledger: ProofLedger = serde_json::from_value(self.payload.clone())
                .map_err(|_| ProtocolError::new(ReasonCode::InvalidArtifact))?;
            ledger.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceGraph {
    pub run_id: String,
    pub root: String,
    pub nodes: Vec<ArtifactNode>,
}

impl EvidenceGraph {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_token(&self.run_id)?;
        if self.nodes.is_empty() || self.nodes.len() > MAX_ARTIFACT_NODES {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        let mut prior = BTreeSet::new();
        for node in &self.nodes {
            node.validate()?;
            if !node.parents.iter().all(|parent| prior.contains(parent)) {
                return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
            }
            if !prior.insert(node.id.clone()) {
                return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
            }
        }
        if !prior.contains(&self.root) {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
        Ok(())
    }

    pub fn proof_ledger(&self) -> Result<Option<ProofLedger>, ProtocolError> {
        self.validate()?;
        let Some(root) = self.nodes.iter().find(|node| node.id == self.root) else {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        };
        if root.kind != ArtifactKind::ProofLedger {
            return Ok(None);
        }
        serde_json::from_value(root.payload.clone())
            .map(Some)
            .map_err(|_| ProtocolError::new(ReasonCode::InvalidArtifact))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    pub reason: ReasonCode,
    pub scope: Option<EvidenceScope>,
}

impl ProtocolError {
    fn new(reason: ReasonCode) -> Self {
        Self {
            reason,
            scope: None,
        }
    }

    fn scoped(reason: ReasonCode, scope: EvidenceScope) -> Self {
        Self {
            reason,
            scope: Some(scope),
        }
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "protocol rejected input: {:?}", self.reason)
    }
}

impl std::error::Error for ProtocolError {}

fn artifact_id(
    kind: ArtifactKind,
    parents: &[String],
    payload: &Value,
) -> Result<String, ProtocolError> {
    validate_value(payload, MAX_FRAME_BYTES)?;
    for parent in parents {
        if !parent.starts_with("sha256:") || !valid_hash(&parent[7..], 64) {
            return Err(ProtocolError::new(ReasonCode::InvalidArtifact));
        }
    }
    let material = serde_json::to_vec(&(kind, parents, payload))
        .map_err(|_| ProtocolError::new(ReasonCode::InvalidArtifact))?;
    let digest = Sha256::digest(material);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn parse_scope(domain: &str, subject: &str) -> Option<EvidenceScope> {
    match (domain, subject) {
        ("shared", "-") => Some(EvidenceScope::Shared),
        ("backend", "-") => Some(EvidenceScope::Backend),
        ("contract", "-") => Some(EvidenceScope::Contract {
            contract_hash: None,
        }),
        ("contract", hash) if valid_hash(hash, 16) => Some(EvidenceScope::Contract {
            contract_hash: Some(hash.to_string()),
        }),
        _ => None,
    }
}

fn header_scope(header: &str) -> Option<EvidenceScope> {
    let mut fields = header.split(' ');
    (fields.next()? == "REPROIT/1").then_some(())?;
    parse_scope(fields.next()?, fields.next()?)
}

fn header_sequence(header: &str) -> Option<u64> {
    header.split(' ').nth(3)?.parse().ok()
}

fn bounded_prefix(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn valid_hash(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_token(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ProtocolError::new(ReasonCode::InvalidEvent));
    }
    Ok(())
}

fn validate_lower_token(value: &str) -> Result<(), ProtocolError> {
    validate_token(value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    }) {
        return Err(ProtocolError::new(ReasonCode::InvalidEvent));
    }
    Ok(())
}

fn validate_optional_token(value: &Option<String>) -> Result<(), ProtocolError> {
    value.as_deref().map(validate_token).transpose().map(drop)
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), ProtocolError> {
    if value.len() > max_bytes {
        return Err(ProtocolError::new(ReasonCode::InvalidEvent));
    }
    Ok(())
}

fn validate_optional_text(value: &Option<String>, max_bytes: usize) -> Result<(), ProtocolError> {
    value
        .as_deref()
        .map(|text| validate_text(text, max_bytes))
        .transpose()
        .map(drop)
}

fn validate_strings(
    values: &[String],
    max_count: usize,
    max_bytes: usize,
) -> Result<(), ProtocolError> {
    if values.len() > max_count {
        return Err(ProtocolError::new(ReasonCode::InvalidEvent));
    }
    for value in values {
        validate_text(value, max_bytes)?;
    }
    Ok(())
}

fn validate_value(value: &Value, max_bytes: usize) -> Result<(), ProtocolError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| ProtocolError::new(ReasonCode::InvalidEvent))?;
    if bytes.len() > max_bytes {
        return Err(ProtocolError::new(ReasonCode::InvalidEvent));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
