use super::*;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LineCase {
    name: String,
    line: String,
    outcome: String,
}

fn action_frame() -> EventFrame {
    EventFrame {
        run_id: "run-1".into(),
        sequence: 1,
        scope: EvidenceScope::Shared,
        event: Event::Action {
            actor: Some("alice".into()),
            action: "tap:key:send".into(),
        },
    }
}

#[test]
fn frame_round_trip_is_exact() {
    let frame = action_frame();
    let line = frame.encode_line().unwrap();
    assert_eq!(decode_frame_line(&line).unwrap(), frame);
}

#[test]
fn canonical_line_corpus_has_exact_outcomes() {
    let cases: Vec<LineCase> =
        serde_json::from_str(include_str!("../fixtures/event-lines-v1.json")).unwrap();
    for case in cases {
        let actual = match decode_frame_line(&case.line) {
            Ok(_) => "accepted",
            Err(defect) => defect.reason.as_str(),
        };
        assert_eq!(actual, case.outcome, "case: {}", case.name);
    }
}

#[test]
fn oversized_scoped_frame_retains_only_bounded_attribution() {
    let line = format!(
        "REPROIT/1 contract 0123456789abcdef 7 run-1 {}",
        "x".repeat(MAX_FRAME_BYTES)
    );
    let defect = decode_frame_line(&line).unwrap_err();
    assert_eq!(defect.reason, ReasonCode::FrameTooLarge);
    assert!(defect.scope.affects_contract("0123456789abcdef"));
    assert!(!defect.scope.affects_contract("fedcba9876543210"));
}

#[test]
fn evidence_graph_rejects_forward_parent_references() {
    let parent = ArtifactNode::new(ArtifactKind::RawCapture, vec![], Value::Null).unwrap();
    let child = ArtifactNode::new(
        ArtifactKind::NormalizedTrace,
        vec![parent.id.clone()],
        Value::Null,
    )
    .unwrap();
    let graph = EvidenceGraph {
        run_id: "run-1".into(),
        root: child.id.clone(),
        nodes: vec![child, parent],
    };
    assert!(graph.validate().is_err());
}

#[test]
fn proof_ledger_promotes_only_complete_exact_proof() {
    let ledger = ProofLedger::from_stages(
        vec!["fnd_0123456789ab".into()],
        vec![AuthoritySource::AuthoredContract],
        EvaluationStatus::Violation,
        vec![],
        ConfirmationStatus::Reproduced,
        true,
        MinimizationStatus::Preserved,
    )
    .unwrap();
    assert_eq!(ledger.promotion, PromotionStatus::Confirmed);
    assert!(ledger.blockers.is_empty());

    let node = ArtifactNode::new(
        ArtifactKind::ProofLedger,
        vec![],
        serde_json::to_value(&ledger).unwrap(),
    )
    .unwrap();
    let graph = EvidenceGraph {
        run_id: "run-1".into(),
        root: node.id.clone(),
        nodes: vec![node],
    };
    assert_eq!(graph.proof_ledger().unwrap(), Some(ledger));
}

#[test]
fn proof_ledger_canonicalizes_set_like_fields() {
    let ledger = ProofLedger::from_stages(
        vec!["second".into(), "first".into(), "first".into()],
        vec![
            AuthoritySource::RuntimeDiagnosis,
            AuthoritySource::AuthoredContract,
            AuthoritySource::RuntimeDiagnosis,
        ],
        EvaluationStatus::Abstain,
        vec![ReasonCode::NoObservations, ReasonCode::NoObservations],
        ConfirmationStatus::NotAttempted,
        false,
        MinimizationStatus::NotAttempted,
    )
    .unwrap();
    assert_eq!(ledger.finding_identities, vec!["first", "second"]);
    assert_eq!(
        ledger.authority,
        vec![
            AuthoritySource::AuthoredContract,
            AuthoritySource::RuntimeDiagnosis,
        ]
    );
    assert_eq!(ledger.evaluation_reasons, vec![ReasonCode::NoObservations]);
}

#[test]
fn proof_ledger_rejects_forged_confirmation() {
    let mut ledger = ProofLedger::from_stages(
        vec!["fnd_0123456789ab".into()],
        vec![],
        EvaluationStatus::Violation,
        vec![],
        ConfirmationStatus::Reproduced,
        true,
        MinimizationStatus::Preserved,
    )
    .unwrap();
    assert_eq!(ledger.promotion, PromotionStatus::Candidate);
    assert_eq!(ledger.blockers, vec![PromotionBlocker::MissingAuthority]);

    ledger.promotion = PromotionStatus::Confirmed;
    ledger.blockers.clear();
    let node = ArtifactNode::new(
        ArtifactKind::ProofLedger,
        vec![],
        serde_json::to_value(ledger).unwrap(),
    )
    .unwrap();
    let graph = EvidenceGraph {
        run_id: "run-1".into(),
        root: node.id.clone(),
        nodes: vec![node],
    };
    assert_eq!(
        graph.validate().unwrap_err().reason,
        ReasonCode::InvalidArtifact
    );
}
