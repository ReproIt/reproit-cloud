use super::*;

fn rec(msg: &str, sig: &str, entry: &str, actions: &[&str]) -> ErrorRec {
    let mut path = vec![Step {
        sig: entry.to_string(),
        action: "load".to_string(),
        label: None,
    }];
    for action in actions {
        path.push(Step {
            sig: "mid".to_string(),
            action: action.to_string(),
            label: None,
        });
    }
    ErrorRec {
        sig: sig.to_string(),
        message: msg.to_string(),
        path,
        context: Map::new(),
    }
}

#[test]
fn evidence_kind_from_content_type_then_extension() {
    // content-type wins when present
    assert_eq!(evidence_kind(Some("video/mp4"), Some("x.gif")), "mp4");
    assert_eq!(evidence_kind(Some("image/gif; q=1"), None), "gif");
    // falls back to filename extension
    assert_eq!(evidence_kind(None, Some("repro.MP4")), "mp4");
    assert_eq!(
        evidence_kind(Some("application/x"), Some("shot.png")),
        "png"
    );
    assert_eq!(evidence_kind(Some("image/jpeg"), None), "jpg");
    // unknown is kept as a generic blob, never rejected
    assert_eq!(evidence_kind(None, Some("weird.xyz")), "blob");
    assert_eq!(evidence_kind(None, None), "blob");
}

#[test]
fn safe_key_rejects_traversal_and_absolute() {
    use crate::tenancy::blob::is_safe_key;
    assert!(is_safe_key("app/42/abc.mp4"));
    assert!(!is_safe_key("/etc/passwd"));
    assert!(!is_safe_key("app/../../etc/passwd"));
    assert!(!is_safe_key("app/./x"));
    assert!(!is_safe_key(""));
    assert!(!is_safe_key("app//x"));
}

#[test]
fn event_context_fingerprint_feeds_fixture_spec() {
    let context = serde_json::from_value(json!({
        "fingerprint": [{
            "field": "name",
            "len": 18,
            "bytes": 90,
            "graphemes": 12,
            "charset": "unicode",
            "scripts": ["Latin", "Arabic"],
            "hasNewline": true
        }]
    }))
    .unwrap();
    let spec = fixture_spec(&context, &[]);
    let generate = &spec["inputs"][0]["generate"];
    assert_eq!(generate["minLen"], json!(18));
    assert_eq!(generate["minBytes"], json!(90));
    assert_eq!(generate["minGraphemes"], json!(12));
    assert_eq!(generate["scripts"], json!(["Latin", "Arabic"]));
    assert_eq!(generate["newline"], json!(true));
}

#[test]
fn bucket_package_exposes_bucket_first_replay_shape() {
    let mut newest = rec(
        "Cannot read property at line 42",
        "crashA",
        "checkout",
        &["type:key:id:card=long", "tap:key:id:pay"],
    );
    newest
        .context
        .insert("build".into(), json!({ "version": "1.2.3" }));
    newest.context.insert(
        "fingerprint".into(),
        json!([{ "field": "card", "len": 64, "charset": "numeric" }]),
    );
    let oldest = rec(
        "Cannot read property at line 1",
        "crashA",
        "checkout",
        &["tap:key:id:pay"],
    );
    let discriminators = vec![json!({
        "key": "locale",
        "value": "tr",
        "cohortShare": 1.0,
        "baselineShare": 0.2,
        "lift": 5.0,
    })];
    let evidence = vec![EvidenceRec {
        kind: "mp4".into(),
        key: "app/1/repro.mp4".into(),
        bytes: 10,
        ts: "2026-06-27T00:00:00Z".into(),
        url: "/v1/blob/app/1/repro.mp4".into(),
    }];
    let results = vec![ReplayResult {
        status: "reproduced".into(),
        runs: 1,
        failures: 1,
        local_repro_id: Some("local-1".into()),
        created_at: "2026-06-27T00:00:00Z".into(),
    }];

    let pkg = bucket_package(
        "app-test",
        "bkt_deadbeef0001",
        &newest,
        &oldest,
        &newest,
        2,
        &discriminators,
        evidence,
        results,
    );

    assert_eq!(pkg["appId"], "app-test");
    assert_eq!(pkg["bucketId"], "bkt_deadbeef0001");
    assert_eq!(pkg["howto"], "reproit <bucketId>: downloads this package, saves it locally, synthesizes the fixture, replays the actions, then reports the verdict to Cloud");
    assert_eq!(pkg["message"], "Cannot read property at line 42");
    assert_eq!(pkg["summary"], "Cannot read property at line N (crashA)");
    assert_eq!(pkg["actions"], pkg["replay"]);
    assert_eq!(
        pkg["actions"],
        json!(["type:key:id:card=long", "tap:key:id:pay"])
    );
    assert_eq!(pkg["displayPath"][1]["action"], "type:key:id:card=long");
    assert_eq!(pkg["fixture"], pkg["fixtureSpec"]);
    assert_eq!(pkg["fixture"]["locale"], "tr");
    assert_eq!(pkg["fixture"]["inputs"][0]["field"], "card");
    assert_eq!(pkg["discriminators"][0]["key"], "locale");
    assert_eq!(pkg["lineage"]["lastSeen"]["version"], "1.2.3");
    assert_eq!(pkg["evidence"][0]["kind"], "mp4");
    assert_eq!(pkg["visualEvidence"]["count"], 1);
    assert_eq!(pkg["visualEvidence"]["paths"], json!(["app/1/repro.mp4"]));
    assert_eq!(pkg["visualEvidence"]["clips"][0]["role"], "clip");
    assert_eq!(pkg["visualEvidence"]["clips"][0]["path"], "app/1/repro.mp4");
    assert_eq!(pkg["visualEvidence"]["screenshots"], json!([]));
    assert_eq!(pkg["results"], pkg["replayResults"]);
    assert_eq!(pkg["repro"]["status"], "reproduced");
}

fn frame(sequence: u64, event: reproit_protocol::Event) -> reproit_protocol::EventFrame {
    reproit_protocol::EventFrame {
        run_id: "run-1".into(),
        sequence,
        scope: reproit_protocol::EvidenceScope::Shared,
        event,
    }
}

#[test]
fn typed_finding_preserves_identity_and_recomputes_bug_id() {
    let identity = reproit_protocol::FindingIdentity {
        oracle: "crash".into(),
        invariant: "no-exception".into(),
        kind: "exception".into(),
        message: "boom at #".into(),
        frame: String::new(),
        trigger: String::new(),
        boundary: None,
    };
    let frames = vec![frame(
        1,
        reproit_protocol::Event::Finding {
            signature: "screen".into(),
            message: "boom at 42".into(),
            identity: identity.clone(),
            path: vec![],
            context: Default::default(),
        },
    )];
    let agg = aggregate_events(&frames);
    let record = &agg.error_recs[0];
    assert_eq!(record.context["findingIdentity"], json!(identity));
    assert_eq!(record.context["oracle"], json!("crash"));
    assert_eq!(
        buckets::bucket_id(record).trim_start_matches("bkt_"),
        buckets::bug_id(record).trim_start_matches("bug_")
    );
}

#[test]
fn typed_edges_sum_and_nonpersistent_frames_are_ignored() {
    let frames = vec![
        frame(
            1,
            reproit_protocol::Event::GraphEdge {
                from: "a".into(),
                action: "tap".into(),
                to: "b".into(),
            },
        ),
        frame(
            2,
            reproit_protocol::Event::GraphEdge {
                from: "a".into(),
                action: "tap".into(),
                to: "b".into(),
            },
        ),
        frame(
            3,
            reproit_protocol::Event::Action {
                actor: None,
                action: "tap".into(),
            },
        ),
    ];
    let agg = aggregate_events(&frames);
    assert_eq!(agg.edge_counts.get("a|tap|b"), Some(&2));
    assert!(agg.error_recs.is_empty());
}

#[test]
fn legacy_untyped_batch_is_rejected() {
    let legacy = json!({
        "appId": "app",
        "events": [{ "kind": "edge", "from": "a", "action": "tap", "to": "b" }]
    });
    assert!(serde_json::from_value::<reproit_protocol::EventBatch>(legacy).is_err());
}

#[test]
fn sample_identity_requires_the_explicit_marker() {
    let mut rec = ErrorRec {
        sig: "s".into(),
        message: "anything".into(),
        path: vec![],
        context: Map::new(),
    };
    assert_eq!(sample_kind(&rec), None);
    rec.context
        .insert("reproitSample".into(), json!(NIMBUS_SAMPLE));
    assert_eq!(sample_kind(&rec), Some(NIMBUS_SAMPLE));
}
