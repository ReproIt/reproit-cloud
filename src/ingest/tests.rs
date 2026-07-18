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
fn error_context_accepts_only_the_canonical_context_field() {
    let mut batch = Map::new();
    batch.insert("locale".into(), json!("en-US"));
    let ev = json!({
        "ctx": { "ignored": true },
        "context": { "plan": "pro", "route": "/checkout" }
    });
    let merged = merge_context(&batch, &ev);
    assert_eq!(merged["locale"], json!("en-US"));
    assert_eq!(merged["plan"], json!("pro"));
    assert_eq!(merged["route"], json!("/checkout"));
    assert!(merged.get("ignored").is_none());
}

#[test]
fn event_context_fingerprint_feeds_fixture_spec() {
    let ev = json!({
        "context": {
            "fingerprint": [{
                "field": "name",
                "len": 18,
                "bytes": 90,
                "graphemes": 12,
                "charset": "unicode",
                "scripts": ["Latin", "Arabic"],
                "hasNewline": true
            }]
        }
    });
    let merged = merge_context(&Map::new(), &ev);
    let spec = fixture_spec(&merged, &[]);
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

#[test]
fn oracle_gate_admits_tagged_error_and_forms_bucket() {
    // A crash is an oracle bug (SDKs tag uncaught crashes oracle:"crash"), so
    // it passes the gate, becomes an occurrence, and opens a bucket.
    let events = vec![json!({
        "kind": "error",
        "sig": "crashA",
        "message": "boom",
        "oracle": "crash",
    })];
    let agg = aggregate_events(&events, &Map::new());
    assert_eq!(agg.error_recs.len(), 1);
    assert_eq!(agg.dropped_untagged, 0);
    assert_eq!(agg.error_recs[0].context["oracle"], json!("crash"));
    // A bucket id is derivable for the accepted occurrence.
    assert!(!buckets::bucket_id(&agg.error_recs[0]).is_empty());
}

#[test]
fn ingest_preserves_bounded_structural_identity_and_recomputes_bug_id() {
    let identity = json!({
        "oracle": "crash",
        "invariant": "no-exception",
        "kind": "exception",
        "message": "boom at #",
        "frame": "",
        "trigger": ""
    });
    let events = vec![json!({
        "kind": "error",
        "sig": "screen",
        "message": "boom at 42",
        "oracle": "crash",
        "findingIdentity": identity,
        "bugId": "bug_attacker_controlled"
    })];
    let agg = aggregate_events(&events, &Map::new());
    let rec = &agg.error_recs[0];
    assert_eq!(rec.context["findingIdentity"], identity);
    assert_ne!(buckets::bug_id(rec), "bug_attacker_controlled");
    assert_eq!(
        buckets::bucket_id(rec).trim_start_matches("bkt_"),
        buckets::bug_id(rec).trim_start_matches("bug_")
    );
}

#[test]
fn oracle_gate_drops_untagged_error_and_forms_no_bucket() {
    // A general error report with no oracle tag is not a product finding: it
    // is dropped before any ErrorRec forms and counted for the response.
    let events = vec![json!({
        "kind": "error",
        "sig": "crashA",
        "message": "boom",
    })];
    let agg = aggregate_events(&events, &Map::new());
    assert!(agg.error_recs.is_empty());
    assert_eq!(agg.dropped_untagged, 1);
}

#[test]
fn oracle_gate_rejects_malformed_ids() {
    // Uppercase, spaces, punctuation, empty, and over-length are all malformed.
    assert!(!oracle_well_formed("Crash"));
    assert!(!oracle_well_formed("blank screen"));
    assert!(!oracle_well_formed("sql;drop"));
    assert!(!oracle_well_formed("crash!"));
    assert!(!oracle_well_formed(""));
    assert!(!oracle_well_formed(&"x".repeat(MAX_ORACLE_ID_BYTES + 1)));
    // Exactly at the cap is still a token.
    assert!(oracle_well_formed(&"x".repeat(MAX_ORACLE_ID_BYTES)));
    // Every canonical registry id passes the gate (choice-anomaly et al).
    for (id, _) in impact::KNOWN_ORACLES {
        assert!(oracle_well_formed(id), "registry id must pass gate: {id}");
    }
    // Through the loop, each malformed error is dropped, none bucketed.
    let events = vec![
        json!({ "kind": "error", "sig": "s", "oracle": "UPPER" }),
        json!({ "kind": "error", "sig": "s", "oracle": "has space" }),
        json!({ "kind": "error", "sig": "s", "oracle": "x".repeat(MAX_ORACLE_ID_BYTES + 1) }),
    ];
    let agg = aggregate_events(&events, &Map::new());
    assert!(agg.error_recs.is_empty());
    assert_eq!(agg.dropped_untagged, 3);
}

#[test]
fn oracle_gate_admits_wellformed_unknown_id() {
    // An id this cloud build does not recognize (from a newer CLI/SDK) still
    // passes: the gate is presence + well-formedness, not registry membership.
    let unknown = "time-travel-9000";
    assert!(!impact::KNOWN_ORACLES.iter().any(|(k, _)| *k == unknown));
    assert!(oracle_well_formed(unknown));
    let events = vec![json!({
        "kind": "error", "sig": "s", "message": "m", "oracle": unknown,
    })];
    let agg = aggregate_events(&events, &Map::new());
    assert_eq!(agg.error_recs.len(), 1);
    assert_eq!(agg.dropped_untagged, 0);
    assert_eq!(agg.error_recs[0].context["oracle"], json!(unknown));
}

#[test]
fn oracle_gate_leaves_edges_and_other_kinds_untouched() {
    // The gate touches only the error kind: edges still sum by key and an
    // unrelated kind is ignored, exactly as before.
    let events = vec![
        json!({ "kind": "edge", "from": "a", "action": "tap", "to": "b" }),
        json!({ "kind": "edge", "from": "a", "action": "tap", "to": "b" }),
        json!({ "kind": "error", "sig": "s" }),
        json!({ "kind": "screenshot" }),
    ];
    let agg = aggregate_events(&events, &Map::new());
    assert_eq!(agg.edge_counts.get("a|tap|b"), Some(&2));
    assert!(agg.error_recs.is_empty());
    assert_eq!(agg.dropped_untagged, 1);
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
