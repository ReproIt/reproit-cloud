use super::*;
use crate::ingest::Step;
use serde_json::Map;

fn rec(msg: &str, sig: &str, entry: &str, actions: &[&str]) -> crate::ingest::ErrorRec {
    let mut path = vec![Step {
        sig: entry.to_string(),
        action: "load".to_string(),
        label: None,
    }];
    for a in actions {
        path.push(Step {
            sig: "mid".to_string(),
            action: a.to_string(),
            label: None,
        });
    }
    crate::ingest::ErrorRec {
        sig: sig.to_string(),
        message: msg.to_string(),
        path,
        context: Map::new(),
    }
}

// ---- 1. triage state machine ----

#[test]
fn status_roundtrips_through_its_wire_string() {
    for s in [
        Status::Untriaged,
        Status::Investigating,
        Status::Fixed,
        Status::Wontfix,
    ] {
        assert_eq!(Status::parse(s.as_str()), Some(s));
    }
    assert_eq!(Status::parse("bogus"), None);
}

#[test]
fn apply_allows_simple_status_changes() {
    assert_eq!(
        apply(Status::Untriaged, Status::Investigating),
        Status::Investigating
    );
    assert_eq!(apply(Status::Investigating, Status::Fixed), Status::Fixed);
    // re-opening a fixed bucket is allowed (coherence, not a forward-only graph).
    assert_eq!(
        apply(Status::Fixed, Status::Investigating),
        Status::Investigating
    );
}

#[test]
fn verified_fix_advances_to_fixed_except_from_wontfix() {
    // From any non-wontfix state a verified fix advances to `fixed`.
    assert_eq!(on_verified_fix(Status::Untriaged), Some(Status::Fixed));
    assert_eq!(on_verified_fix(Status::Investigating), Some(Status::Fixed));
    // Idempotent: an already-fixed bucket re-confirms fixed.
    assert_eq!(on_verified_fix(Status::Fixed), Some(Status::Fixed));
    // THE EXCEPTION: a human's `wontfix` is never overridden by the auto signal.
    assert_eq!(on_verified_fix(Status::Wontfix), None);
}

// ---- 2. seat gate ----

#[test]
fn seat_decision_gates_only_the_dashboard_surface() {
    // Not signed in: 401 upstream.
    assert_eq!(seat_decision(false, false), SeatVerdict::NotSignedIn);
    assert_eq!(seat_decision(false, true), SeatVerdict::NotSignedIn);
    // Signed in WITHOUT a seat: 402 (entitlement gap), the CLI still works.
    assert_eq!(seat_decision(true, false), SeatVerdict::NoSeat);
    // Signed in WITH a seat: served.
    assert_eq!(seat_decision(true, true), SeatVerdict::Allow);
}

// ---- 2b. bearer-key authorization (the agent/CLI org-key path) ----

#[test]
fn bearer_decision_authorizes_own_org_and_rejects_cross_tenant() {
    // The shared admin/ops key: full access, no org scoping.
    assert_eq!(bearer_decision(true, None), BearerVerdict::Admin);
    // A per-org key whose org OWNS this app: served, scoped to that org.
    assert_eq!(
        bearer_decision(false, Some((42, true))),
        BearerVerdict::Org(42)
    );
    // CROSS-TENANT: a valid key from a DIFFERENT org (does NOT own this app) is
    // denied here, so the request falls through to cookie+seat (404), never
    // leaking another tenant's data.
    assert_eq!(
        bearer_decision(false, Some((99, false))),
        BearerVerdict::Deny
    );
    // An unknown / non-org key (no org resolved) is denied.
    assert_eq!(bearer_decision(false, None), BearerVerdict::Deny);
    // Admin wins regardless of any org-ownership fact.
    assert_eq!(
        bearer_decision(true, Some((7, false))),
        BearerVerdict::Admin
    );
}

#[test]
fn bearer_reads_authorization_header() {
    let mut h = HeaderMap::new();
    assert_eq!(bearer(&h), None);
    h.insert(AUTHORIZATION, "Bearer sk_live_abc".parse().unwrap());
    assert_eq!(bearer(&h).as_deref(), Some("sk_live_abc"));
    // A non-bearer scheme is not a bearer token.
    let mut h2 = HeaderMap::new();
    h2.insert(AUTHORIZATION, "Basic xyz".parse().unwrap());
    assert_eq!(bearer(&h2), None);
}

// ---- 3. "grab a bug" detail builder ----

#[test]
fn bucket_detail_bundles_everything_a_dev_needs_to_grab_a_bug() {
    let mut newest = rec(
        "Cannot read property of undefined at line 42",
        "crashX",
        "checkout",
        &["type:key:id:card=long", "tap:key:id:pay"],
    );
    newest
        .context
        .insert("build".into(), serde_json::json!({ "version": "1.4.5" }));
    let oldest = rec(
        "Cannot read property of undefined at line 9001",
        "crashX",
        "checkout",
        &["tap:key:id:pay"],
    );
    let repro = serde_json::json!({ "status": "reproduced", "attempts": 3, "rate": 0.66 });
    let ticket = Some(serde_json::json!({
        "provider": "github", "repo": "acme/web", "externalId": "12",
        "url": "https://github.com/acme/web/issues/12"
    }));
    let triage = Triage {
        status: "investigating".into(),
        assignee: None,
        updated_at: "2026-06-21T00:00:00Z".into(),
        fixed_in_build: None,
    };
    let discs = vec![serde_json::json!({
        "key": "locale",
        "value": "tr",
        "cohortShare": 1.0,
        "baselineShare": 0.3,
        "lift": 3.3
    })];
    let cohorts = vec![serde_json::json!({
        "key": "locale",
        "total": 3,
        "values": [{
            "value": "tr",
            "count": 3,
            "cohortShare": 1.0,
            "baselineShare": 0.3,
            "lift": 3.3
        }]
    })];
    let bid = "bkt_deadbeef0001";
    let res = resolution::Outcome {
        status: resolution::Resolution::Active,
        fixed_in_build: None,
        last_seen_on_fixed_build: None,
        post_fix_occurrences: 0,
    };
    let d = bucket_detail(
        "acme-web",
        bid,
        &newest,
        &oldest,
        None,
        3,
        discs.clone(),
        cohorts.clone(),
        repro.clone(),
        ticket.clone(),
        Some(&triage),
        &res,
    );

    // Identity + the reproduce command a dev runs to grab it.
    assert_eq!(d["bucketId"], bid);
    assert_eq!(d["appId"], "acme-web");
    assert_eq!(d["count"], 3);
    assert_eq!(d["reproduceCommand"], format!("reproit {bid}"));
    // The executable replay (PII-safe class tokens) is present.
    assert_eq!(
        d["replay"],
        serde_json::json!(["type:key:id:card=long", "tap:key:id:pay"])
    );
    // The repro trust signal + lineage + linked ticket pass through.
    assert_eq!(d["repro"], repro);
    assert_eq!(d["lineage"]["lastSeen"]["version"], "1.4.5");
    assert_eq!(d["discriminators"], serde_json::json!(discs));
    assert_eq!(d["cohorts"], serde_json::json!(cohorts));
    assert_eq!(d["ticket"]["externalId"], "12");
    // The management state a dev acts on (the dev's INTENT).
    assert_eq!(d["triage"]["status"], "investigating");
    // The SYSTEM-computed prod-truth, side by side with the intent.
    assert_eq!(d["resolution"]["status"], "active");
    assert_eq!(d["resolution"]["postFixOccurrences"], 0);
}

#[test]
fn bucket_detail_defaults_to_implicit_untriaged_with_no_triage_or_ticket() {
    let r = rec("boom", "c", "home", &["tap:key:id:save"]);
    let repro = serde_json::json!({ "status": "ready", "attempts": 0 });
    let res = resolution::Outcome {
        status: resolution::Resolution::Active,
        fixed_in_build: None,
        last_seen_on_fixed_build: None,
        post_fix_occurrences: 0,
    };
    let d = bucket_detail(
        "app",
        "bkt_x",
        &r,
        &r,
        None,
        1,
        Vec::new(),
        Vec::new(),
        repro,
        None,
        None,
        &res,
    );
    // A never-touched bucket reads as `untriaged`, no ticket.
    assert_eq!(d["triage"]["status"], "untriaged");
    assert_eq!(d["triage"]["updatedAt"], Value::Null);
    assert_eq!(d["triage"]["fixedInBuild"], Value::Null);
    assert_eq!(d["ticket"], Value::Null);
    // No fix claimed => prod-truth is active.
    assert_eq!(d["resolution"]["status"], "active");
}
