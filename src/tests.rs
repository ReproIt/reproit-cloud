//! Process-composition unit tests: host allowlist, CSRF origin policy,
//! admin targeting, raw-job gating, and database-plane resolution.

use super::{
    admin_target_result, csrf_origin_allowed, host_is_allowed, normalize_host, origin_of,
    raw_jobs_enabled, resolve_db_config,
};
use axum::http::HeaderMap;
use std::collections::HashSet;

#[test]
fn host_allowlist_is_structural_and_case_insensitive() {
    let allowed = HashSet::from([
        "cloud.reproit.com".to_string(),
        "ingest.reproit.com".to_string(),
    ]);
    assert!(host_is_allowed(Some("cloud.reproit.com"), &allowed));
    assert!(host_is_allowed(Some("INGEST.REPROIT.COM:443"), &allowed));
    assert!(host_is_allowed(Some("cloud.reproit.com."), &allowed));
    assert!(!host_is_allowed(Some("untrusted.example.net"), &allowed));
    assert!(!host_is_allowed(
        Some("cloud.reproit.com.evil.test"),
        &allowed
    ));
    assert!(!host_is_allowed(None, &allowed));
    assert_eq!(
        normalize_host(" Example.COM:8080 ").as_deref(),
        Some("example.com")
    );
    assert!(host_is_allowed(Some("anything.local"), &HashSet::new()));
}

#[test]
fn origin_of_strips_path_and_normalizes() {
    assert_eq!(
        origin_of("https://cloud.reproit.com/app?x=1#h").as_deref(),
        Some("https://cloud.reproit.com")
    );
    assert_eq!(
        origin_of("HTTP://Cloud.Reproit.COM:8080/").as_deref(),
        Some("http://Cloud.Reproit.COM:8080")
    );
    assert_eq!(origin_of("not-a-url"), None);
    assert_eq!(origin_of("https://"), None);
}

#[test]
fn csrf_allowed_origin_passes() {
    let allowed = vec!["https://cloud.reproit.com".to_string()];
    // Bare origin and a full URL both normalize to the allowed origin.
    assert!(csrf_origin_allowed(
        Some("https://cloud.reproit.com"),
        &allowed
    ));
    assert!(csrf_origin_allowed(
        Some("https://cloud.reproit.com/account/seats"),
        &allowed
    ));
}

#[test]
fn csrf_foreign_origin_rejected() {
    let allowed = vec!["https://cloud.reproit.com".to_string()];
    assert!(!csrf_origin_allowed(Some("https://evil.example"), &allowed));
    // Same host, different scheme/port is still foreign.
    assert!(!csrf_origin_allowed(
        Some("http://cloud.reproit.com"),
        &allowed
    ));
    assert!(!csrf_origin_allowed(
        Some("https://cloud.reproit.com:8443"),
        &allowed
    ));
}

#[test]
fn csrf_missing_origin_passes() {
    let allowed = vec!["https://cloud.reproit.com".to_string()];
    // No Origin/Referer (same-origin navigation, native/CLI client) -> allow.
    assert!(csrf_origin_allowed(None, &allowed));
}

#[test]
fn raw_jobs_are_only_enabled_for_dev_or_self_host() {
    assert!(!raw_jobs_enabled(false, false));
    assert!(raw_jobs_enabled(true, false));
    assert!(raw_jobs_enabled(false, true));
}

#[test]
fn self_host_maps_database_url_to_both_planes() {
    let (control, tenant) = resolve_db_config(true, Some("postgres://x/db"), None, "dflt");
    assert_eq!(control, "postgres://x/db");
    assert_eq!(tenant.as_deref(), Some("postgres://x/db"));
}

#[test]
fn self_host_tenant_override_wins_for_telemetry() {
    let (control, tenant) = resolve_db_config(
        true,
        Some("postgres://x/db"),
        Some("postgres://x/tel"),
        "dflt",
    );
    assert_eq!(control, "postgres://x/db");
    assert_eq!(tenant.as_deref(), Some("postgres://x/tel"));
}

#[test]
fn self_host_without_database_url_uses_the_local_default() {
    // The self-host distribution must come up with zero env for local
    // evaluation; the built-in localhost default backs both planes.
    let (control, tenant) = resolve_db_config(true, None, None, "dflt");
    assert_eq!(control, "dflt");
    assert_eq!(tenant.as_deref(), Some("dflt"));
}

#[test]
fn non_self_host_keeps_the_planes_independent() {
    let (control, tenant) = resolve_db_config(
        false,
        Some("postgres://x/ctl"),
        Some("postgres://x/tel"),
        "d",
    );
    assert_eq!(control, "postgres://x/ctl");
    assert_eq!(tenant.as_deref(), Some("postgres://x/tel"));
    let (control, tenant) = resolve_db_config(false, None, None, "d");
    assert_eq!(control, "d");
    assert_eq!(tenant, None);
}

#[test]
fn dashboard_never_advertises_retired_cli_commands() {
    let surfaces = [
        include_str!("../static/app.js"),
        include_str!("../static/triage.js"),
        include_str!("../docs/ci/reproit-repro.yml"),
        include_str!("../README.md"),
    ];
    for surface in surfaces {
        assert!(!surface.contains("reproit cloud reproduce"));
        assert!(!surface.contains("reproit cloud pull"));
        assert!(!surface.contains("reproit cloud login"));
        assert!(!surface.contains("reproit check ${job.id}"));
        assert!(!surface.contains("reproit run explore"));
        assert!(!surface.contains("reproit record"));
        assert!(!surface.contains("record --upload"));
    }
    assert!(surfaces[0].contains("reproit ${bktArg}"));
    assert!(!surfaces[0].contains("--app ${app}"));
    assert!(surfaces[2].contains("reproit __cloud-internal __replay-dispatch"));
}

#[test]
fn delete_confirmation_shows_the_case_sensitive_name() {
    let dashboard = include_str!("../static/app.js");
    let styles = include_str!("../static/styles.css");

    assert!(dashboard.contains(r#"class="confirmation-value">${esc(project.name)}</span>"#));
    assert!(dashboard.contains("Capitalization and spacing must match."));
    assert!(dashboard.contains("The value does not match. Copy the name exactly as shown."));
    assert!(styles.contains(".confirmation-value{"));
    assert!(styles.contains("text-transform:none"));
}

#[test]
fn project_deletion_selects_a_surviving_project() {
    let dashboard = include_str!("../static/app.js");

    assert!(dashboard.contains("function projectAfterDeletion(projects, deletedAppId)"));
    assert!(dashboard.contains("const nextProject = projectAfterDeletion("));
    assert!(dashboard.contains("Switched to ${nextProject.name}."));
}

#[test]
fn replay_path_exposes_its_overflow_scrollbar() {
    let styles = include_str!("../static/styles.css");

    assert!(styles.contains(".path-card .bd::-webkit-scrollbar-thumb"));
    assert!(styles.contains("overflow-y:auto"));
    assert!(styles.contains("scrollbar-width:thin"));
}

#[test]
fn admin_target_requires_numeric_header() {
    let headers = HeaderMap::new();
    let err = admin_target_result(&headers).unwrap_err();
    assert!(err.message().contains("X-Reproit-Tenant"));

    let mut headers = HeaderMap::new();
    headers.insert("x-reproit-tenant", "abc".parse().unwrap());
    let err = admin_target_result(&headers).unwrap_err();
    assert!(err.message().contains("numeric"));

    let mut headers = HeaderMap::new();
    headers.insert("x-reproit-tenant", "123".parse().unwrap());
    assert_eq!(admin_target_result(&headers).unwrap(), 123);
}
