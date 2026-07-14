//! Stable, content-addressed error buckets.
//!
//! A production error's "identity" must survive new events arriving. List
//! positions shift every ingest, so any external reference (a PR-comment deep
//! link, an agent's "reproduce bucket X", a "no prod hits since" tracker) would
//! rot. A `bucket_id` is instead a pure hash of the error's
//! root-cause-identifying features, so the SAME error always lands in the SAME
//! bucket forever. The id is materialized into `errors.bucket_id` at ingest so
//! per-bucket reads are indexed; this module remains the single source of truth
//! for computing that value.
//!
//! Everything here is a deterministic, side-effect-free transform over the
//! errors a handler already fetched; the DB/evidence/results orchestration lives
//! in the handlers.

use super::{ErrorRec, ReplayResult};
use serde_json::{json, Map, Value};

/// Stable bucket id for an error: a hash of its root-cause features, NOT its
/// position. We hash the normalized message (volatile specifics removed), the
/// crash-state signature, and the entry-state signature, so two occurrences of
/// the same bug, reached by the same entry, collapse to one bucket.
pub fn bucket_id(rec: &ErrorRec) -> String {
    use sha2::{Digest, Sha256};
    let start_sig = rec.path.first().map(|s| s.sig.as_str()).unwrap_or("");
    let crash_sig = rec.sig.as_str();
    let msg = normalize_message(&rec.message);
    let mut h = Sha256::new();
    h.update(msg.as_bytes());
    h.update([0x1f]);
    h.update(crash_sig.as_bytes());
    h.update([0x1f]);
    h.update(start_sig.as_bytes());
    let hex = hex::encode(h.finalize());
    format!("bkt_{}", &hex[..12])
}

/// The normalized (digit/whitespace-collapsed) message for a bucket. PII-safe:
/// it's the same conservative normalization the bucket id hashes over, so it
/// carries no raw values. Public so the ticket integration can embed it in an
/// issue body without re-implementing the normalization.
pub fn normalized_message(rec: &ErrorRec) -> String {
    normalize_message(&rec.message)
}

/// A short one-line crash descriptor for a ticket title: the crash signature
/// plus the normalized message, truncated. Derived/value-free by construction
/// (both inputs are already PII-safe).
pub fn crash_summary(rec: &ErrorRec) -> String {
    let msg = normalized_message(rec);
    let head: String = msg.chars().take(80).collect();
    if head.is_empty() {
        rec.sig.clone()
    } else {
        format!("{} ({})", head, rec.sig)
    }
}

/// Normalize a message so two occurrences of the same root cause hash equal:
/// collapse numeric runs, volatile build hashes / ids, and whitespace, then trim.
/// This is deliberately conservative; over-normalizing would merge distinct bugs.
fn normalize_message(m: &str) -> String {
    let mut out = String::with_capacity(m.len());
    let mut last_was_space = false;
    let mut token = String::new();
    let flush_token = |out: &mut String, token: &mut String| {
        if token.is_empty() {
            return;
        }
        out.push_str(&normalize_token(token));
        token.clear();
    };

    for ch in m.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch);
            last_was_space = false;
        } else {
            flush_token(&mut out, &mut token);
            if ch.is_whitespace() {
                if !last_was_space {
                    out.push(' ');
                }
                last_was_space = true;
            } else {
                out.push(ch);
                last_was_space = false;
            }
        }
    }
    flush_token(&mut out, &mut token);
    out.trim().to_string()
}

fn normalize_token(token: &str) -> String {
    if token.chars().all(|c| c.is_ascii_digit()) {
        return "N".to_string();
    }
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("0x")
        && lower.len() >= 6
        && lower[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return "0xID".to_string();
    }
    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
    let all_hex = token.chars().all(|c| c.is_ascii_hexdigit());
    if token.len() >= 7 && all_hex && has_alpha {
        return "ID".to_string();
    }
    if token.len() >= 8 && has_digit && has_alpha {
        return "ID".to_string();
    }
    token.to_string()
}

/// Group occurrences (id, created_at, rec) by bucket id, returning each bucket's
/// indices into `occ` in the original (oldest-first) order, sorted by occurrence
/// count descending. Indices keep the caller free to pull id/timestamp/rec.
#[cfg(test)] // production reads use the MATERIALIZED errors.bucket_id column
             // (written at ingest with `bucket_id` above) or `ingest::group_stored`; this
             // in-memory reference grouping survives as the semantic spec the tests pin.
pub fn group(occ: &[(i64, String, ErrorRec)]) -> Vec<(String, Vec<usize>)> {
    let mut by_bucket: std::collections::BTreeMap<String, Vec<usize>> = Default::default();
    let mut order: Vec<String> = Vec::new();
    for (i, (_, _, rec)) in occ.iter().enumerate() {
        let b = bucket_id(rec);
        let entry = by_bucket.entry(b.clone()).or_default();
        if entry.is_empty() {
            order.push(b);
        }
        entry.push(i);
    }
    let mut out: Vec<(String, Vec<usize>)> = order
        .into_iter()
        .map(|b| {
            let idx = by_bucket.remove(&b).unwrap_or_default();
            (b, idx)
        })
        .collect();
    out.sort_by_key(|b| std::cmp::Reverse(b.1.len()));
    out
}

/// The executable replay for an error: keep the actionable steps (taps, keys,
/// and PII-safe typed-input steps), dropping passive load/nav/auto transitions.
/// This is exactly the runner's replay format.
///
/// `type:<sel>=<class>` steps are kept so a DATA-DEPENDENT failure (one that
/// only fires on a particular kind of input, e.g. an RTL or overlong value)
/// reproduces: the runner reconstructs a synthetic value from the class token
/// and types it. We keep them only when the value is a bounded class TOKEN, never
/// raw user text, so a replay package can never carry a literal typed value.
pub fn replay_actions(rec: &ErrorRec) -> Vec<String> {
    rec.path
        .iter()
        .map(|s| s.action.clone())
        .filter(|a| is_replay_action(a))
        .collect()
}

pub fn display_path(rec: &ErrorRec) -> Vec<Value> {
    rec.path
        .iter()
        .map(|s| {
            serde_json::json!({
                "sig": s.sig,
                "action": s.action,
                "label": s.label,
                "display": s.label.as_deref().unwrap_or(&s.action),
            })
        })
        .collect()
}

fn is_replay_action(a: &str) -> bool {
    a == "back" || a.starts_with("key:") || is_structural_tap_action(a) || is_safe_type_action(a)
}

fn is_structural_tap_action(a: &str) -> bool {
    let Some(sel) = a.strip_prefix("tap:") else {
        return false;
    };
    is_structural_selector(sel)
}

fn is_structural_selector(sel: &str) -> bool {
    sel.starts_with("key:") || is_role_selector(sel)
}

fn is_role_selector(sel: &str) -> bool {
    let Some((role, idx)) = sel.strip_prefix("role:").and_then(|s| s.split_once('#')) else {
        return false;
    };
    !role.is_empty()
        && role.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        && !idx.is_empty()
        && idx.chars().all(|c| c.is_ascii_digit())
}

/// Whether a `type:<sel>=<class>` step is replayable AND safe to embed in a
/// replay package. The SDK encodes typed input as a property class (the runner's
/// adversarial-value id, e.g. `rtl` / `emoji` / `long`), never the user's actual
/// text; this validates that DEFENSIVELY -- a bounded lowercase identifier token
/// after `=`, so any step carrying raw user input (capitals, spaces, an `@`, or
/// just length) is dropped rather than risk leaking PII into the package.
fn is_safe_type_action(a: &str) -> bool {
    let Some(rest) = a.strip_prefix("type:") else {
        return false;
    };
    // The selector (key:<id> / role:<role>#<idx>) carries no `=`, so the class
    // token is everything after the last `=`.
    let Some((_sel, class)) = rest.rsplit_once('=') else {
        return false;
    };
    if !_sel.starts_with("key:") && !is_role_selector(_sel) {
        return false;
    }
    !class.is_empty()
        && class.len() <= 32
        && class
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Build lineage `{firstSeen, lastSeen}` from the `context.build` of the oldest
/// and newest occurrence. Each side carries whatever of `{version, commit}` the
/// SDK reported (absent fields are simply omitted), so "regressed in 1.4.2 / no
/// hits since 1.4.5" and fix verification become possible.
pub fn lineage(oldest: &ErrorRec, newest: &ErrorRec) -> Value {
    json!({ "firstSeen": build_of(oldest), "lastSeen": build_of(newest) })
}

/// Extract the PII-safe build descriptor `{version?, commit?}` from an error's
/// context, if the SDK attached one under `context.build`.
fn build_of(rec: &ErrorRec) -> Value {
    let mut out = Map::new();
    if let Some(build) = rec.context.get("build").and_then(|v| v.as_object()) {
        for k in ["version", "commit"] {
            if let Some(v) = build.get(k).and_then(|v| v.as_str()) {
                out.insert(k.to_string(), json!(v));
            }
        }
    }
    Value::Object(out)
}

/// The `context.build.version` string for an occurrence, or `None` if the SDK
/// didn't attach one. This is the single build coordinate the timeline segments
/// by and the resolution engine anchors on, kept value-free (a build label, no
/// user data), so both the graph and the auto-resolve decision agree on it.
pub fn build_version(rec: &ErrorRec) -> Option<String> {
    rec.context
        .get("build")
        .and_then(|v| v.as_object())
        .and_then(|b| b.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// One cell of the per-bucket occurrence time-series: a count of occurrences in
/// a `[window, window+window_secs)` time bucket attributed to a single build.
/// `window` is the RFC3339 start of the time bucket (UTC, floored to the window
/// size); `build` is the `context.build.version` or `"unknown"` when the SDK
/// reported no build. This is exactly what the dashboard graphs (a stacked
/// per-build series), so the shape is flat and serialization-ready.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TimelineCell {
    pub window: String,
    pub build: String,
    pub count: u64,
}

/// The shaped occurrence time-series for a bucket: the per-(window, build) cells
/// plus a per-window TOTAL series (build-agnostic) the dashboard overlays as the
/// headline line. Both are sorted oldest window first (and cells by build within
/// a window) so the output is deterministic and directly renderable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Timeline {
    pub cells: Vec<TimelineCell>,
    pub total: Vec<TimelineCount>,
}

/// One cell of the build-agnostic total series: occurrences in a time window
/// across all builds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TimelineCount {
    pub window: String,
    pub count: u64,
}

/// Default time-window for the occurrence series: one hour. A founder-tunable
/// knob (the dashboard may offer day/hour/minute), shipped as a constant so the
/// default is explicit rather than a magic number at the call site.
pub const DEFAULT_TIMELINE_WINDOW_SECS: i64 = 3600;

/// PURE time-series shaping: group a bucket's occurrences `(created_at_rfc3339,
/// build_version)` into `(time-window, build)` cells with counts, plus a
/// build-agnostic per-window total. Side-effect-free over already-fetched data
/// (the DB read lives in the handler), exactly like the other bucket transforms.
///
/// Time bucketing floors each occurrence's UTC timestamp to a multiple of
/// `window_secs` from the Unix epoch, so windows line up across buckets and
/// across builds. An occurrence whose timestamp doesn't parse, or whose build is
/// absent, is still counted (build `"unknown"`) rather than dropped: a quiet
/// build with no version tag must not silently vanish from the "is it resolved?"
/// picture. Pass `DEFAULT_TIMELINE_WINDOW_SECS` for the default hourly grid.
pub fn timeline(occ: &[(String, Option<String>)], window_secs: i64) -> Timeline {
    use std::collections::BTreeMap;
    let window_secs = window_secs.max(1);
    // (window_start_epoch, build) -> count, and window_start_epoch -> total.
    let mut cells: BTreeMap<(i64, String), u64> = BTreeMap::new();
    let mut totals: BTreeMap<i64, u64> = BTreeMap::new();
    for (ts, build) in occ {
        let epoch = parse_epoch(ts).unwrap_or(0);
        let win = epoch.div_euclid(window_secs) * window_secs;
        let build = build.clone().unwrap_or_else(|| "unknown".to_string());
        *cells.entry((win, build)).or_default() += 1;
        *totals.entry(win).or_default() += 1;
    }
    Timeline {
        cells: cells
            .into_iter()
            .map(|((win, build), count)| TimelineCell {
                window: epoch_to_rfc3339(win),
                build,
                count,
            })
            .collect(),
        total: totals
            .into_iter()
            .map(|(win, count)| TimelineCount {
                window: epoch_to_rfc3339(win),
                count,
            })
            .collect(),
    }
}

/// Parse an RFC3339 timestamp to a Unix epoch second, or None if it doesn't
/// parse. Tolerant of the offset forms the DB round-trips (`Z` / `+00:00`).
fn parse_epoch(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.timestamp())
}

/// Render a Unix epoch second back to an RFC3339 UTC instant (the window label).
fn epoch_to_rfc3339(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap())
        .to_rfc3339()
}

/// Summarize a bucket's reproduction attempts into the trust signal:
/// `{status, attempts, reproduced, rate, localReproId?}`. The headline status is
/// the latest verdict (results arrive newest-first); `reproduced/attempts` is the
/// rate that tells a user "this is real" vs "fixed / data-dependent".
pub fn repro_status(results: &[ReplayResult]) -> Value {
    let attempts = results.len();
    if attempts == 0 {
        return json!({ "status": "ready", "attempts": 0, "reproduced": 0 });
    }
    let reproduced = results.iter().filter(|r| r.status == "reproduced").count();
    let latest = &results[0];
    json!({
        "status": latest.status,
        "attempts": attempts,
        "reproduced": reproduced,
        "rate": (reproduced as f64 / attempts as f64 * 100.0).round() / 100.0,
        "localReproId": latest.local_repro_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::Step;

    fn rec(msg: &str, sig: &str, entry: &str, actions: &[&str]) -> ErrorRec {
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
        ErrorRec {
            sig: sig.to_string(),
            message: msg.to_string(),
            path,
            context: Map::new(),
        }
    }

    #[test]
    fn bucket_id_is_stable_and_volatile_specifics_collapse() {
        // Same root cause, different line numbers / counts -> same bucket.
        let a = rec("Cannot read property at line 42", "crashA", "home", &[]);
        let b = rec("Cannot read property at line 9001", "crashA", "home", &[]);
        assert_eq!(bucket_id(&a), bucket_id(&b));
        assert!(bucket_id(&a).starts_with("bkt_"));
        // Different crash signature -> different bucket.
        let c = rec("Cannot read property at line 42", "crashB", "home", &[]);
        assert_ne!(bucket_id(&a), bucket_id(&c));
        // Different entry state -> different bucket.
        let d = rec("Cannot read property at line 42", "crashA", "settings", &[]);
        assert_ne!(bucket_id(&a), bucket_id(&d));
    }

    #[test]
    fn normalize_collapses_digits_and_whitespace() {
        assert_eq!(normalize_message("line 42  col\t7"), "line N col N");
        assert_eq!(normalize_message("0x7ffe1234 bad"), "0xID bad");
    }

    #[test]
    fn normalize_collapses_deploy_hashes_without_erasing_routes() {
        assert_eq!(
            normalize_message("ChunkLoadError: Loading chunk main.a1b2c3d4.js failed"),
            "ChunkLoadError: Loading chunk main.ID.js failed"
        );
        assert_eq!(
            normalize_message("ChunkLoadError: Loading chunk main.deadbeef.js failed"),
            "ChunkLoadError: Loading chunk main.ID.js failed"
        );
        assert_eq!(
            normalize_message("Cannot read property on checkout route"),
            "Cannot read property on checkout route"
        );
        let a = rec(
            "ChunkLoadError: Loading chunk main.a1b2c3d4.js failed",
            "crashA",
            "home",
            &[],
        );
        let b = rec(
            "ChunkLoadError: Loading chunk main.deadbeef.js failed",
            "crashA",
            "home",
            &[],
        );
        assert_eq!(bucket_id(&a), bucket_id(&b));
    }

    #[test]
    fn replay_actions_keep_only_executable_steps() {
        let r = rec("e", "s", "home", &["tap:key:testid:go", "key:Enter"]);
        // path also has the passive "load" entry step, which must be dropped.
        assert_eq!(replay_actions(&r), vec!["tap:key:testid:go", "key:Enter"]);
    }

    #[test]
    fn replay_actions_drop_human_label_taps_but_display_path_keeps_label() {
        let mut r = rec("e", "s", "home", &["tap:Open Settings", "tap:key:id:save"]);
        r.path[1].label = Some("Open Settings".into());
        r.path[2].label = Some("Save".into());

        assert_eq!(replay_actions(&r), vec!["tap:key:id:save"]);
        assert_eq!(display_path(&r)[1]["display"], "Open Settings");
        assert_eq!(display_path(&r)[2]["display"], "Save");
    }

    #[test]
    fn replay_actions_keep_pii_safe_typed_steps_for_data_dependent_repro() {
        // A data-dependent failure: the crash needs an RTL value typed into a
        // field. The typed step carries a property CLASS token (`rtl`), not the
        // user's text, so it must survive into the replay package -- otherwise the
        // value-carrying step is lost and the bug cannot reproduce.
        let r = rec(
            "boom",
            "crashRtl",
            "profile",
            &["type:key:id:name=rtl", "tap:key:id:save"],
        );
        assert_eq!(
            replay_actions(&r),
            vec!["type:key:id:name=rtl", "tap:key:id:save"]
        );

        // Defensive PII guard: a typed step carrying RAW user text (capitals,
        // spaces, an `@`, or just length) is NEVER embedded in a replay package.
        for raw in [
            "type:key:id:name=John Doe",
            "type:key:id:email=jane@example.com",
            "type:key:id:bio=A really long actual sentence the user typed",
        ] {
            let r = rec("boom", "c", "home", &[raw, "tap:key:id:save"]);
            assert_eq!(
                replay_actions(&r),
                vec!["tap:key:id:save"],
                "raw typed value must be dropped: {raw}"
            );
        }
    }

    #[test]
    fn group_buckets_by_identity_sorted_by_count() {
        let occ = vec![
            (1i64, "t1".to_string(), rec("boom 1", "crashA", "home", &[])),
            (2, "t2".to_string(), rec("boom 2", "crashA", "home", &[])),
            (3, "t3".to_string(), rec("other", "crashB", "home", &[])),
        ];
        let g = group(&occ);
        assert_eq!(g.len(), 2);
        // crashA bucket (2 occurrences) sorts before crashB (1).
        assert_eq!(g[0].1.len(), 2);
        assert_eq!(g[0].1, vec![0, 1]);
        assert_eq!(g[1].1.len(), 1);
    }

    #[test]
    fn lineage_reads_build_version_and_commit() {
        let mut oldest = rec("e", "s", "home", &[]);
        oldest.context.insert(
            "build".into(),
            json!({ "version": "1.4.2", "commit": "abc" }),
        );
        let mut newest = rec("e", "s", "home", &[]);
        newest
            .context
            .insert("build".into(), json!({ "version": "1.4.5" }));
        let l = lineage(&oldest, &newest);
        assert_eq!(l["firstSeen"]["version"], "1.4.2");
        assert_eq!(l["firstSeen"]["commit"], "abc");
        assert_eq!(l["lastSeen"]["version"], "1.4.5");
        assert!(l["lastSeen"].get("commit").is_none());
    }

    #[test]
    fn build_version_reads_context_build_version() {
        let mut r = rec("e", "s", "home", &[]);
        assert_eq!(build_version(&r), None);
        r.context
            .insert("build".into(), json!({ "version": "1.4.5", "commit": "z" }));
        assert_eq!(build_version(&r).as_deref(), Some("1.4.5"));
    }

    #[test]
    fn timeline_buckets_by_window_and_build_with_totals() {
        // Two occurrences in the same hour on build 1.0, one the next hour on 1.1.
        let occ = vec![
            ("2026-06-21T00:05:00Z".to_string(), Some("1.0".to_string())),
            ("2026-06-21T00:40:00Z".to_string(), Some("1.0".to_string())),
            ("2026-06-21T01:10:00Z".to_string(), Some("1.1".to_string())),
        ];
        let t = timeline(&occ, DEFAULT_TIMELINE_WINDOW_SECS);
        // Two windows in the total series, oldest first.
        assert_eq!(t.total.len(), 2);
        assert_eq!(t.total[0].count, 2);
        assert_eq!(t.total[1].count, 1);
        // The hour-00 window collapses both 1.0 hits into one cell of count 2.
        assert_eq!(t.cells.len(), 2);
        assert_eq!(t.cells[0].build, "1.0");
        assert_eq!(t.cells[0].count, 2);
        assert_eq!(t.cells[1].build, "1.1");
        assert_eq!(t.cells[1].count, 1);
        // Window labels are floored to the hour grid.
        assert_eq!(t.cells[0].window, "2026-06-21T00:00:00+00:00");
        assert_eq!(t.cells[1].window, "2026-06-21T01:00:00+00:00");
    }

    #[test]
    fn timeline_counts_occurrences_with_no_build_as_unknown() {
        // A quiet build with no version tag must not vanish from the picture.
        let occ = vec![
            ("2026-06-21T00:05:00Z".to_string(), None),
            ("2026-06-21T00:06:00Z".to_string(), Some("2.0".to_string())),
        ];
        let t = timeline(&occ, DEFAULT_TIMELINE_WINDOW_SECS);
        // Same window, two builds: "2.0" and "unknown" (sorted: "2.0" < "unknown").
        assert_eq!(t.cells.len(), 2);
        assert!(t.cells.iter().any(|c| c.build == "unknown" && c.count == 1));
        assert!(t.cells.iter().any(|c| c.build == "2.0" && c.count == 1));
        assert_eq!(t.total.len(), 1);
        assert_eq!(t.total[0].count, 2);
    }

    #[test]
    fn repro_status_summarizes_attempts() {
        let none: Vec<ReplayResult> = vec![];
        assert_eq!(repro_status(&none)["status"], "ready");
        let results = vec![
            ReplayResult {
                status: "reproduced".into(),
                runs: 3,
                failures: 3,
                local_repro_id: Some("abc123".into()),
                created_at: "t2".into(),
            },
            ReplayResult {
                status: "clean".into(),
                runs: 3,
                failures: 0,
                local_repro_id: None,
                created_at: "t1".into(),
            },
        ];
        let s = repro_status(&results);
        assert_eq!(s["status"], "reproduced"); // latest (newest-first) wins
        assert_eq!(s["attempts"], 2);
        assert_eq!(s["reproduced"], 1);
        assert_eq!(s["rate"], json!(0.5));
        assert_eq!(s["localReproId"], "abc123");
    }
}
