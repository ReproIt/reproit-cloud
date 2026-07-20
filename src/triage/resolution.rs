//! PROD-EVIDENCE resolution: the SYSTEM-computed truth about a bug, derived from
//! the production occurrence stream rather than a human's status click.
//!
//! The model (see the brief): the dev sets INTENT (the `bucket_triage.status`:
//! new/investigating/fixed/wontfix); this module computes TRUTH from what prod
//! actually sees. A bug is RESOLVED when prod stops seeing it on builds at/after
//! the claimed fix, with enough post-fix traffic that we WOULD have seen it if it
//! were still there; REGRESSED when it recurs on a fixed build; ACTIVE when no fix
//! was ever claimed. The gap between the dev's intent and this computed truth is
//! the signal the dashboard surfaces.
//!
//! Everything here is a PURE, side-effect-free decision over already-fetched data
//! (the DB read lives in the handler), exactly like `ingest::buckets` and the
//! triage state machine. The thresholds/windows are the founder's to tune; we
//! ship sensible defaults as named constants so the call sites carry no magic
//! numbers.
//!
//! TWO SIGNALS, deliberately separate:
//!   - the BUG's own occurrences on builds at/after the fix (a recurrence => the
//!     fix didn't hold => REGRESSED), and
//!   - the app's POST-FIX TRAFFIC on the fixed build (the denominator: "would we
//!     have seen it if it were still there?"). Resolution gates on this so a
//!     low-traffic bug that merely went quiet is NOT declared resolved. The
//!     handler measures traffic from the app-wide error stream on the fixed
//!     build; the decision stays pure by taking it as a number.
//!
//! BUILD ORDERING WITHOUT SEMVER. Cloud data alone can't reliably parse every
//! app's version scheme (`1.4.5`, `2026.06.21`, `canary-7`, a git sha...). So
//! "build >= fixed_in_build" is decided by FIRST-SEEN TIME in the occurrence
//! stream: a build is "at or after the fix" if its earliest occurrence is at or
//! after the fixed build's earliest occurrence (the fixed build always counts as
//! on-or-after itself). This is robust to any versioning scheme and honest about
//! what telemetry can know: users on OLD app versions still hitting the old bug
//! are NOT a regression, and first-seen ordering captures exactly that (their
//! build first appeared before the fix shipped).

use serde_json::{json, Value};

// ---- default thresholds (founder-tunable; shipped as named constants) -------

/// Minimum quiet gap, in seconds, between `now` and the LAST occurrence on a
/// fixed build before we'll call a bug RESOLVED. A bug that went quiet five
/// minutes ago isn't resolved, it's between sessions; 72h is a conservative
/// "a fix that held across a few days of normal traffic" default.
pub const DEFAULT_RESOLVE_QUIET_SECS: i64 = 72 * 3600;

/// Minimum POST-FIX TRAFFIC (app-wide occurrences observed on builds at/after the
/// fix) before a clean window counts as RESOLVED. This is the anti-false-positive
/// gate: do NOT resolve a low-traffic bug just because it went quiet. We must
/// have seen enough traffic on the fixed build that, if the bug were still there,
/// we'd have seen it recur. The founder tunes this against per-app traffic; a
/// session-count denominator is the natural next refinement.
pub const DEFAULT_MIN_POST_FIX_TRAFFIC: u64 = 50;

// ---- the computed prod-truth ------------------------------------------------

/// The SYSTEM-computed resolution truth for a bucket, distinct from the dev's
/// triage INTENT. Side by side with the triage status, the gap is the signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// No fix claimed yet (no `fixed_in_build`): truth is simply "active". The
    /// dev hasn't asserted a fix, so there's nothing for prod to confirm/deny.
    Active,
    /// A fix is claimed and prod is still validating it: the bug has stopped
    /// recurring on at/after-fix builds, but EITHER not enough post-fix traffic
    /// to be sure OR not enough quiet time has elapsed. Honest "we don't know yet".
    Resolving,
    /// Prod confirms the fix: zero recurrences on builds at/after the fix for the
    /// quiet window, AND enough post-fix traffic that we'd have seen a recurrence.
    Resolved,
    /// Prod contradicts the fix: the bug recurred on a build at/after the fix.
    /// (Occurrences on OLD builds, before the fix shipped, are NOT a regression.)
    Regressed,
}

impl Resolution {
    /// The wire string surfaced in the bucket detail's `resolution.status`.
    pub fn as_str(self) -> &'static str {
        match self {
            Resolution::Active => "active",
            Resolution::Resolving => "resolving",
            Resolution::Resolved => "resolved",
            Resolution::Regressed => "regressed",
        }
    }
}

/// Tunable thresholds for the decision, so a call site (or a test) can override
/// the shipped defaults. `Default` yields the founder-tunable constants above.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub resolve_quiet_secs: i64,
    pub min_post_fix_traffic: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            resolve_quiet_secs: DEFAULT_RESOLVE_QUIET_SECS,
            min_post_fix_traffic: DEFAULT_MIN_POST_FIX_TRAFFIC,
        }
    }
}

/// The full computed verdict: the status plus the evidence behind it, so the
/// dashboard can show "resolved BECAUSE 0 recurrences across 800 post-fix
/// sessions, quiet 5 days" or "regressed BECAUSE last seen on the fix build 1h
/// ago".
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub status: Resolution,
    pub fixed_in_build: Option<String>,
    /// RFC3339 of the bug's most recent occurrence ON A BUILD AT/AFTER THE FIX,
    /// or None if it never recurred post-fix. The "last seen on fixed build" the
    /// UI shows and the anchor for the quiet-gap check.
    pub last_seen_on_fixed_build: Option<String>,
    /// Count of THIS BUG's occurrences on builds at/after the fix (a recurrence;
    /// any nonzero value proves a regression).
    pub post_fix_occurrences: u64,
}

impl Outcome {
    /// Serialize for the bucket detail's `resolution` block (camelCase to match
    /// the rest of the detail payload).
    pub fn to_json(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "fixedInBuild": self.fixed_in_build,
            "lastSeenOnFixedBuild": self.last_seen_on_fixed_build,
            "postFixOccurrences": self.post_fix_occurrences,
        })
    }
}

/// One occurrence, reduced to exactly what the decision needs: when it happened
/// (RFC3339) and which build it was seen on (`context.build.version`, or None).
#[derive(Debug, Clone)]
pub struct Occurrence {
    pub at: String,
    pub build: Option<String>,
}

/// First-seen epoch per build across a stream of occurrences. The handler passes
/// the APP-WIDE stream so the fix build is anchored even when THIS bug never
/// recurred on it (a bucket-scoped stream would lose the anchor). Pure helper.
pub fn first_seen_by_build(occ: &[Occurrence]) -> std::collections::BTreeMap<String, i64> {
    let mut first_seen: std::collections::BTreeMap<String, i64> = Default::default();
    for o in occ {
        if let (Some(b), Some(e)) = (o.build.as_deref(), parse_epoch(&o.at)) {
            first_seen
                .entry(b.to_string())
                .and_modify(|m| *m = (*m).min(e))
                .or_insert(e);
        }
    }
    first_seen
}

/// Count app-wide POST-FIX TRAFFIC: occurrences in `app_stream` on builds whose
/// first appearance is at/after the fix build's first appearance. This is the
/// denominator the resolution gate needs ("would we have seen it if it were still
/// there?"). Pure; the handler supplies the app-wide error stream.
pub fn post_fix_traffic(app_stream: &[Occurrence], fixed_in_build: &str) -> u64 {
    let first_seen = first_seen_by_build(app_stream);
    let Some(&fix_epoch) = first_seen.get(fixed_in_build) else {
        return 0;
    };
    app_stream
        .iter()
        .filter(|o| {
            let Some(b) = o.build.as_deref() else {
                return false;
            };
            let Some(e) = parse_epoch(&o.at) else {
                return false;
            };
            let on_or_after =
                b == fixed_in_build || first_seen.get(b).is_some_and(|&first| first >= fix_epoch);
            on_or_after && e >= fix_epoch
        })
        .count() as u64
}

/// Count accepted SDK batches on builds deployed at or after the candidate fix.
pub fn post_fix_build_traffic(builds: &[(Occurrence, u64)], fixed_in_build: &str) -> u64 {
    let first_seen = first_seen_by_build(
        &builds
            .iter()
            .map(|(occurrence, _)| occurrence.clone())
            .collect::<Vec<_>>(),
    );
    let Some(&fix_epoch) = first_seen.get(fixed_in_build) else {
        return 0;
    };
    builds
        .iter()
        .filter_map(|(occurrence, count)| {
            let build = occurrence.build.as_deref()?;
            let epoch = parse_epoch(&occurrence.at)?;
            let on_or_after = build == fixed_in_build
                || first_seen
                    .get(build)
                    .is_some_and(|&first| first >= fix_epoch);
            (on_or_after && epoch >= fix_epoch).then_some(*count)
        })
        .sum()
}

/// PURE prod-truth decision. Inputs:
///   - `bug` : the BUG's own occurrences (this bucket's stream), each `(at, build)`.
///   - `fix_first_seen` : map of build -> first-seen epoch from the APP-WIDE
///     stream, so "at/after the fix" is anchored even when the bug never recurred
///     on the fix build (compute with `first_seen_by_build` over the app stream).
///   - `fixed_in_build` : the build claimed to fix the bucket, or None.
///   - `post_fix_traffic` : app-wide occurrences on at/after-fix builds (the
///     resolution denominator; compute with `post_fix_traffic`).
///   - `now` (RFC3339) + thresholds.
///
/// Rules, faithful to the model:
///   - No `fixed_in_build` => ACTIVE (the dev never asserted a fix). Untouched.
///   - Fix build never seen app-wide => RESOLVING (no anchor to confirm/deny yet).
///   - SEGMENT BY BUILD via first-seen time: a build is "at/after the fix" iff its
///     first appearance is >= the fix build's. Occurrences on builds that first
///     appeared BEFORE the fix are old-version users hitting the old bug: NOT a
///     regression, excluded from the post-fix view entirely.
///   - REGRESSED: the bug has ANY occurrence on an at/after-fix build dated
///     at/after the fix shipped. The fix didn't hold.
///   - RESOLVED: zero such recurrences, `resolve_quiet_secs` of quiet since the
///     fix shipped, AND `post_fix_traffic >= min_post_fix_traffic` (we'd have
///     seen it).
///   - RESOLVING: a fix is claimed but neither resolved nor regressed yet.
///
/// An unparseable `now` disables the time-gate (treated as the epoch), which can
/// only HOLD a resolution back to `resolving`, never falsely resolve: fails safe.
pub fn evaluate(
    bug: &[Occurrence],
    fix_first_seen: &std::collections::BTreeMap<String, i64>,
    fixed_in_build: Option<&str>,
    post_fix_traffic: u64,
    now: &str,
    th: Thresholds,
) -> Outcome {
    // No fix claimed: prod-truth is simply active, untouched.
    let Some(fixed) = fixed_in_build else {
        return Outcome {
            status: Resolution::Active,
            fixed_in_build: None,
            last_seen_on_fixed_build: None,
            post_fix_occurrences: 0,
        };
    };

    // The fix build's first appearance (app-wide) is the cut line. If it was never
    // seen, there's no anchor to segment against: the fix can't be confirmed or
    // denied yet, so stay `resolving` (claimed-but-unvalidated).
    let Some(&fix_epoch) = fix_first_seen.get(fixed) else {
        return Outcome {
            status: Resolution::Resolving,
            fixed_in_build: Some(fixed.to_string()),
            last_seen_on_fixed_build: None,
            post_fix_occurrences: 0,
        };
    };

    // Which builds are "at/after the fix": the fixed build itself, plus any build
    // whose first appearance is >= the fix build's first appearance.
    let on_or_after = |build: &str| -> bool {
        build == fixed
            || fix_first_seen
                .get(build)
                .is_some_and(|&first| first >= fix_epoch)
    };

    // The bug's post-fix RECURRENCES: its own occurrences on at/after-fix builds,
    // dated at/after the fix shipped. (The date guard makes "true recurrence"
    // explicit and is robust to any clock skew on a late-arriving event.)
    let mut post_fix_occurrences: u64 = 0;
    let mut last_seen_epoch: Option<i64> = None;
    for o in bug {
        let Some(build) = o.build.as_deref() else {
            continue; // no build tag: can't attribute to pre/post fix, skip.
        };
        let Some(epoch) = parse_epoch(&o.at) else {
            continue;
        };
        if on_or_after(build) && epoch >= fix_epoch {
            post_fix_occurrences += 1;
            last_seen_epoch = Some(last_seen_epoch.map_or(epoch, |m| m.max(epoch)));
        }
    }

    // REGRESSED: any true post-fix recurrence means the fix didn't hold.
    if post_fix_occurrences > 0 {
        return Outcome {
            status: Resolution::Regressed,
            fixed_in_build: Some(fixed.to_string()),
            last_seen_on_fixed_build: last_seen_epoch.map(epoch_to_rfc3339),
            post_fix_occurrences,
        };
    }

    // No recurrence. RESOLVED requires BOTH gates: enough quiet time since the fix
    // shipped AND enough app-wide post-fix traffic (so a quiet low-traffic bug is
    // never falsely resolved). Otherwise we're still validating: RESOLVING.
    let now_epoch = parse_epoch(now).unwrap_or(0);
    let enough_quiet = (now_epoch - fix_epoch) >= th.resolve_quiet_secs;
    let enough_traffic = post_fix_traffic >= th.min_post_fix_traffic;
    let status = if enough_quiet && enough_traffic {
        Resolution::Resolved
    } else {
        Resolution::Resolving
    };
    Outcome {
        status,
        fixed_in_build: Some(fixed.to_string()),
        last_seen_on_fixed_build: None,
        post_fix_occurrences: 0,
    }
}

fn parse_epoch(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.timestamp())
}

fn epoch_to_rfc3339(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap())
        .to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occ(at: &str, build: Option<&str>) -> Occurrence {
        Occurrence {
            at: at.to_string(),
            build: build.map(|s| s.to_string()),
        }
    }

    /// Build the app-wide first-seen map + post-fix traffic from an explicit app
    /// stream, then evaluate, the way the handler wires it. Most tests drive the
    /// bug stream AS the app stream (single-bug app) and override traffic where
    /// the volume gate is what's under test.
    fn eval(
        bug: &[Occurrence],
        app_stream: &[Occurrence],
        fixed: Option<&str>,
        traffic: u64,
        now: &str,
        th: Thresholds,
    ) -> Outcome {
        let fs = first_seen_by_build(app_stream);
        evaluate(bug, &fs, fixed, traffic, now, th)
    }

    #[test]
    fn no_fixed_in_build_is_active_untouched() {
        let stream = vec![
            occ("2026-06-01T00:00:00Z", Some("1.0")),
            occ("2026-06-02T00:00:00Z", Some("1.0")),
        ];
        let out = eval(
            &stream,
            &stream,
            None,
            0,
            "2026-07-01T00:00:00Z",
            Thresholds::default(),
        );
        assert_eq!(out.status, Resolution::Active);
        assert_eq!(out.fixed_in_build, None);
        assert_eq!(out.post_fix_occurrences, 0);
    }

    #[test]
    fn recurrence_on_new_build_at_or_after_fix_is_regressed() {
        // Fix claimed in 1.1; the bug recurs on 1.1 and on 1.2 (a newer build).
        let stream = vec![
            occ("2026-06-01T00:00:00Z", Some("1.0")), // pre-fix old build
            occ("2026-06-10T00:00:00Z", Some("1.1")), // fix build first appears
            occ("2026-06-10T01:00:00Z", Some("1.1")), // recurrence ON the fix build
            occ("2026-06-12T00:00:00Z", Some("1.2")), // recurrence on a newer build
        ];
        let out = eval(
            &stream,
            &stream,
            Some("1.1"),
            999,
            "2026-06-20T00:00:00Z",
            Thresholds::default(),
        );
        assert_eq!(out.status, Resolution::Regressed);
        // The 1.1 first-appearance hit, the 1.1 recurrence, and the 1.2 hit: 3.
        assert_eq!(out.post_fix_occurrences, 3);
        assert_eq!(
            out.last_seen_on_fixed_build.as_deref(),
            Some("2026-06-12T00:00:00+00:00")
        );
    }

    #[test]
    fn recurrence_on_old_build_before_fix_is_not_a_regression() {
        // Fix shipped in 1.5. Users still on 1.4 keep hitting the OLD bug AFTER the
        // fix (by wall clock), but on the OLD build: NOT a regression. With both
        // gates satisfied and a live fix-build anchor, prod-truth is RESOLVED.
        let bug = vec![
            occ("2026-06-01T00:00:00Z", Some("1.4")), // old build first-seen
            occ("2026-06-16T00:00:00Z", Some("1.4")), // old-build user post-fix
            occ("2026-06-20T00:00:00Z", Some("1.4")),
        ];
        // App stream additionally shows the fix build 1.5 is live (anchor) and
        // carries the post-fix traffic denominator.
        let mut app = bug.clone();
        app.push(occ("2026-06-15T00:00:00Z", Some("1.5"))); // fix build first-seen
        let out = eval(
            &bug,
            &app,
            Some("1.5"),
            500, // plenty of post-fix traffic
            "2026-08-01T00:00:00Z",
            Thresholds::default(),
        );
        assert_eq!(out.post_fix_occurrences, 0);
        assert_eq!(out.status, Resolution::Resolved);
    }

    #[test]
    fn clean_window_with_enough_volume_is_resolved() {
        // The bug only ever hit 1.9 (pre-fix). The fix shipped in 2.0, the app saw
        // heavy traffic on 2.0, and the bug never recurred. Quiet window elapsed +
        // traffic over threshold => RESOLVED.
        let bug = vec![
            occ("2026-06-01T00:00:00Z", Some("1.9")),
            occ("2026-06-05T00:00:00Z", Some("1.9")),
        ];
        let mut app = bug.clone();
        app.push(occ("2026-06-10T00:00:00Z", Some("2.0"))); // fix build live
        let out = eval(
            &bug,
            &app,
            Some("2.0"),
            DEFAULT_MIN_POST_FIX_TRAFFIC, // exactly meets the gate
            "2026-08-01T00:00:00Z",       // long past the 72h quiet window
            Thresholds::default(),
        );
        assert_eq!(out.status, Resolution::Resolved);
        assert_eq!(out.post_fix_occurrences, 0);
        assert_eq!(out.fixed_in_build.as_deref(), Some("2.0"));
    }

    #[test]
    fn quiet_but_low_volume_is_not_resolved() {
        // The false-positive guard: the bug went quiet, the quiet window elapsed,
        // but post-fix TRAFFIC is below threshold, so we can't claim "we'd have
        // seen it". Must stay RESOLVING, not resolved.
        let bug = vec![occ("2026-06-01T00:00:00Z", Some("1.9"))];
        let mut app = bug.clone();
        app.push(occ("2026-06-10T00:00:00Z", Some("2.0"))); // fix build live
        let out = eval(
            &bug,
            &app,
            Some("2.0"),
            3, // far below the default 50 traffic gate
            "2026-08-01T00:00:00Z",
            Thresholds::default(),
        );
        assert_eq!(out.status, Resolution::Resolving);
        assert_eq!(out.post_fix_occurrences, 0);
    }

    #[test]
    fn not_enough_quiet_time_stays_resolving_even_with_volume() {
        // Fix build live, no recurrence, traffic over threshold, but only an hour
        // of quiet against the 72h window: still validating.
        let bug = vec![occ("2026-06-01T00:00:00Z", Some("1.9"))];
        let mut app = bug.clone();
        app.push(occ("2026-06-10T00:00:00Z", Some("2.0")));
        let out = eval(
            &bug,
            &app,
            Some("2.0"),
            500,
            "2026-06-10T01:00:00Z", // 1h after the fix appeared
            Thresholds::default(),
        );
        assert_eq!(out.status, Resolution::Resolving);
    }

    #[test]
    fn fix_build_never_seen_is_resolving_no_anchor() {
        // A fix is claimed on a build that never appeared in prod yet: there's no
        // anchor to confirm or deny, so the honest verdict is resolving.
        let bug = vec![occ("2026-06-01T00:00:00Z", Some("1.0"))];
        let out = eval(
            &bug,
            &bug,
            Some("9.9"),
            500,
            "2026-09-01T00:00:00Z",
            Thresholds::default(),
        );
        assert_eq!(out.status, Resolution::Resolving);
        assert_eq!(out.post_fix_occurrences, 0);
    }

    #[test]
    fn unparseable_now_fails_safe_to_resolving_not_resolved() {
        // A bad `now` can only hold a resolution back, never falsely resolve.
        let bug = vec![occ("2026-06-01T00:00:00Z", Some("1.9"))];
        let mut app = bug.clone();
        app.push(occ("2026-06-10T00:00:00Z", Some("2.0")));
        let out = eval(
            &bug,
            &app,
            Some("2.0"),
            500,
            "not-a-timestamp",
            Thresholds::default(),
        );
        assert_ne!(out.status, Resolution::Resolved);
        assert_eq!(out.status, Resolution::Resolving);
    }

    #[test]
    fn post_fix_traffic_segments_by_build_first_seen() {
        // Traffic helper: only at/after-fix builds count toward the denominator.
        let app = vec![
            occ("2026-06-01T00:00:00Z", Some("1.0")), // pre-fix: excluded
            occ("2026-06-02T00:00:00Z", Some("1.0")), // pre-fix: excluded
            occ("2026-06-10T00:00:00Z", Some("1.1")), // fix build: counted
            occ("2026-06-11T00:00:00Z", Some("1.1")), // counted
            occ("2026-06-12T00:00:00Z", Some("1.2")), // newer build: counted
        ];
        assert_eq!(post_fix_traffic(&app, "1.1"), 3);
        // A fix build never seen => zero traffic (no anchor).
        assert_eq!(post_fix_traffic(&app, "9.9"), 0);
    }
}
