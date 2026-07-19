//! RANKED-BY-IMPACT ordering: the "what do I fix first?" default for the bucket
//! list. A bug list sorted by recency or raw count buries the one bug that is
//! crashing users RIGHT NOW under a pile of stale low-severity noise. This module
//! turns a bucket's signals into a single, deterministic, EXPLAINABLE impact score
//! so the dashboard's default order is "fix this first".
//!
//! Everything here is a PURE, side-effect-free transform over signals a handler
//! has already fetched (the crash signature, the occurrence count, the timeline,
//! the computed resolution status), exactly like `ingest::buckets` and
//! `triage::resolution`. The DB reads live in the handler; the ranking is a pure
//! function of its inputs, so it unit-tests with no DB/HTTP and the order is
//! reproducible across runs.
//!
//! The score is a WEIGHTED SUM of six factors, each a bounded contribution so no
//! single signal can dominate, and each surfaced in a `why` breakdown so the
//! ranking is trustable (a user can SEE why a bug is #1). The weights and the
//! severity table are founder-tunable named constants, never magic numbers at the
//! call site:
//!
//! - SEVERITY: the oracle class (crash > leak > operability > jank/overflow),
//!   a weight table keyed off the crash signature.
//! - BLAST: blast radius. Distinct affected users is the true metric; occurrence
//!   count is the supported proxy today (one row per occurrence), so the count
//!   stands in until sessions land.
//! - FREQUENCY: the recent occurrence RATE (hits in the recent window).
//! - TREND: velocity. Is it spiking? Derived from the timeline slope so a bug
//!   accelerating NOW outranks a stable one of equal size.
//! - RECENCY: recently-seen outranks stale (an exponential decay on the gap since
//!   the last occurrence).
//! - ACTIONABLE: a boost for NEW and for REGRESSED buckets, the ones a dev can act
//!   on immediately (a fresh bug, or a fix that just broke).

use super::buckets::Timeline;
use serde_json::{json, Value};

// ---- factor weights (founder-tunable; shipped as named constants) -----------

/// Weight on the SEVERITY factor (oracle class). Severity is the spine of the
/// ranking, a crash must outrank a cosmetic jank of equal volume, so it carries
/// the largest weight.
pub const W_SEVERITY: f64 = 40.0;

/// Weight on BLAST RADIUS (distinct affected users; occurrence count is today's
/// proxy). A bug hitting many users outranks one hitting a handful.
pub const W_BLAST: f64 = 25.0;

/// Weight on FREQUENCY (recent occurrence rate). A bug firing often right now is
/// more urgent than one that fired a lot once and stopped.
pub const W_FREQUENCY: f64 = 15.0;

/// Weight on TREND/velocity (is it spiking?). A bug accelerating NOW gets pushed
/// up the list ahead of a stable one of the same size.
pub const W_TREND: f64 = 20.0;

/// Weight on RECENCY (recently-seen vs stale). Decays the score of a bug that has
/// gone quiet, without erasing it (a stale crash still outranks a fresh jank).
pub const W_RECENCY: f64 = 15.0;

/// Additive BOOST for a NEW bucket (never touched): actionable right now, file it
/// or grab it. Applied on top of the weighted factors so a brand-new crash leaps
/// to the top of the queue.
pub const BOOST_NEW: f64 = 12.0;

/// Additive BOOST for a REGRESSED bucket (prod contradicts a claimed fix): the
/// single most actionable state, a fix that just broke. Deliberately set ABOVE
/// the sum of every weighted factor (`W_SEVERITY + W_BLAST + W_FREQUENCY +
/// W_TREND + W_RECENCY` = 115), so ANY regression jumps straight to the top of
/// the queue ahead of any non-regressed bug, however severe or spiking. Among
/// regressed buckets, the underlying factors still order them, the boost is a
/// constant lift that preserves their relative ranking.
pub const BOOST_REGRESSED: f64 = 120.0;

// ---- severity by oracle class -----------------------------------------------

/// The oracle/severity class of a bucket, ordered most-severe first. Cloud data
/// alone doesn't carry a structured oracle tag, so we classify off the crash
/// signature + message tokens the SDK already emits (`classify`). The ordinal is
/// the relative severity weight (0..=1 after normalization in `severity_factor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A hard crash / unhandled exception: the app died. Highest severity.
    Crash,
    /// A resource/memory leak: degrades over time, eventually fatal.
    Leak,
    /// An operability / accessibility failure (a11y, focus trap, unreachable
    /// control): the app is up but a class of users can't operate it.
    Operability,
    /// A visual jank / layout overflow: cosmetic, lowest severity.
    Jank,
    /// Anything we can't classify from the signal: a middling default so an
    /// unclassified bug isn't silently buried OR falsely promoted to crash.
    Unclassified,
}

impl Severity {
    /// The relative severity weight in `0.0..=1.0` (crash is 1.0). This is the
    /// founder-tunable severity TABLE: the gaps between classes are the policy.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Crash => 1.0,
            Severity::Leak => 0.8,
            Severity::Operability => 0.55,
            Severity::Jank => 0.3,
            Severity::Unclassified => 0.5,
        }
    }

    /// The wire label surfaced in the `why` breakdown.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Crash => "crash",
            Severity::Leak => "leak",
            Severity::Operability => "operability",
            Severity::Jank => "jank",
            Severity::Unclassified => "unclassified",
        }
    }
}

/// The cloud's half of the cross-repo oracle contract: EVERY oracle category the
/// reproit CLI can stamp onto a finding (its `oracle` field), mapped to the
/// Severity class the cloud weights it as. This is the single place the cloud
/// acknowledges an oracle id; the CLI's canonical list lives in
/// `reproit-cli/crates/reproit/oracle-registry.json` and this table MUST cover
/// every id in it (enforced by `known_oracles_cover_the_cli_registry`). When the
/// CLI adds an oracle, CI fails there until the id + its Severity are added here.
/// The Severity assignment is founder-tunable policy (same as the keyword table
/// in `classify`): crash/hang are outages; leak and wakelock degrade; occlusion/
/// choice/broken-route/security/divergence and the metamorphic family
/// (rotation, background-restore, scroll-round-trip,
/// safe-area, permission-walk, invariant, contract) are real functional/operability
/// defects; content/flicker/visual/jank are cosmetic.
pub const KNOWN_ORACLES: &[(&str, Severity)] = &[
    // Registry/taxonomy drift is diagnostic evidence, never a confirmed bug.
    ("unclassified", Severity::Unclassified),
    ("crash", Severity::Crash),
    ("hang", Severity::Crash),
    ("leak", Severity::Leak),
    ("occlusion", Severity::Operability),
    ("detached-indicator", Severity::Operability),
    ("choice-anomaly", Severity::Operability),
    ("broken-route", Severity::Operability),
    ("stuck-keyboard", Severity::Operability),
    ("duplicate-submit", Severity::Operability),
    ("focus-loss", Severity::Operability),
    ("accessibility-state", Severity::Operability),
    ("blank-screen", Severity::Operability),
    ("zoom-reflow", Severity::Operability),
    ("security", Severity::Operability),
    ("divergence", Severity::Operability),
    ("invariant", Severity::Operability),
    ("contract", Severity::Operability),
    ("rotation", Severity::Operability),
    ("background-restore", Severity::Operability),
    ("scroll-round-trip", Severity::Operability),
    ("safe-area", Severity::Operability),
    ("permission-walk", Severity::Operability),
    ("wakelock", Severity::Leak),
    ("broken-asset", Severity::Jank),
    ("jank", Severity::Jank),
    ("content-bug", Severity::Jank),
    ("flicker", Severity::Jank),
    ("visual", Severity::Jank),
];

/// The Severity for a STRUCTURED oracle id (the finding's `oracle` field), the
/// authoritative classifier. An unrecognized id remains `Unclassified`, so a newer CLI
/// never breaks ingestion and prose cannot promote taxonomy drift into a bug claim.
pub fn severity_for_oracle(id: &str) -> Severity {
    KNOWN_ORACLES
        .iter()
        .find(|(k, _)| *k == id)
        .map(|(_, s)| *s)
        .unwrap_or(Severity::Unclassified)
}

// ---- the score + its explanation --------------------------------------------

/// Default recency half-life, in seconds: how fast a bug's recency contribution
/// decays once it goes quiet. 24h means a bug last seen a day ago keeps half its
/// recency credit; a week-old one keeps ~1/128. Founder-tunable.
pub const RECENCY_HALF_LIFE_SECS: f64 = 24.0 * 3600.0;

/// The window, in seconds, the FREQUENCY factor counts occurrences over (the
/// "recent rate"). 24h by default: occurrences in the last day are "recent".
pub const FREQUENCY_WINDOW_SECS: i64 = 24 * 3600;

/// The occurrence count (within the frequency window) that saturates the
/// FREQUENCY factor to 1.0. Past this a bug is "firing constantly"; more hits
/// don't make it more urgent. Founder-tunable.
pub const FREQUENCY_SATURATION: f64 = 50.0;

/// The total occurrence count that saturates the BLAST factor to 1.0. A bug that
/// has hit this many times has maximal blast credit; the curve is logarithmic so
/// the first few users matter most. Founder-tunable.
pub const BLAST_SATURATION: f64 = 500.0;

/// The computed impact score for one bucket plus the breakdown behind it, so the
/// ranking is explainable. `score` is the sort key (higher = fix first); `why`
/// carries each factor's contribution so the dashboard can show "ranked #1
/// because: crash, spiking, 300 users hit it".
#[derive(Debug, Clone, PartialEq)]
pub struct Impact {
    pub score: f64,
    pub severity: Severity,
    pub why: Value,
}

/// The resolution-derived actionability of a bucket, reduced to exactly what the
/// impact boost needs: is it brand NEW (never touched) and/or REGRESSED (prod
/// contradicts a claimed fix). The handler maps the triage row + resolution
/// `Outcome` to these two flags; the score stays pure by taking them as bools.
#[derive(Debug, Clone, Copy, Default)]
pub struct Actionability {
    pub is_new: bool,
    pub is_regressed: bool,
}

/// The signals one bucket contributes to the ranking, gathered by the handler
/// from already-fetched data. Keeping them in one struct keeps `impact_score`'s
/// signature honest and the call site readable.
#[derive(Debug, Clone)]
pub struct BucketSignals<'a> {
    /// The structured oracle id from the finding. Missing or unrecognized ids
    /// remain unclassified; message prose never upgrades evidence severity.
    pub oracle: Option<&'a str>,
    /// Total occurrence count for the bucket (today's blast-radius proxy).
    pub count: u64,
    /// The bucket's occurrence time-series (drives trend/velocity + frequency).
    pub timeline: &'a Timeline,
    /// RFC3339 of the bucket's most recent occurrence, or None if somehow empty
    /// (drives recency). The handler reads it off the newest occurrence.
    pub last_seen: Option<&'a str>,
    /// NEW / REGRESSED flags (drive the actionability boost).
    pub action: Actionability,
}

/// PURE, deterministic, EXPLAINABLE impact score. Combines the six founder-tunable
/// factors into a single sort key and emits the `why` breakdown that justifies the
/// rank. No DB/HTTP, no clock read except the `now` passed in, so the same inputs
/// always produce the same score (ties break deterministically downstream on the
/// stable bucket id).
///
/// Each factor is normalized to `0.0..=1.0` before its weight is applied, so a
/// weight is the factor's MAX contribution and the weights are directly
/// comparable. The boosts are additive on top (a NEW or REGRESSED bug is pushed
/// up regardless of its raw factors, because it's the one a dev can act on now).
pub fn impact_score(sig: &BucketSignals, now: &str) -> Impact {
    // Structured taxonomy is authoritative. Prose is presentation, not proof.
    let severity = sig
        .oracle
        .map(severity_for_oracle)
        .unwrap_or(Severity::Unclassified);
    let now_epoch = parse_epoch(now);

    let f_sev = severity.weight();
    let f_blast = blast_factor(sig.count);
    let f_freq = frequency_factor(sig.timeline, now_epoch);
    let f_trend = trend_factor(sig.timeline);
    let f_recency = recency_factor(sig.last_seen, now_epoch);

    let mut score = W_SEVERITY * f_sev
        + W_BLAST * f_blast
        + W_FREQUENCY * f_freq
        + W_TREND * f_trend
        + W_RECENCY * f_recency;

    // Actionability boosts: additive, on top of the weighted factors.
    let mut boost = 0.0;
    if sig.action.is_new {
        boost += BOOST_NEW;
    }
    if sig.action.is_regressed {
        boost += BOOST_REGRESSED;
    }
    score += boost;

    // Round to 2dp so the score is stable/serialization-clean and ties between
    // genuinely-equal buckets are exact (broken downstream on bucket id).
    let score = (score * 100.0).round() / 100.0;

    let why = json!({
        "severity": { "class": severity.as_str(), "factor": round2(f_sev), "weight": W_SEVERITY },
        "blast": { "factor": round2(f_blast), "weight": W_BLAST, "count": sig.count },
        "frequency": { "factor": round2(f_freq), "weight": W_FREQUENCY },
        "trend": { "factor": round2(f_trend), "weight": W_TREND, "spiking": f_trend > 0.5 },
        "recency": { "factor": round2(f_recency), "weight": W_RECENCY },
        "boost": { "new": sig.action.is_new, "regressed": sig.action.is_regressed, "total": round2(boost) },
    });

    Impact {
        score,
        severity,
        why,
    }
}

/// BLAST factor in `0.0..=1.0`: a logarithmic curve on the occurrence count, so
/// the first handful of affected users move the needle most and the factor
/// saturates near `BLAST_SATURATION`. (Distinct users is the true metric; the
/// occurrence count is the supported proxy today.)
fn blast_factor(count: u64) -> f64 {
    if count == 0 {
        return 0.0;
    }
    let c = (count as f64).ln_1p();
    let cap = BLAST_SATURATION.ln_1p();
    (c / cap).min(1.0)
}

/// FREQUENCY factor in `0.0..=1.0`: occurrences in the recent window
/// (`FREQUENCY_WINDOW_SECS` back from `now`) over `FREQUENCY_SATURATION`, capped.
/// Counts straight off the timeline's per-window totals so it agrees with the
/// graph the dashboard shows. With no parseable `now` we can't bound a window, so
/// the factor is 0 (fails low, never falsely urgent).
fn frequency_factor(timeline: &Timeline, now_epoch: Option<i64>) -> f64 {
    let Some(now) = now_epoch else {
        return 0.0;
    };
    let cutoff = now - FREQUENCY_WINDOW_SECS;
    let recent: u64 = timeline
        .total
        .iter()
        .filter(|c| parse_epoch(&c.window).is_some_and(|w| w >= cutoff))
        .map(|c| c.count)
        .sum();
    (recent as f64 / FREQUENCY_SATURATION).min(1.0)
}

/// TREND/velocity factor in `0.0..=1.0`: is the bug spiking? We split the total
/// series into an OLDER half and a NEWER half (by window) and compare their hit
/// rates. A newer half busier than the older half is acceleration (factor > 0.5);
/// a fading bug scores below 0.5; a flat or single-window series sits at 0.5
/// (neutral, neither penalized nor boosted). Bounded to `0.0..=1.0`.
fn trend_factor(timeline: &Timeline) -> f64 {
    let n = timeline.total.len();
    if n < 2 {
        return 0.5; // not enough history to call a trend: neutral.
    }
    let mid = n / 2;
    let older: u64 = timeline.total[..mid].iter().map(|c| c.count).sum();
    let newer: u64 = timeline.total[mid..].iter().map(|c| c.count).sum();
    let (older, newer) = (older as f64, newer as f64);
    if older + newer == 0.0 {
        return 0.5;
    }
    // newer share of the two halves: 0.5 = flat, ->1.0 = all-recent spike,
    // ->0.0 = fully faded. This IS the bounded velocity signal.
    newer / (older + newer)
}

/// RECENCY factor in `0.0..=1.0`: exponential decay on the gap since `last_seen`,
/// with half-life `RECENCY_HALF_LIFE_SECS`. Just-seen = 1.0; one half-life ago =
/// 0.5; long-stale -> 0. A future-dated or unparseable timestamp clamps to 1.0
/// (treat "just seen"): never penalize a bug for a clock quirk. None (no last
/// occurrence) -> 0.
fn recency_factor(last_seen: Option<&str>, now_epoch: Option<i64>) -> f64 {
    let (Some(last), Some(now)) = (last_seen.and_then(parse_epoch), now_epoch) else {
        return 0.0;
    };
    let gap = (now - last) as f64;
    if gap <= 0.0 {
        return 1.0;
    }
    0.5_f64.powf(gap / RECENCY_HALF_LIFE_SECS)
}

fn parse_epoch(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.timestamp())
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::buckets::{Timeline, TimelineCell, TimelineCount};

    /// Build a total-only timeline from (window_rfc3339, count) pairs. Cells are
    /// filled to mirror the totals (single synthetic build) so the shape is valid.
    fn tl(points: &[(&str, u64)]) -> Timeline {
        Timeline {
            cells: points
                .iter()
                .map(|(w, c)| TimelineCell {
                    window: w.to_string(),
                    build: "1.0".to_string(),
                    count: *c,
                })
                .collect(),
            total: points
                .iter()
                .map(|(w, c)| TimelineCount {
                    window: w.to_string(),
                    count: *c,
                })
                .collect(),
        }
    }

    fn signals<'a>(
        _crash_sig: &'a str,
        _message: &'a str,
        count: u64,
        timeline: &'a Timeline,
        last_seen: Option<&'a str>,
        action: Actionability,
    ) -> BucketSignals<'a> {
        BucketSignals {
            oracle: Some("crash"),
            count,
            timeline,
            last_seen,
            action,
        }
    }

    const NOW: &str = "2026-06-21T12:00:00Z";

    #[test]
    fn severity_table_orders_crash_over_leak_over_operability_over_jank() {
        assert!(Severity::Crash.weight() > Severity::Leak.weight());
        assert!(Severity::Leak.weight() > Severity::Operability.weight());
        assert!(Severity::Operability.weight() > Severity::Jank.weight());
    }

    #[test]
    fn severity_for_oracle_maps_known_ids_and_defaults_unclassified() {
        assert_eq!(severity_for_oracle("crash"), Severity::Crash);
        assert_eq!(severity_for_oracle("hang"), Severity::Crash);
        assert_eq!(severity_for_oracle("leak"), Severity::Leak);
        assert_eq!(severity_for_oracle("security"), Severity::Operability);
        assert_eq!(severity_for_oracle("rotation"), Severity::Operability);
        assert_eq!(severity_for_oracle("stuck-keyboard"), Severity::Operability);
        assert_eq!(severity_for_oracle("occlusion"), Severity::Operability);
        assert_eq!(severity_for_oracle("graph"), Severity::Unclassified);
        assert_eq!(severity_for_oracle("overflow"), Severity::Unclassified);
        assert_eq!(severity_for_oracle("dynamic-type"), Severity::Unclassified);
        assert_eq!(severity_for_oracle("undo-inverse"), Severity::Unclassified);
        // An id the cloud does not recognize remains Unclassified. It is retained
        // without guessing severity from prose.
        assert_eq!(severity_for_oracle("metamorphic"), Severity::Unclassified);
        assert_eq!(
            severity_for_oracle("deep-link-parity"),
            Severity::Unclassified
        );
        assert_eq!(
            severity_for_oracle("no-such-oracle"),
            Severity::Unclassified
        );
    }

    #[test]
    fn impact_score_uses_only_the_structured_oracle() {
        let t = tl(&[(NOW, 1)]);
        // A "security" finding whose sig/message carry NO severity keywords:
        // keyword inference alone would land Unclassified (0.5), but the structured
        // oracle id classifies it Operability.
        let mut sig = signals(
            "someSig",
            "a plain message",
            1,
            &t,
            Some(NOW),
            Actionability::default(),
        );
        sig.oracle = Some("security");
        assert_eq!(impact_score(&sig, NOW).severity, Severity::Operability);
        // An unrecognized oracle id remains unclassified; taxonomy drift cannot
        // manufacture a confirmed bug from presentation prose.
        sig.oracle = Some("brand-new-oracle");
        assert_eq!(impact_score(&sig, NOW).severity, Severity::Unclassified);
    }

    // CROSS-REPO DRIFT GUARD (P0). tests/golden/fixtures/oracle-registry.json is a
    // pinned copy of reproit-cli's canonical oracle contract. The cloud MUST map
    // every id in it (via KNOWN_ORACLES) or CI fails HERE until the new id + its
    // Severity are added. A newer CLI never breaks ingestion (severity_for_oracle
    // degrades safely to Unclassified); this test is the alarm to add
    // first-class handling. Mirrors the fixture-spec drift test in cohorts.rs.
    #[test]
    fn known_oracles_cover_the_cli_registry() {
        const REGISTRY: &str = include_str!("../../tests/golden/fixtures/oracle-registry.json");
        let doc: serde_json::Value =
            serde_json::from_str(REGISTRY).expect("registry is valid JSON");
        let cli_ids: Vec<String> = doc["oracles"]
            .as_array()
            .expect("registry has an `oracles` array")
            .iter()
            .map(|v| v.as_str().expect("each oracle id is a string").to_string())
            .collect();
        let missing: Vec<&str> = cli_ids
            .iter()
            .map(|s| s.as_str())
            .filter(|id| !KNOWN_ORACLES.iter().any(|(k, _)| k == id))
            .collect();
        assert!(
            missing.is_empty(),
            "P0: reproit-cloud does not handle oracle id(s) {missing:?} from the CLI registry. \
             Add them to impact::KNOWN_ORACLES with a Severity."
        );

        // When the CLI repo is checked out beside the cloud, the pinned golden must
        // equal the live contract, so it cannot silently rot.
        let sibling = std::path::Path::new("../reproit-cli/crates/reproit/oracle-registry.json");
        if sibling.exists() {
            let live = std::fs::read_to_string(sibling).expect("read sibling registry");
            let live_json: serde_json::Value =
                serde_json::from_str(&live).expect("sibling registry is valid JSON");
            assert_eq!(
                doc, live_json,
                "the pinned oracle-registry.json golden has drifted from reproit-cli's live copy; \
                 refresh tests/golden/fixtures/oracle-registry.json."
            );
        }
    }

    #[test]
    fn spiking_crash_outranks_stable_crash_outranks_stale_jank() {
        // A SPIKING crash: recent windows much busier than older ones, seen now.
        let spiking = tl(&[
            ("2026-06-21T06:00:00Z", 1),
            ("2026-06-21T07:00:00Z", 2),
            ("2026-06-21T10:00:00Z", 20),
            ("2026-06-21T11:00:00Z", 40),
        ]);
        let spiking_crash = impact_score(
            &signals(
                "crashCheckout",
                "panic null deref",
                63,
                &spiking,
                Some("2026-06-21T11:30:00Z"),
                Actionability::default(),
            ),
            NOW,
        );

        // A STABLE crash: flat series, same severity, last seen recently.
        let stable = tl(&[
            ("2026-06-21T06:00:00Z", 10),
            ("2026-06-21T07:00:00Z", 10),
            ("2026-06-21T10:00:00Z", 10),
            ("2026-06-21T11:00:00Z", 10),
        ]);
        let stable_crash = impact_score(
            &signals(
                "crashSettings",
                "panic null deref",
                40,
                &stable,
                Some("2026-06-21T11:30:00Z"),
                Actionability::default(),
            ),
            NOW,
        );

        // A STALE jank: low severity, last seen a week ago, no recent hits.
        let stale = tl(&[("2026-06-14T06:00:00Z", 5), ("2026-06-14T07:00:00Z", 4)]);
        let mut stale_jank_signals = signals(
            "layoutJank",
            "visible frame jank",
            9,
            &stale,
            Some("2026-06-14T07:00:00Z"),
            Actionability::default(),
        );
        stale_jank_signals.oracle = Some("jank");
        let stale_jank = impact_score(&stale_jank_signals, NOW);

        assert!(
            spiking_crash.score > stable_crash.score,
            "spiking crash ({}) must outrank stable crash ({})",
            spiking_crash.score,
            stable_crash.score
        );
        assert!(
            stable_crash.score > stale_jank.score,
            "stable crash ({}) must outrank stale jank ({})",
            stable_crash.score,
            stale_jank.score
        );
        // And the severity classes came out right.
        assert_eq!(spiking_crash.severity, Severity::Crash);
        assert_eq!(stale_jank.severity, Severity::Jank);
    }

    #[test]
    fn a_regression_jumps_to_the_top() {
        // The strongest possible NON-regressed bug: a SPIKING, high-blast crash,
        // seen right now (max severity + max recency + acceleration). This is the
        // hardest thing for a regression to beat.
        let spiking = tl(&[
            ("2026-06-21T08:00:00Z", 1),
            ("2026-06-21T09:00:00Z", 2),
            ("2026-06-21T10:00:00Z", 30),
            ("2026-06-21T11:00:00Z", 60),
        ]);
        let worst_active_crash = impact_score(
            &signals(
                "crashCheckout",
                "panic null deref",
                999,
                &spiking,
                Some("2026-06-21T11:59:00Z"),
                Actionability::default(),
            ),
            NOW,
        );

        // A modest, low-severity jank that has REGRESSED must STILL outrank it: the
        // regression boost is set above the sum of every weighted factor, so any
        // regression is the dominant actionability signal.
        let small_jank = tl(&[("2026-06-21T11:00:00Z", 2)]);
        let mut regressed_jank_signals = signals(
            "layoutJank",
            "visible frame jank",
            3,
            &small_jank,
            Some("2026-06-21T11:30:00Z"),
            Actionability {
                is_new: false,
                is_regressed: true,
            },
        );
        regressed_jank_signals.oracle = Some("jank");
        let regressed_jank = impact_score(&regressed_jank_signals, NOW);
        let big_stable_crash = worst_active_crash;

        assert!(
            regressed_jank.score > big_stable_crash.score,
            "a regressed bucket ({}) must jump above a non-regressed crash ({})",
            regressed_jank.score,
            big_stable_crash.score
        );
        // The why breakdown makes the regression boost explicit.
        assert_eq!(regressed_jank.why["boost"]["regressed"], json!(true));
    }

    #[test]
    fn new_bucket_gets_a_boost_over_an_identical_touched_one() {
        let series = tl(&[("2026-06-21T11:00:00Z", 5)]);
        let mk = |action| {
            impact_score(
                &signals(
                    "crashX",
                    "panic",
                    10,
                    &series,
                    Some("2026-06-21T11:30:00Z"),
                    action,
                ),
                NOW,
            )
        };
        let new = mk(Actionability {
            is_new: true,
            is_regressed: false,
        });
        let touched = mk(Actionability::default());
        assert!(new.score > touched.score);
        assert!((new.score - touched.score - BOOST_NEW).abs() < 0.01);
    }

    #[test]
    fn ties_are_deterministic_identical_inputs_score_identically() {
        // Two buckets with identical signals must score EXACTLY equal, so the
        // downstream tie-break (stable bucket id) is the only thing that orders
        // them, reproducibly.
        let series = tl(&[("2026-06-21T11:00:00Z", 7)]);
        let a = impact_score(
            &signals(
                "crashSame",
                "panic",
                21,
                &series,
                Some("2026-06-21T11:30:00Z"),
                Actionability::default(),
            ),
            NOW,
        );
        let b = impact_score(
            &signals(
                "crashSame",
                "panic",
                21,
                &series,
                Some("2026-06-21T11:30:00Z"),
                Actionability::default(),
            ),
            NOW,
        );
        assert_eq!(a.score, b.score);
    }

    #[test]
    fn recency_decays_a_stale_bug_below_a_fresh_one_all_else_equal() {
        let series = tl(&[("2026-06-21T11:00:00Z", 5)]);
        let fresh = impact_score(
            &signals(
                "crashX",
                "panic",
                10,
                &series,
                Some("2026-06-21T11:55:00Z"),
                Actionability::default(),
            ),
            NOW,
        );
        let stale = impact_score(
            &signals(
                "crashX",
                "panic",
                10,
                &series,
                Some("2026-06-10T00:00:00Z"),
                Actionability::default(),
            ),
            NOW,
        );
        assert!(fresh.score > stale.score);
    }

    #[test]
    fn trend_factor_reads_acceleration_from_the_slope() {
        // Rising series -> > 0.5 (spiking); falling -> < 0.5; flat -> 0.5.
        let rising = tl(&[
            ("2026-06-21T08:00:00Z", 1),
            ("2026-06-21T09:00:00Z", 1),
            ("2026-06-21T10:00:00Z", 10),
            ("2026-06-21T11:00:00Z", 10),
        ]);
        let falling = tl(&[
            ("2026-06-21T08:00:00Z", 10),
            ("2026-06-21T09:00:00Z", 10),
            ("2026-06-21T10:00:00Z", 1),
            ("2026-06-21T11:00:00Z", 1),
        ]);
        let flat = tl(&[
            ("2026-06-21T08:00:00Z", 5),
            ("2026-06-21T09:00:00Z", 5),
            ("2026-06-21T10:00:00Z", 5),
            ("2026-06-21T11:00:00Z", 5),
        ]);
        assert!(trend_factor(&rising) > 0.5);
        assert!(trend_factor(&falling) < 0.5);
        assert!((trend_factor(&flat) - 0.5).abs() < 1e-9);
        // A single window is neutral (no trend to call).
        assert!((trend_factor(&tl(&[("2026-06-21T11:00:00Z", 9)])) - 0.5).abs() < 1e-9);
    }
}
