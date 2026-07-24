//! Shard scheduling policy for the worker pool: WHICH pending work a claiming
//! worker should try for next. This is the pure decision core; the claim path
//! (`worker::claim_across_tenants`) gathers the candidate set from the tenant
//! DBs, asks `claim_order`, then attempts the atomic per-job DB claims in that
//! order. The DB claim (`FOR UPDATE SKIP LOCKED`) enforces mutual exclusion;
//! this module only decides ORDER.
//!
//! Design (see docs/architecture/scheduler.md):
//!   * Tiers: `ios` is Mac-bound and scarce (Apple hardware, cannot autoscale to
//!     zero); `web`/`android` run on elastic Linux. Only the Mac tier carries a
//!     hard per-tenant lane cap; the elastic tier is treated as unbounded.
//!   * Classes: Interactive (a human/agent is blocked: a `reproduce` or a quick
//!     scan) vs Batch (a background fuzz campaign nobody waits on). Interactive
//!     is boosted so it never queues behind a 10k-shard sweep.
//!   * Policy: least-slack-first, with a fairness penalty so one tenant's huge
//!     campaign cannot starve another, and a HARD per-tenant Mac lane cap.
//!
//! Every worker is a PULL client that only claims when it has a free slot, so
//! pool occupancy self-regulates; there is no central pool-occupancy state to
//! gate on, only ordering and the lane cap.
//!
//! Pure + deterministic: wall-clock time is passed in as unix seconds, never read
//! here, so every decision is unit-testable and reproducible.

/// Execution tier of a shard's backend. Only `Mac` is rationed; `Elastic` runs
/// on Linux and is treated as effectively unbounded (burst containers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Elastic,
    Mac,
}

/// Map a `JobSpec.backend` to its tier. Only iOS *requires* a Mac; Android
/// emulators run on Linux and web is headless, so both are elastic.
pub fn tier(backend: &str) -> Tier {
    match backend {
        "ios" => Tier::Mac,
        _ => Tier::Elastic,
    }
}

/// Service class. Interactive is latency-sensitive work a caller is blocked on;
/// Batch is throughput work nobody waits on synchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Interactive,
    Batch,
}

/// Jobs at or below this shard count (or an explicit `reproduce`) default to
/// interactive; larger campaigns are batch. The submitter may override.
pub const INTERACTIVE_SHARD_MAX: u32 = 4;

/// Turnaround SLA per class, in seconds: a shard's deadline is its enqueue
/// instant plus the SLA of its class, and urgency (slack) is measured against
/// that deadline. Interactive targets minutes (a caller is blocked); batch
/// targets hours (a campaign nobody waits on).
pub const INTERACTIVE_SLA_S: i64 = 600;
pub const BATCH_SLA_S: i64 = 6 * 3600;

/// How much more urgent an interactive shard is treated than a batch one, in
/// "slack seconds", ON TOP of its nearer SLA deadline: interactive is scheduled
/// as if its deadline were this much nearer still.
const INTERACTIVE_BOOST: f64 = 3600.0;

/// Each running shard a tenant holds ABOVE its fair share adds this many apparent
/// slack-seconds to its next shard, so a tenant hogging the pool yields to a
/// tenant that is under-served. Soft pressure; the lane cap is the hard stop.
const FAIRNESS_PENALTY: f64 = 30.0;

/// Default per-tenant Mac lane cap on the hosted pool.
pub const DEFAULT_LANE_CAP: u32 = 4;

/// Deployment-level scheduler configuration.
///
/// Rationing is a property of the POOL, not the deployment. It applies wherever
/// a SHARED, FINITE pool executes shards:
///   * Reproit's HOSTED control plane rations its own Mac pool (`hosted()`):
///     per-tenant lane caps on the iOS tier.
///   * A SELF-HOST deployment driving its OWN simulators does not
///     (`self_hosted()`): that is the customer's capacity, so the gate is inert
///     and ordering is plain least-slack + fairness.
///
/// Follows the existing "self-host removes commercial seat caps" rule (main.rs).
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// When false, the commercial gate is inert (unlimited lanes); only
    /// least-slack priority and the fairness penalty remain.
    pub rationed: bool,
    /// Per-tenant Mac lane cap when rationed.
    pub default_lane_cap: u32,
}

impl SchedulerConfig {
    /// Reproit's hosted control plane: ration the shared Mac pool.
    pub fn hosted() -> Self {
        Self {
            rationed: true,
            default_lane_cap: DEFAULT_LANE_CAP,
        }
    }

    /// A self-host deployment driving its own workers: no rationing, unlimited
    /// lanes.
    pub fn self_hosted() -> Self {
        Self {
            rationed: false,
            default_lane_cap: u32::MAX,
        }
    }

    /// Select from the deployment's RESOLVED self-host flag (`App.self_hosted`,
    /// the same resolution that removes seat caps), honoring the hosted pool
    /// knob `REPROIT_SCHED_LANE_CAP` when set to a positive integer.
    pub fn resolve(self_hosted: bool) -> Self {
        if self_hosted {
            return Self::self_hosted();
        }
        let mut cfg = Self::hosted();
        if let Ok(v) = std::env::var("REPROIT_SCHED_LANE_CAP") {
            if let Ok(n) = v.parse::<u32>() {
                if n > 0 {
                    cfg.default_lane_cap = n;
                }
            }
        }
        cfg
    }

    /// The lane cap the claim path enforces per tenant on the Mac tier.
    /// Unlimited when unrationed (self-host).
    pub fn lane_cap(&self) -> u32 {
        if self.rationed {
            self.default_lane_cap
        } else {
            u32::MAX
        }
    }
}

/// Derive a class from job shape when the submitter does not pin one.
pub fn class_for(mode: &str, seeds: u32) -> Class {
    if mode == "reproduce" || seeds <= INTERACTIVE_SHARD_MAX {
        Class::Interactive
    } else {
        Class::Batch
    }
}

/// The instant work of `class` enqueued at `enqueue_unix` is late.
pub fn deadline_unix(enqueue_unix: i64, class: Class) -> i64 {
    enqueue_unix.saturating_add(match class {
        Class::Interactive => INTERACTIVE_SLA_S,
        Class::Batch => BATCH_SLA_S,
    })
}

/// A tenant's fair share of a tier's occupancy: total running shards across the
/// competing tenants divided by the number of tenants with pending work. The
/// fairness penalty bites only tenants running ABOVE this average.
pub fn fair_share(tier_running_total: u32, active_tenants: u32) -> u32 {
    tier_running_total.checked_div(active_tenants).unwrap_or(0)
}

/// A fully-resolved scheduling candidate: one job with claimable pending shards
/// plus the tenant context the policy needs. The claim path builds these from
/// the tenant DBs it is about to choose among; the policy never touches the DB.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub tenant: String,
    pub tier: Tier,
    pub class: Class,
    /// `enqueue_unix + SLA(class)`. The instant this work is late.
    pub deadline_unix: i64,
    /// Shards this tenant currently has RUNNING in this tier.
    pub tenant_running: u32,
    /// `fair_share(tier_running_total, active_tenants)`, precomputed by the
    /// caller over the gathered candidate set.
    pub tenant_fair_share: u32,
    /// Hard ceiling on this tenant's concurrent Mac shards (the lane count its
    /// plan allows); `u32::MAX` when unrationed.
    pub tenant_lane_cap: u32,
}

/// HARD admission gate, independent of priority: the per-tenant Mac lane cap.
/// The elastic tier is unrationed (Linux burst absorbs it). A candidate that
/// fails this must not be claimed even if it is the most urgent.
pub fn may_claim(c: &Candidate) -> bool {
    c.tier != Tier::Mac || c.tenant_running < c.tenant_lane_cap
}

/// Claim priority. LOWER is claimed sooner. Least-slack-first, interactive
/// boosted ahead of batch, with a fairness penalty on tenants over their share.
pub fn claim_score(c: &Candidate, now_unix: i64) -> f64 {
    let slack = (c.deadline_unix - now_unix) as f64;
    let boost = match c.class {
        Class::Interactive => INTERACTIVE_BOOST,
        Class::Batch => 0.0,
    };
    let over = c.tenant_running.saturating_sub(c.tenant_fair_share) as f64;
    slack - boost + FAIRNESS_PENALTY * over
}

/// The order a worker should attempt claims in: every admissible candidate,
/// most urgent first (lowest `claim_score`). Returns indices into `cands` so
/// the caller can map back to its claim targets. Losing the DB race on one
/// candidate falls through to the next; the DB enforces mutual exclusion, this
/// only orders. Tiebreak is older deadline, then tenant name, then input order,
/// so the ranking is deterministic across workers and across DB row order.
pub fn claim_order(cands: &[Candidate], now_unix: i64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..cands.len()).filter(|&i| may_claim(&cands[i])).collect();
    order.sort_by(|&a, &b| {
        let (a, b) = (&cands[a], &cands[b]);
        claim_score(a, now_unix)
            .partial_cmp(&claim_score(b, now_unix))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.deadline_unix.cmp(&b.deadline_unix))
            .then(a.tenant.cmp(&b.tenant))
    });
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(tenant: &str, class: Class, deadline: i64, running: u32, cap: u32) -> Candidate {
        Candidate {
            tenant: tenant.into(),
            tier: Tier::Mac,
            class,
            deadline_unix: deadline,
            tenant_running: running,
            tenant_fair_share: 4,
            tenant_lane_cap: cap,
        }
    }

    #[test]
    fn ios_is_the_only_mac_tier() {
        assert_eq!(tier("ios"), Tier::Mac);
        assert_eq!(tier("android"), Tier::Elastic);
        assert_eq!(tier("web"), Tier::Elastic);
    }

    #[test]
    fn class_defaults_by_size_and_mode() {
        assert_eq!(class_for("fuzz", 64), Class::Batch);
        assert_eq!(class_for("fuzz", 3), Class::Interactive);
        assert_eq!(class_for("reproduce", 999), Class::Interactive);
    }

    #[test]
    fn deadline_tracks_the_class_sla() {
        assert_eq!(
            deadline_unix(1_000, Class::Interactive),
            1_000 + INTERACTIVE_SLA_S
        );
        assert_eq!(deadline_unix(1_000, Class::Batch), 1_000 + BATCH_SLA_S);
        // An interactive shard is late long before a batch shard enqueued with it.
        assert!(deadline_unix(0, Class::Interactive) < deadline_unix(0, Class::Batch));
    }

    #[test]
    fn fair_share_is_the_per_tenant_average() {
        assert_eq!(fair_share(9, 3), 3);
        assert_eq!(fair_share(2, 3), 0);
        assert_eq!(fair_share(5, 0), 0);
    }

    #[test]
    fn interactive_jumps_ahead_of_a_more_urgent_batch() {
        // Batch deadline is sooner, but interactive's boost wins.
        let batch = cand("a", Class::Batch, 1_000, 0, 10);
        let inter = cand("b", Class::Interactive, 2_000, 0, 10);
        let cands = [batch, inter];
        let order = claim_order(&cands, 0);
        assert_eq!(order, vec![1, 0]);
    }

    #[test]
    fn lane_cap_is_a_hard_stop_on_the_mac_tier_only() {
        let capped = cand("a", Class::Interactive, 1_000, 5, 5); // running == cap
        assert!(!may_claim(&capped));
        assert!(claim_order(std::slice::from_ref(&capped), 0).is_empty());
        // The same load on the elastic tier is never gated.
        let mut elastic = capped.clone();
        elastic.tier = Tier::Elastic;
        assert!(may_claim(&elastic));
        assert_eq!(claim_order(std::slice::from_ref(&elastic), 0), vec![0]);
    }

    #[test]
    fn fairness_penalty_yields_to_an_underserved_tenant() {
        // Same deadline + class; hog is over its fair share of 4, other is under.
        let hog = cand("hog", Class::Batch, 1_000, 8, 20);
        let fair = cand("fair", Class::Batch, 1_000, 1, 20);
        let cands = [hog, fair];
        assert_eq!(claim_order(&cands, 0), vec![1, 0]);
    }

    #[test]
    fn order_ranks_every_admissible_candidate_deterministically() {
        let late_batch = cand("a", Class::Batch, 9_000, 0, 10);
        let soon_batch = cand("b", Class::Batch, 1_000, 0, 10);
        let inter = cand("c", Class::Interactive, 2_000, 0, 10);
        let capped = cand("d", Class::Interactive, 0, 10, 10);
        let cands = [late_batch, soon_batch, inter, capped];
        // Interactive first, then batch by deadline; the capped one never appears.
        assert_eq!(claim_order(&cands, 0), vec![2, 1, 0]);
        // Ties break on tenant name, so all workers agree on one ranking.
        let twin_a = cand("a", Class::Batch, 1_000, 0, 10);
        let twin_b = cand("b", Class::Batch, 1_000, 0, 10);
        assert_eq!(claim_order(&[twin_b, twin_a], 0), vec![1, 0]);
    }

    #[test]
    fn self_host_is_unrationed_pure_least_slack() {
        let cfg = SchedulerConfig::self_hosted();
        assert!(!cfg.rationed);
        assert_eq!(cfg.lane_cap(), u32::MAX);
        assert!(!SchedulerConfig::resolve(true).rationed);
        // A tenant far "over" any commercial cap still gets its most urgent
        // (soonest deadline) work claimed first: the gate never fires.
        let soon = cand("own", Class::Batch, 100, 99, u32::MAX);
        let late = cand("own", Class::Batch, 9_000, 0, u32::MAX);
        let cands = [late, soon];
        assert_eq!(claim_order(&cands, 0), vec![1, 0]);
    }

    #[test]
    fn hosted_config_gates_the_mac_lane() {
        let cfg = SchedulerConfig::hosted();
        assert!(cfg.rationed);
        assert_eq!(cfg.lane_cap(), DEFAULT_LANE_CAP);
        assert!(SchedulerConfig::resolve(false).rationed);
    }
}
