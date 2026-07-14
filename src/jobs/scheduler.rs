//! Shard scheduling policy for the worker pool: WHICH pending shard a claiming
//! worker should get, WHEN batch work must yield to interactive, and HOW MANY
//! Macs the iOS tier needs to hold an SLA. This is the pure decision core; the
//! claim handler (`worker::claim`) and the autoscale control loop call into it.
//!
//! Design (see docs/architecture/scheduler.md):
//!   * Tiers: `ios` is Mac-bound and scarce (Apple hardware, cannot autoscale to
//!     zero); `web`/`android` run on elastic Linux. The scheduler only RATIONS
//!     the Mac tier; the elastic tier is treated as unbounded.
//!   * Classes: Interactive (a human/agent is blocked: a `reproduce` or a quick
//!     scan) vs Batch (a background fuzz campaign nobody waits on). Interactive
//!     keeps reserved Mac headroom so it never queues behind a 10k-shard sweep.
//!   * Objective: minimize Mac-hours subject to p95 wait <= SLA, i.e. run the
//!     pool at `TARGET_UTIL` (~0.8), never 100%. Queue wait explodes past ~0.85.
//!   * Policy: least-slack-first, with a fairness penalty so one tenant's huge
//!     campaign cannot starve another, and a HARD per-tenant lane cap.
//!
//! Pure + deterministic: wall-clock time is passed in as unix seconds, never read
//! here, so every decision is unit-testable and reproducible.
#![allow(dead_code)] // wired into the claim path + control loop incrementally.

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

/// Steady-state Mac utilization we size and autoscale toward. Above ~0.85 the
/// M/M/c queue wait grows nonlinearly, so we deliberately leave headroom.
pub const TARGET_UTIL: f64 = 0.80;

/// How much more urgent an interactive shard is treated than a batch one, in
/// "slack seconds": interactive is scheduled as if its deadline were this much
/// nearer. One hour is enough to jump it ahead of any same-day campaign.
const INTERACTIVE_BOOST: f64 = 3600.0;

/// Each running shard a tenant holds ABOVE its fair share adds this many apparent
/// slack-seconds to its next shard, so a tenant hogging the pool yields to a
/// tenant that is under-served. Soft pressure; the lane cap is the hard stop.
const FAIRNESS_PENALTY: f64 = 30.0;

/// Don't release Macs until desired is at least this many below current. Cloud
/// Macs bill in 24h blocks, so scale-down is deliberately sticky to avoid paying
/// to reacquire a host we just dropped.
const DOWNSCALE_HYSTERESIS: u32 = 1;

/// Deployment-level scheduler configuration.
///
/// Rationing is a property of the POOL, not the deployment. It applies wherever a
/// SHARED, FINITE pool executes shards:
///   * A self-host deployment driving its own simulators does not ration:
///     that is the customer's capacity, and a pulling worker only claims when it
///     has a free slot, so the gates are inert and `pick` is plain least-slack.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// When false, the commercial gates are inert (unlimited lanes, no interactive
    /// floor, no autoscale); only least-slack priority remains.
    pub rationed: bool,
    /// Default per-tenant Mac lane cap when rationed (a per-org value may override).
    pub default_lane_cap: u32,
    /// Free Mac slots held for interactive work when rationed.
    pub reserved_interactive: u32,
    /// Target steady-state utilization for sizing/autoscale.
    pub target_util: f64,
}

impl SchedulerConfig {
    /// A self-host deployment driving its own workers: no rationing, plain
    /// least-slack. Unlimited lanes, no interactive floor.
    pub fn self_hosted() -> Self {
        Self {
            rationed: false,
            default_lane_cap: u32::MAX,
            reserved_interactive: 0,
            target_util: TARGET_UTIL,
        }
    }

    /// This distribution has exactly one scheduler posture.
    pub fn from_env() -> Self {
        Self::self_hosted()
    }

    /// The lane cap to enforce for a tenant, honoring a per-org override. Unlimited
    /// when unrationed (self-host).
    pub fn lane_cap(&self, org_override: Option<u32>) -> u32 {
        if !self.rationed {
            return u32::MAX;
        }
        org_override.unwrap_or(self.default_lane_cap)
    }

    /// The `PoolState` the claim path passes to `pick`: `Some` (gated) only when
    /// rationed; `None` (least-slack, self-regulating workers) otherwise. The
    /// caller supplies the live pool occupancy (`mac_total`, `mac_running`).
    pub fn pool_state(&self, mac_total: u32, mac_running: u32) -> Option<PoolState> {
        if !self.rationed {
            return None;
        }
        Some(PoolState {
            mac_total,
            mac_running,
            mac_reserved_interactive: self.reserved_interactive,
        })
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

/// A fully-resolved scheduling candidate: one claimable pending shard plus the
/// tenant/pool context the policy needs. The claim handler builds these from the
/// pending rows it is about to choose among; the policy never touches the DB.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub tenant: String,
    pub tier: Tier,
    pub class: Class,
    /// `enqueue_unix + SLA(class)`. The instant this shard is late.
    pub deadline_unix: i64,
    /// Mean per-shard runtime estimate (seconds), for slack + sizing.
    pub est_remaining_s: f64,
    /// Shards this tenant currently has RUNNING in this tier.
    pub tenant_running: u32,
    /// `pool_capacity / active_tenants`, precomputed by the caller.
    pub tenant_fair_share: u32,
    /// Hard ceiling on this tenant's concurrent shards in this tier (the lane
    /// count it has bought / its plan allows).
    pub tenant_lane_cap: u32,
}

/// Snapshot of the rationed (Mac) pool at claim time. `mac_total` is the SIM-SLOT
/// capacity (macs * sims_per_mac), not the host count.
#[derive(Debug, Clone, Copy)]
pub struct PoolState {
    pub mac_total: u32,
    pub mac_running: u32,
    /// Free Mac slots reserved for interactive work; batch may not consume the
    /// pool below this floor.
    pub mac_reserved_interactive: u32,
}

/// HARD admission gates (independent of priority). A candidate that fails any of
/// these must not be claimed even if it is the most urgent.
pub fn may_claim(c: &Candidate, pool: &PoolState) -> bool {
    // The elastic tier is unrationed: Linux burst absorbs it.
    if c.tier != Tier::Mac {
        return true;
    }
    // Per-tenant lane cap: never let one tenant exceed its bought concurrency.
    if c.tenant_running >= c.tenant_lane_cap {
        return false;
    }
    let free = pool.mac_total.saturating_sub(pool.mac_running);
    if free == 0 {
        return false;
    }
    // Protect interactive headroom: batch may not take the last reserved slots.
    if matches!(c.class, Class::Batch) && free <= pool.mac_reserved_interactive {
        return false;
    }
    true
}

/// Claim priority. LOWER is claimed sooner. Least-slack-first, interactive boosted
/// ahead of batch, with a fairness penalty on tenants over their share.
pub fn claim_score(c: &Candidate, now_unix: i64) -> f64 {
    let slack = (c.deadline_unix - now_unix) as f64 - c.est_remaining_s;
    let boost = match c.class {
        Class::Interactive => INTERACTIVE_BOOST,
        Class::Batch => 0.0,
    };
    let over = c.tenant_running.saturating_sub(c.tenant_fair_share) as f64;
    slack - boost + FAIRNESS_PENALTY * over
}

/// Pick the shard a worker should claim: the admissible candidate with the lowest
/// `claim_score`. `pool` is `Some` only when a SHARED, finite pool is executing
/// the shard (our hosted Mac pool); then the hard gates apply and the worker may
/// idle (`None`) to protect the interactive floor. `pool` is `None` when the
/// caller drives its OWN workers (a self-host deployment, or the elastic Linux
/// tier): there is nothing to ration, a pulling worker only asks when it has a
/// free slot, so we skip the gates and return the least-slack shard. Priority
/// (least-slack, interactive-first) applies either way. Mirrors the SQL ORDER BY;
/// kept here so the policy is testable.
pub fn pick<'a>(
    cands: &'a [Candidate],
    pool: Option<&PoolState>,
    now_unix: i64,
) -> Option<&'a Candidate> {
    cands
        .iter()
        .filter(|c| pool.is_none_or(|p| may_claim(c, p)))
        .min_by(|a, b| {
            claim_score(a, now_unix)
                .partial_cmp(&claim_score(b, now_unix))
                .unwrap_or(std::cmp::Ordering::Equal)
                // Stable tiebreak: older deadline first, then tenant name, so the
                // choice is deterministic across workers and across DB row order.
                .then(a.deadline_unix.cmp(&b.deadline_unix))
                .then(a.tenant.cmp(&b.tenant))
        })
}

/// Sustained Mac HOST count to serve an offered iOS load at `TARGET_UTIL`.
/// Offered load (Erlangs) = arrival_rate * mean_runtime. Sim slots needed =
/// load / target_util; hosts = ceil(slots / sims_per_mac). This is the pool you
/// OWN; the autoscaler bursts above it for spikes.
pub fn macs_needed(
    ios_shards_per_s: f64,
    mean_runtime_s: f64,
    sims_per_mac: u32,
    target_util: f64,
) -> u32 {
    if sims_per_mac == 0 || target_util <= 0.0 || ios_shards_per_s <= 0.0 {
        return 0;
    }
    let slots = (ios_shards_per_s * mean_runtime_s) / target_util;
    (slots / sims_per_mac as f64).ceil() as u32
}

/// Autoscale verdict for the control loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    Up(u32),
    Down(u32),
    Hold,
}

/// Desired Mac count to drain the current iOS backlog within `sla_s`, with
/// hysteresis. Scale-down is conservative (24h cloud-Mac billing), so we only
/// release when desired is `DOWNSCALE_HYSTERESIS` hosts below current.
///
/// NOTE: this reacts to a SPIKE in the backlog. It cannot beat a SUSTAINED load
/// above the pool ceiling: if `macs_needed(sustained...)` exceeds what you are
/// willing to own + burst, the queue grows without bound regardless. Size the
/// owned pool to sustained peak; this only shaves the spikes on top.
pub fn autoscale(
    q_depth: u32,
    running: u32,
    mean_runtime_s: f64,
    sla_s: f64,
    sims_per_mac: u32,
    current_macs: u32,
) -> Scale {
    if sims_per_mac == 0 || sla_s <= 0.0 {
        return Scale::Hold;
    }
    let work_s = (q_depth + running) as f64 * mean_runtime_s;
    let slots = (work_s / sla_s).ceil();
    let desired = (slots / sims_per_mac as f64).ceil() as u32;
    if desired > current_macs {
        Scale::Up(desired - current_macs)
    } else if desired + DOWNSCALE_HYSTERESIS < current_macs {
        Scale::Down(current_macs - desired)
    } else {
        Scale::Hold
    }
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
            est_remaining_s: 60.0,
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
    fn interactive_jumps_ahead_of_a_more_urgent_batch() {
        // Batch deadline is sooner, but interactive's boost wins.
        let batch = cand("a", Class::Batch, 1_000, 0, 10);
        let inter = cand("b", Class::Interactive, 2_000, 0, 10);
        let pool = PoolState {
            mac_total: 8,
            mac_running: 0,
            mac_reserved_interactive: 2,
        };
        let cands = [batch, inter];
        let picked = pick(&cands, Some(&pool), 0).unwrap();
        assert_eq!(picked.tenant, "b");
    }

    #[test]
    fn lane_cap_is_a_hard_stop() {
        let c = cand("a", Class::Interactive, 1_000, 5, 5); // running == cap
        let pool = PoolState {
            mac_total: 8,
            mac_running: 5,
            mac_reserved_interactive: 0,
        };
        assert!(!may_claim(&c, &pool));
        assert!(pick(std::slice::from_ref(&c), Some(&pool), 0).is_none());
    }

    #[test]
    fn batch_cannot_eat_interactive_headroom_but_interactive_can() {
        // 2 free slots, both reserved for interactive.
        let pool = PoolState {
            mac_total: 8,
            mac_running: 6,
            mac_reserved_interactive: 2,
        };
        let batch = cand("a", Class::Batch, 1_000, 0, 10);
        let inter = cand("b", Class::Interactive, 1_000, 0, 10);
        assert!(!may_claim(&batch, &pool));
        assert!(may_claim(&inter, &pool));
        // With only batch available, the worker idles to protect the headroom.
        assert!(pick(std::slice::from_ref(&batch), Some(&pool), 0).is_none());
    }

    #[test]
    fn fairness_penalty_yields_to_an_underserved_tenant() {
        // Same deadline + class; hog is over its fair share of 4, other is under.
        let mut hog = cand("hog", Class::Batch, 1_000, 8, 20);
        hog.tenant_fair_share = 4;
        let mut fair = cand("fair", Class::Batch, 1_000, 1, 20);
        fair.tenant_fair_share = 4;
        let pool = PoolState {
            mac_total: 32,
            mac_running: 9,
            mac_reserved_interactive: 0,
        };
        let cands = [hog, fair];
        let picked = pick(&cands, Some(&pool), 0).unwrap();
        assert_eq!(picked.tenant, "fair");
    }

    #[test]
    fn self_host_is_unrationed_pure_least_slack() {
        let cfg = SchedulerConfig::self_hosted();
        assert!(!cfg.rationed);
        assert_eq!(cfg.lane_cap(Some(2)), u32::MAX); // override ignored, no caps
        assert!(cfg.pool_state(8, 8).is_none()); // no gated pool -> pick sees None
                                                 // A tenant already "over" any cap, pool notionally full: with pool = None
                                                 // (self-regulating workers) the gates never fire, so the most urgent
                                                 // (soonest deadline) shard still gets claimed.
        let soon = cand("own", Class::Batch, 100, 99, 1);
        let late = cand("own", Class::Batch, 9_000, 0, 1);
        let cands = [late, soon];
        let picked = pick(&cands, None, 0).unwrap();
        assert_eq!(picked.deadline_unix, 100);
    }

    #[test]
    fn sizing_uses_offered_load_over_target_util() {
        // 0.2 ios shards/s * 300s = 60 Erlangs; /0.8 = 75 slots; /5 sims = 15 macs.
        assert_eq!(macs_needed(0.2, 300.0, 5, 0.80), 15);
        assert_eq!(macs_needed(0.0, 300.0, 5, 0.80), 0);
    }

    #[test]
    fn autoscale_up_then_hold_then_sticky_down() {
        // 100 queued+running * 60s = 6000s of work; /600s SLA = 10 slots; /5 = 2 macs.
        assert_eq!(autoscale(90, 10, 60.0, 600.0, 5, 1), Scale::Up(1));
        assert_eq!(autoscale(90, 10, 60.0, 600.0, 5, 2), Scale::Hold);
        // Backlog drains: desired 0, current 3 -> release (3 > 0 + hysteresis).
        assert_eq!(autoscale(0, 0, 60.0, 600.0, 5, 3), Scale::Down(3));
        // One host above desired: hysteresis holds (don't flap a 24h-billed Mac).
        assert_eq!(autoscale(0, 0, 60.0, 600.0, 5, 1), Scale::Hold);
    }
}
