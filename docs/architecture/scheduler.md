# Shard scheduler

How the worker pool decides which pending shard a claiming worker gets, how the
scarce Mac (iOS) tier is rationed, and how the owned pool is sized + autoscaled.
The pure decision core lives in `src/jobs/scheduler.rs`; this doc is the why and
the wiring.

## The problem

Fuzz/scan work is **batch + shardable**: a job fans into one independent shard
per seed (`jobs::Job::new`), and shards run in any order on any capable worker.
That makes a shared, scheduled pool strictly cheaper than per-customer reserved
lanes (an idle reserved lane is a wasted Mac). But the tiers are not equal:

- `web` / `android` -> **elastic**: Linux containers, autoscale per-second to
  zero, effectively unbounded. Never rationed.
- `ios` -> **Mac**: Apple-hardware bound, cannot autoscale to zero, cloud Macs
  bill in 24h blocks. This is the scarce resource the scheduler exists to ration.

(Your own worker note already encodes this: "a Mac for ios + android + web, a
Linux box for web/android." Only iOS *requires* the Mac.)

## Objective

Minimize Mac-hours **subject to p95 wait <= SLA**. These pull against each other:
fewer Macs -> higher utilization -> longer queues, and queue wait explodes
nonlinearly past ~85% (M/M/c). So the target is `TARGET_UTIL ~= 0.80`, never
100%. "Minimal Macs" means "run at ~80% util," not "pack to full."

## Policy (what `claim` orders by)

Two service classes:

- **Interactive** - a human or agent is blocked (a `reproduce`, a small scan).
  Wants seconds-to-minutes.
- **Batch** - a background campaign nobody waits on. Wants results within hours.

`class_for(mode, seeds)` defaults small jobs / `reproduce` to interactive, large
campaigns to batch; the submitter may pin it.

Selection (`scheduler::claim_order`), lowest score attempted first:

1. **Hard admission gate** (`may_claim`), independent of priority:
   - elastic tier: always admit (Linux burst absorbs it).
   - **per-tenant lane cap**: `tenant_running < tenant_lane_cap`. The hard ceiling
     on bought concurrency. This is the gate that makes managed iOS sellable.
2. **Priority** (`claim_score`) among the admissible: **least-slack-first**
   (`deadline_unix(enqueue, class) - now`), interactive boosted ahead of batch,
   plus a **fairness penalty** on tenants running above
   `fair_share(tier_running_total, active_tenants)` so one tenant's campaign
   cannot starve another. Deterministic tiebreak on deadline then tenant, so all
   workers agree on one ranking.

There is no pool-occupancy gate: every worker is a PULL client that only claims
when it has a free slot, so occupancy self-regulates and the control plane has no
central slot count to gate on. The one gate it must enforce is the lane cap.

## Wiring into the claim path (live)

`worker::claim_across_tenants` visits the tenants the `tenant_pending_shards`
routing hint names, and per claim:

1. **Gather** (`gather_candidates`): per tenant, `pending_jobs(caps)` (one row
   per job with claimable pending shards: backend, enqueue time, shard count)
   and `running_by_backend()` (per-tier tenant load). One `Candidate` per job;
   fair share computed over the gathered set.
2. **Order** (`scheduler::claim_order`): the pure policy ranks every admissible
   candidate. The policy never touches the DB (ratchet-adjacent purity: same
   contract as the ranking modules in `tests/architecture.rs`).
3. **Claim in order**: attempt `claim_shard(worker, caps, Some(job))` down the
   ranking. The claim query is unchanged in mechanism, `FOR UPDATE SKIP LOCKED`,
   so two workers can walk the same ranking and never double-claim; losing a
   race falls through to the next candidate.

Class derives from job shape (`class_for("fuzz", seeds)`); an explicit
`JobSpec.class` pin and a per-org purchased `mac_lane_cap` remain future schema
work (today the cap is `REPROIT_SCHED_LANE_CAP` / `DEFAULT_LANE_CAP` per
deployment).

## Sizing the owned pool (design, not code)

Offered load (Erlangs) = arrival_rate * mean_runtime; slots = load /
target_util (~0.80); hosts = ceil(slots / sims_per_mac). `sims_per_mac` is
RAM-bound concurrency per box, so you buy capacity on **two axes**: more RAM per
Mac (more sims/host) and more hosts.

Size to **sustained peak**, not instantaneous peak. A scheduler absorbs spikes;
it cannot beat a sustained load above the ceiling (the queue just grows). Sizing
to sustained instead of instantaneous is the big Mac saving.

The sizing/autoscale helpers (`macs_needed`, `autoscale`) were removed from
`scheduler.rs` when the ordering policy went live: there is no autoscale control
loop or Mac-pool inventory to drive them yet, and dead speculative code does not
ratchet. Reintroduce them with the control loop, alongside downscale hysteresis
(cloud Macs bill in 24h blocks, so release is deliberately sticky).

## Pricing tie-back

This validates runs-with-SLA pricing (the site's "N runs/mo"): a shared scheduled
pool delivers a turnaround SLA, not dedicated hardware. The build it implies:
**run counter** (meter) + **scheduler** (deliver the SLA) + **per-tenant lane
cap** (fair share + the hard gate). Web/Android stay elastic and ungated; only
the iOS lane cap is load-bearing for COGS.

## The honest floor

Scheduling raises utilization and absorbs spikes. It does **not** create
capacity. If `macs_needed(sustained...)` exceeds what you will own + burst, no
policy saves the SLA. Forecast sustained iOS load -> own that many Macs -> let the
scheduler + burst handle the variance on top.
