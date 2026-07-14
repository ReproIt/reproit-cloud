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

Selection (`scheduler::pick`), lowest score claimed first:

1. **Hard admission gates** (`may_claim`), independent of priority:
   - elastic tier: always admit (Linux burst absorbs it).
   - **per-tenant lane cap**: `tenant_running < tenant_lane_cap`. The hard ceiling
     on bought concurrency. This is the gate that makes managed iOS sellable.
   - **interactive headroom**: batch may not consume the last
     `mac_reserved_interactive` free slots, so an interactive shard never queues
     behind a 10k-shard sweep.
2. **Priority** (`claim_score`) among the admissible: **least-slack-first**
   (`deadline - now - est_runtime`), interactive boosted ahead of batch, plus a
   **fairness penalty** on tenants running above `pool_capacity / active_tenants`
   so one tenant's campaign cannot starve another. Deterministic tiebreak on
   deadline then tenant, so all workers agree.

## Wiring into the existing claim path

`worker::claim` today fans across tenant DBs and grabs "the first pending shard
whose backend is in the worker's caps" (FIFO-ish; global fairness is Open
Question 4). Three changes turn that into the policy above, smallest first:

1. **Within a tenant** - replace the FIFO `ORDER BY` in the per-tenant claim
   query with the `claim_score` expression (least-slack + interactive boost +
   fairness penalty). `scheduler::claim_score` is the canonical mirror; keep the
   SQL and it byte-aligned with a test, same pattern as the fixture v2 contract.
2. **Hard gates in SQL** - add `AND tenant_running < lane_cap` and the
   interactive-headroom predicate to the claim `WHERE`, so a capped/headroom
   violation is never even locked. `may_claim` is the mirror for tests.
3. **Across tenants** - visit tenants in fairness order (least running-share
   first) instead of arbitrary, closing Open Question 4. The per-tenant
   `tenant_pending_shards` hint already exists; add a running-share column.

New fields this needs:

- `JobSpec`: `class: Option<"interactive"|"batch">` (default via `class_for`),
  and an SLA per class to compute `deadline_unix = enqueue + sla(class)`.
- shard row: `enqueue_unix`, `deadline_unix`, `class` (denormalized for ORDER BY).
- org/plan: `mac_lane_cap` (the bought iOS concurrency).
- a pool snapshot the claim handler reads: `mac_total` (= owned+burst macs *
  sims_per_mac), `mac_running`, `mac_reserved_interactive`.

## Sizing the owned pool

`macs_needed(ios_shards_per_s, mean_runtime_s, sims_per_mac, TARGET_UTIL)`:
offered load (Erlangs) = arrival_rate * mean_runtime; slots = load / target_util;
hosts = ceil(slots / sims_per_mac). `sims_per_mac` is RAM-bound concurrency per
box, so you buy capacity on **two axes**: more RAM per Mac (more sims/host) and
more hosts.

Size to **sustained peak**, not instantaneous peak. The scheduler + autoscaler
absorb spikes; they cannot beat a sustained load above the ceiling (the queue
just grows). Sizing to sustained instead of instantaneous is the big Mac saving.

## Autoscale

`autoscale(q_depth, running, mean_runtime_s, sla_s, sims_per_mac, current_macs)`
returns the desired host delta to drain the current backlog within the SLA, with
`DOWNSCALE_HYSTERESIS` so we don't release a 24h-billed Mac we'll re-need. It is a
**spike shaver on an owned baseline**: keep the owned pool at sustained-peak,
burst cloud Macs (Orka / EC2 mac, minutes to allocate, 24h min) above it, release
only after sustained idle past the min-commit window.

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
