# Reproit Cloud code organization

Cloud follows the same correctness standard as the CLI: deterministic domain logic stays pure,
external input is bounded and fallible, and unsupported evidence causes abstention rather than a
guessed verdict.

## Dependency direction

```text
process startup -> HTTP routing/middleware -> handlers -> domain services
                                                   | -> tenant stores / blob storage
                                                   | -> workers / integrations
```

- `main.rs` is a thin process delegate. `lib.rs` owns application startup and shared state;
  `router.rs` owns route composition and transport protection profiles.
- `auth/`, `ingest/`, and `triage/` translate authenticated HTTP requests into domain operations.
- Pure scoring, grouping, identity, and resolution logic lives in focused modules beneath those
  domains. Pure code does not read environment variables, query a database, call the network, or
  inspect the clock implicitly.
- `db/` owns persistence and migrations. Tenant-bound handlers operate through a resolved `Tenant`;
  they do not reconstruct tenant identity or issue cross-tenant queries.
- `tenancy/` owns tenant resolution, provisioning, and scoped artifact storage.
- `jobs/` and `integrations/` own external execution and delivery adapters.
- `ingest/aggregation.rs`, `evidence.rs`, `export.rs`, and `replay.rs` own their named trust
  boundaries; `ingest/mod.rs` coordinates handlers and bucket presentation.

Dependencies point inward. Domain calculations receive explicit inputs and do not depend on Axum,
SQLx, process state, or dashboard presentation.

## Product trust boundary

The bug feed is a claim, not a collection of suspicions. A surfaced bug must have:

1. authoritative evidence that an exact rule was violated;
2. a stable finding identity;
3. a clean replay that reproduced that identity; and
4. enough evidence to distinguish an application failure from runner or setup failure.

Internally, evaluation may abstain when evidence is missing, ambiguous, stale, unsupported, or from
an unrecognized taxonomy. Abstention is diagnostic state; it is not a bug, a successful check, or a
third user-facing finding class. Cloud may retain such input for compatibility and investigation,
but it must not promote or rank it as a confirmed bug.

## Correctness rules

1. Bound request bytes, pagination, scans, retries, exported rows, artifact sizes, and worker
   leases.
2. Treat every wire, database, worker, integration, and artifact value as fallible.
3. Keep deterministic transforms pure and pass time, configuration, and storage in explicitly.
4. Prefer enums and state machines where correlated flags permit invalid states.
5. Preserve wire formats, stable identities, ordering, tenant boundaries, and abstention behavior
   with characterization tests before refactoring.
6. Keep one canonical implementation for routes, bucket identity, oracle taxonomy, artifact paths,
   tenant resolution, and replay status.
7. Unclassified future wire values degrade safely; they never inherit crash severity or confirmed state.
8. Keep modules cohesive and private by default. Do not add generic `utils`, `common`, or `crosscut`
   modules.
9. Put bounds in executable tests and test the value at or beyond each boundary.
10. Keep owned Rust and prose within 100 columns. Generated and third-party files are excluded.

## Refactor sequence

The current application predates these boundaries, so ratchets begin without pretending the split
is complete. Refactor in mechanically reviewable stages:

1. characterize routes, wire responses, authorization, and tenant isolation;
2. extract pure domain calculations from handlers;
3. move route construction out of process startup;
4. split large domain coordinators by responsibility; and
5. tighten the ratchets after every extraction.

Formatting, warnings-as-errors Clippy, unit tests, contract drift tests, disposable-Postgres tests,
and the applicable deployment smoke test are required for framework-wide Cloud changes.
