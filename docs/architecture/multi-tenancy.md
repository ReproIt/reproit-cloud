# Multi-tenancy architecture

Status: implemented, with the production verification gaps listed in section 8.

This document describes the hosted service as it ships. The hosted application
uses a control plane for identity and routing, one Postgres database per
organization for customer data, and a tenant-bound object-store scope. The
self-hosted product runs the same data-plane model with one fixed tenant.

## 1. Security boundary

Customer telemetry, findings, evidence metadata, jobs, and project state live in
a database dedicated to one organization. Tenant tables do not carry an
`org_id` isolation column. A query against a tenant store therefore cannot read
another organization's rows because those rows are in a different database.

The shared control database contains only cross-tenant control-plane state:

- users, sessions, organizations, memberships, invitations, and API keys;
- audit state, plus billing/SSO/SCIM columns added by the hosted edition's
  schema extension (self-host never creates or reads them);
- the tenant registry, including database connection and blob scope;
- bounded scheduling hints needed to select tenant work.

It does not contain customer event graphs, finding evidence, or replay data.

Blob access is bound to the same resolved tenant as the database handle. Hosted
R2 uses a stable `t/<org_id>/` key scope. When credential minting is configured,
every operation uses temporary credentials restricted to that exact prefix and
fails closed if minting fails. It never falls back to the parent credential.

## 2. Request lifecycle

Authentication resolves a request to an organization before customer data is
accessed:

1. An API key names its organization. A dashboard session uses its explicit
   `active_org_id`; membership is checked when the active organization changes.
2. `tenancy::resolver::Resolver` loads the organization's active tenant record.
   A suspended, provisioning, or missing tenant is not served.
3. The resolver acquires a pool for that tenant's database and derives a blob
   handle for that tenant's registered scope.
4. The handler receives a `Tenant` containing the bound `TenantStore` and
   `TenantBlobs`. It does not receive an unrestricted customer-data store.

The resolver caches mappings for at most 120 seconds and at most 8,192
organizations. Provisioning, offboarding, and connection changes invalidate the
mapping and pool eagerly. On a cache miss, a control-plane failure fails the
request rather than guessing a mapping.

The admin principal may select a tenant for an explicit operation. It is never
used as an implicit tenant default.

## 3. Connection ownership and bounds

`tenancy::pool::TenantPools` owns live tenant pools. Its bounds are explicit:

- at most 256 live pools by default, configurable with
  `REPROIT_TENANT_POOL_CAP` and clamped to at least one;
- at most four connections in each tenant pool;
- a 10-second connection acquisition timeout;
- a 60-second SQLx idle timeout and 900-second maximum connection lifetime;
- eviction after 300 seconds without use by default, configurable with
  `REPROIT_TENANT_POOL_IDLE_SECS`;
- least-recently-used eviction when the live-pool cap is exceeded.

Pool construction occurs outside the cache lock. If concurrent requests race to
create the same pool, one pool becomes canonical and the extra pool is dropped.
A periodic application task sweeps idle pools.

Hosted connection strings request Neon's pooled endpoint. The application-side
bounds above still require a production load test against real provider limits,
as recorded in section 8.

## 4. Provisioning and recovery

Provisioning crosses the control and tenant planes, so its order is deliberate:

1. Persist a `provisioning` tenant record in the control database.
2. Provision or adopt a stable provider database for the organization.
3. Persist the connection string.
4. Apply the tenant schema.
5. persist the blob mode and `t/<org_id>` scope;
6. change the tenant status to `active` last.

Each step is idempotent. Startup reconciliation retries every tenant left in
`provisioning`, and one failed tenant does not block reconciliation of others.
The resolver only serves `active` records, so partially provisioned storage is
not reachable through normal request paths.

The hosted `NeonProvider` uses a stable per-organization project name, adopts an
existing project on retry, creates the tenant database, and requests a pooled
connection URI. Local development uses real database-per-tenant provisioning on
one Postgres server.

## 5. Schema and data ownership

`db::control::CONTROL_SCHEMA` owns control-plane tables.
`db::schema::TENANT_SCHEMA` owns customer-data tables. Architecture tests assert
that customer tables do not drift into the control schema and control tables do
not drift into tenant databases.

The tenant schema includes projects, event graph edges, findings and evidence
metadata, replay results, triage and resolution state, jobs, and shards. `app_id`
remains inside a tenant database to distinguish an organization's projects. It
is not the tenant boundary.

The schema is applied idempotently at provisioning and startup. A version record
tracks the current declarative schema. Before storing production customer data,
destructive schema evolution requires a migration process with rollback and
fleet verification rather than relying only on idempotent creation statements.

## 6. Blob isolation

`tenancy::blob` exposes a tenant-scoped handle, not a raw shared bucket handle.
The default hosted mode is prefix isolation with a trailing slash. This prevents
the scope for `t/4` from including `t/42`.

With `R2_CREDS_API_TOKEN` and `R2_ACCOUNT_ID` configured, the service requests
temporary R2 credentials restricted to the resolved prefix. Credentials are
cached by scope and refreshed before a signed URL could outlive its signing
credential. A minting failure fails the tenant operation.

Unit tests verify the requested Cloudflare policy, prefix normalization,
credential cache behavior, and fail-closed behavior against a local mock. A live
Cloudflare test is still required to prove provider enforcement, see section 8.

Self-hosted mode uses its configured S3-compatible bucket or local directory for
its single tenant. It does not need a cross-tenant credential boundary.

## 7. Self-hosted mode

Self-hosted mode sets one fixed organization and one `TENANT_DATABASE_URL`.
Resolution skips the hosted tenant-registry lookup and always returns a store for
that fixed database plus the single configured blob scope. The handlers, tenant
schema, event protocol, replay model, and data-plane operations remain the same.

The multi-tenant data plane itself is shared, composable library code, not a
hosted-only surface. `REPROIT_TENANT_PROVIDER` selects `local` (a
database-per-org on the base Postgres) or, behind the `neon` feature, a
project-per-org provider; the R2 backend can mint short-lived prefix-scoped
credentials via Cloudflare's temp-access-credentials API. Self-host leaves the
provider unset (single tenant) and uses convention-only blob scoping, so this
code is dormant by default. `scripts/audit-boundary.sh` therefore forbids only
the genuinely hosted-only surfaces (billing flows, enterprise SSO/SCIM, hosted
usage metering), not the shared tenancy provider or the credential minter.

The source-available self-hosted Cloud is licensed under Elastic License 2.0.
The CLI and SDK repositories are separate and licensed under Apache License 2.0.

## 8. Production release gates still required

The implementation and local integration tests establish the application
boundaries. They do not substitute for these provider and workload checks:

1. Run a live Cloudflare R2 isolation test with two tenant credentials. Each
   credential must read and write its own prefix and must be denied access to the
   other prefix. Record credential-policy inputs and cleanup evidence.
2. Run a bounded active-tenant load test against the production Neon pooler.
   Record pool hit and miss latency, cold-resume latency, open connections,
   eviction, error rate, throughput, and provider limits at the tested scale.
3. Exercise control-plane interruption with both cached and uncached tenants.
   Record the current fail-closed behavior and recovery after the control plane
   returns. A future stale-cache availability policy requires a separate threat
   model before implementation.
4. Exercise backup and restore for the control database, one tenant database,
   and one tenant blob scope. Verify row and object counts before declaring the
   restore successful.
5. Run two-tenant API and dashboard negative tests in the deployed environment,
   including active-org switching, API-key routing, evidence URLs, worker result
   submission, suspension, and offboarding.

Release evidence must identify the exact deployed commit and provider
configuration. Each gate must also bind its exact GitHub Actions workflow run
and downloaded artifact digest to that commit. A mock-only result cannot close
a live-provider gate.

All five gates are executable harnesses driven by the deploy repo's
`hosted-production-gates` workflow (one job per gate). The R2 isolation, Neon
pool-load, and control-plane interruption gates live in this repository as
ignored tests (`tenancy::blob::r2_scoped_creds_tests` and
`tenancy::gate_drills`); the interruption drill runs entirely against a
disposable local Postgres, the other two against protected disposable provider
resources. The backup-restore and two-tenant negative gates are scripts in the
deploy repo. A passing gate writes a JSON evidence fragment to
`GATE_EVIDENCE_PATH` (see `tenancy::gate_evidence`), each job uploads its
fragment as a run artifact, and the deploy repo's
`scripts/assemble_production_evidence.py` folds the fragments plus run
provenance into the one bounded manifest. `release-1.0.sh` refuses the first
hosted 1.0 release unless `scripts/verify_production_readiness.py` accepts
that manifest for the exact commit being deployed.
