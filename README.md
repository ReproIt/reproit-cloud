# reproit-cloud

The source-available, self-hosted control plane for
[Reproit](https://github.com/ReproIt/reproit). It groups production failures and
CLI/CI findings into stable bugs with reproducible evidence.

## What it provides

- Production event ingest with write-only project keys
- Stable bug grouping and impact ranking
- Replay packages, evidence, reproduction history, and resolution tracking
- Collection of confirmed `scan`, `fuzz`, and production reproduction results
- GitHub, Jira, Linear, and Shortcut integrations
- Pull-based workers for private infrastructure
- Team roles, audit history, and data export
- PostgreSQL with local or S3-compatible artifact storage

The server never needs application source code. Reproduction jobs are dispatched
to your CI checkout, and workers run the same `reproit` binary as developers.

## Quick start

```bash
docker compose up -d

docker compose exec cloud reproit-cloud init \
  --email admin@example.com \
  --password 'replace-with-a-long-password' \
  --project 'My app'
```

Open `http://localhost:8080`. Save the project keys printed by `init`; they are
shown only once.

Required production configuration:

```bash
DATABASE_URL=postgres://reproit:strong-password@postgres:5432/reproit
REPROIT_PUBLIC_URL=https://bugs.example.com
REPROIT_CONN_ENC_KEY=<32-byte-hex-key>
REPROIT_ARTIFACT_DIR=/var/lib/reproit/artifacts
REPROIT_API_KEY=<long-random-operations-key>
```

Copy [.env.example](.env.example) for bootstrap and S3-compatible storage
options. Remove `REPROIT_DEV_OPEN` before exposing the service publicly.

## Execution model

```text
developer machine / CI / private worker
              |
 scan, fuzz, production replay
              |
       confirmed evidence
              v
       self-hosted Reproit Cloud
```

You provide runner capacity, backups, network access, retention, and storage.

## Core API

All `/v1/*` management routes require a secret project key. Event producers may use a
project-pinned, write-only publishable key. `POST /v1/events` accepts only a validated
`reproit-protocol` version 1 batch with a required idempotency id, strictly ordered frames, and
validated evidence graphs. The earlier permissive `{appId, events}` body is rejected.

```text
POST /v1/events
GET  /v1/graph/:app
GET  /v1/apps/:app/buckets
GET  /v1/apps/:app/buckets/:bucket
GET  /v1/apps/:app/buckets/:bucket/evidence
POST /v1/apps/:app/buckets/:bucket/evidence
GET  /v1/apps/:app/buckets/:bucket/replay-results
POST /v1/apps/:app/buckets/:bucket/replay-results
POST /v1/apps/:app/buckets/:bucket/reproduce
GET  /v1/apps/:app/export
POST /v1/worker/claim
POST /v1/worker/shards/:id/heartbeat
POST /v1/worker/shards/:id/result
```

## Security boundary

- one installation maps to one PostgreSQL database and one artifact namespace;
- secret and publishable project keys have separate read/write capabilities;
- passwords use Argon2id and session/API tokens are stored hashed;
- stored integration credentials use authenticated encryption;
- evidence paths are confined to the configured artifact root;
- raw worker paths are confined to `REPROIT_JOBS_ROOT`;

See [self-hosted architecture](docs/architecture/self-hosted.md) and
[data handling](https://github.com/ReproIt/reproit/blob/main/docs/data-handling.md).

## Original captures

`reproit record --upload` creates a short-lived Cloud review session. The signed-in user chooses
the destination project and report details in the browser, then the CLI streams the immutable
manifest, video, and structural evidence. Cloud verifies the declared SHA-256 hashes before the
capture becomes complete. Capture rows and blobs are tenant-scoped, project deletion removes their
object keys, and portability exports include both capture metadata and immutable file keys.

## Validation

```bash
cargo fmt --all --check
cargo test
docker compose up -d
./scripts/smoke-self-hosted.sh
```

The experimental backend-contract dogfood path is opt-in and limited to five
JSON routes. It does not claim XML, multipart, streaming, tenant, or complete
effect evidence. Its checked-in OpenAPI artifact and live disposable-Postgres
capture can be verified with:

```bash
cargo run -- backend-contract
./validation/backend-contract-live.sh
```

Only requests carrying `x-reproit-trace` are captured when
`REPROIT_EXPERIMENTAL_BACKEND_CONTRACTS=1`; ordinary server behavior is inert.

## License

Copyright 2026 Repro It, Inc. Licensed under the
[Elastic License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution details.
