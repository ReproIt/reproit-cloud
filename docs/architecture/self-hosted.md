# Self-hosted architecture

## Boundary

One process serves one installation. Identity and routing metadata share the
operator's PostgreSQL database with the installation's tenant schema, while the
code keeps them behind separate stores to preserve least-privilege handler APIs.
Every authenticated request resolves to the fixed installation id.

There is no provider API, cross-customer lookup, subscription state, commercial
entitlement, or externally operated worker fleet in this edition.

## Data flow

1. SDKs send derived structural events through a write-only project key.
2. Ingest validates oracle identity and rejects ungrounded error events.
3. Equivalent occurrences materialize into stable buckets.
4. Local and CI runs upload confirmed evidence through secret project keys.
5. A reproduction request dispatches to the configured customer repository.
6. The customer's CI posts the verdict back to the same bucket.

## Storage

- PostgreSQL stores accounts, projects, events, buckets, run state, and audit rows.
- Evidence uses a confined local directory by default.
- An S3-compatible backend is optional for durable or replicated artifacts.
- Operators own backup, retention, encryption-at-rest, and disaster recovery.

## Workers

Workers claim shards using an operator-configured bearer token. They run the
normal Reproit CLI against applications and devices available inside the
operator's network. The server stores results but does not provision devices.

## Hosted-service separation

The hosted Reproit service is not a mode or feature flag in this repository. It
is a separate private application. Compatibility is maintained through versioned
HTTP payloads and golden fixtures, not through hosted code in this distribution.
