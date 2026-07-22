# Backup and restore

A recoverable installation needs one consistent PostgreSQL dump, the matching
evidence objects, configuration, and the exact image digest. Store backups in a
separate failure domain and encrypt them with an operator-owned key.

## Backup

1. Record the application image digest and configuration with secrets redacted.
2. Pause ingest or place the service in an operator-controlled maintenance
   window so database rows and object keys do not change during the snapshot.
3. Create a custom-format dump:

```sh
pg_dump --format=custom --no-owner --file reproit.dump "$DATABASE_URL"
pg_restore --list reproit.dump > reproit.dump.list
sha256sum reproit.dump reproit.dump.list > SHA256SUMS
```

4. Snapshot the entire configured artifact directory or S3-compatible bucket.
   Preserve object keys and checksums. Do not use a lifecycle-filtered copy.
5. Resume ingest only after both snapshots and their checksums are durable.

## Restore drill

Restore into a new, isolated database and artifact namespace. Never test a
restore over production.

```sh
createdb reproit_restore_test
pg_restore --exit-on-error --no-owner \
  --dbname postgres:///reproit_restore_test reproit.dump
```

Restore evidence to a new directory or bucket, start the exact recorded image
with isolated loopback bindings, then run:

```sh
./scripts/smoke-self-hosted.sh
```

Verify authentication, one known bucket, its replay package, and at least one
evidence object. Record restore duration and the newest recovered event. Delete
the isolated drill environment after the result is recorded.

Run a restore drill at least quarterly and before a risky schema upgrade. Set
retention and recovery objectives based on your ingest rate and business needs.
