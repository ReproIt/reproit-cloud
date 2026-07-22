# Upgrading ReproIt Cloud

1. Read [CHANGELOG.md](../CHANGELOG.md) and back up PostgreSQL and evidence.
2. Record the current image digest and application version.
3. Pull or build the new immutable version without replacing the running stack.
4. Restore the backup into a disposable environment and run
   `scripts/smoke-self-hosted.sh` against it.
5. Deploy the new version. Startup migrations are forward-only, so do not use a
   binary older than the migrated schema.
6. Run the smoke script again and verify one authenticated ingest and replay.

For rollback after a migration, restore the pre-upgrade database and evidence
snapshot together, then run the prior image digest. Never combine an older
database with newer evidence metadata or the reverse.
