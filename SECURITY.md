# Security policy

The latest 1.x release receives security fixes. Report vulnerabilities through
GitHub's private vulnerability reporting for `ReproIt/reproit-cloud`, not a
public issue. Include the affected version, deployment shape, reproduction, and
impact without customer credentials or evidence.

Before exposing an installation, remove `REPROIT_DEV_OPEN`, use TLS, set unique
random secrets, configure durable PostgreSQL and object storage, restrict
network access, and establish tested backups. See
[backup and restore](docs/operations/backup-restore.md).
