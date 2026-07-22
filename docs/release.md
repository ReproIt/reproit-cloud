# Self-hosted release contract

An immutable `v1.x.y` Git tag identifies the supported source tree and the
checksummed source archive attached to its GitHub release. The archive is the
input operators use to build the pinned Dockerfile and Compose deployment.

Every release candidate must pass, for the exact commit:

- formatting, strict Clippy, unit and PostgreSQL-backed integration tests;
- the full `r2` feature build and dependency audit;
- the local-filesystem Compose smoke;
- the S3-compatible MinIO Compose smoke;
- an archive extraction check and `reproit-cloud --version` check.

Validate without publishing:

```sh
gh workflow run release.yml -f version=1.0.0 -f publish=false
```

Before publication, replace `Unreleased` in `CHANGELOG.md` with the UTC release
date and obtain successful CI for that exact commit. Publishing creates the
immutable GitHub release and tag. It does not deploy the separately operated
hosted service.
