# reproit-cloud control-plane image. Multi-stage: build the crate, ship a slim
# runtime with just the binary. The dashboard HTML in static/ is include_str!'d
# at COMPILE time, so it must be present in the build stage (baked into the
# binary), not the runtime stage.
#
# This image is the CONTROL PLANE only (axum API + dashboard). Workers are a
# SEPARATE pull-based pool that dial OUT to this app and run the public `reproit`
# binary; they are not built here (see README "Workers"). With --workers 0 (the
# production default) the control plane needs no engine binary at all.
#
# Pin to bookworm so the build-stage glibc matches the bookworm-slim runtime.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY experimental/reproit-backend ./experimental/reproit-backend
COPY contracts ./contracts
COPY src ./src
COPY static ./static
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
# Build with optional S3-compatible artifact storage. Selection is at runtime:
# R2_* present selects object storage, otherwise local filesystem storage under
# REPROIT_ARTIFACT_DIR. pkg-config is
# installed above; rust-s3 uses rustls (tokio-rustls-tls), so no OpenSSL system
# dependency is needed.
ARG CARGO_FEATURES="r2"
RUN cargo build --release --features "$CARGO_FEATURES"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/reproit-cloud /usr/local/bin/reproit-cloud
ENV RUST_LOG=info
EXPOSE 8080
# DATABASE_URL and REPROIT_API_KEY are provided at runtime.
ENTRYPOINT ["reproit-cloud", "--port", "8080"]
