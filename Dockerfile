# syntax=docker/dockerfile:1
# ── Build stage ───────────────────────────────────────────────────────────────
# Multi-arch OCI index digests verified from Docker Hub on 2026-07-30.
FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder
WORKDIR /app

# Cache dependencies first: copy manifests, build a stub, then the real source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY . .
# Touch so cargo rebuilds with the real main.rs (the stub above shares its path).
RUN touch src/main.rs && cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user; /data holds the persisted state + pools registry.
RUN useradd --system --create-home --uid 10001 appuser \
    && mkdir -p /data && chown appuser:appuser /data
WORKDIR /data
USER appuser

COPY --from=builder /app/target/release/privacy-indexer /usr/local/bin/privacy-indexer

EXPOSE 8787
# All settings come from env (see .env.example) so no CLI flags are needed here.
ENTRYPOINT ["privacy-indexer"]
