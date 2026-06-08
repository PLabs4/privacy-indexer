# syntax=docker/dockerfile:1
# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder
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
FROM debian:bookworm-slim AS runtime
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
