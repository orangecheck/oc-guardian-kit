# syntax=docker/dockerfile:1
#
# oc-guardian — the Fedimint guardian image OrangeCheck deploys to Fly.
#
# `provisionHosted` (oc-me-web) creates a Fly machine from this image and
# injects OC_OPERATOR_ID / OC_OPERATOR_PUBKEY_HEX / OC_FEDERATION_SLUG /
# OC_ATTESTATION_POST_URL, exposing ports 9000 (P2P) + 9001 (API). The
# entrypoint (`oc-guardian fedimintd run`) maps that env to FM_* and
# supervises a bundled, pinned fedimintd; it emits operator-signed
# attestations (no TEE).
#
# fedimintd is fetched + SHA-256-verified at build time. The release
# workflow MUST pass the verified upstream hash:
#   docker build \
#     --build-arg FEDIMINTD_VERSION=0.7.2 \
#     --build-arg FEDIMINTD_SHA256=<verified-upstream-sha256> .
# Without FEDIMINTD_SHA256 the build fails — we never ship an unverified
# consensus binary.

# ── Stage 1 · build the kit (oc-guardian) ────────────────────────────
FROM rust:1.85-slim-bookworm AS kit-build
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin oc-guardian

# ── Stage 2 · fetch + verify fedimintd ───────────────────────────────
FROM debian:bookworm-slim AS fedimintd-fetch
ARG FEDIMINTD_VERSION=0.7.2
ARG FEDIMINTD_URL=https://github.com/fedimint/fedimint/releases/download/v${FEDIMINTD_VERSION}/fedimintd-x86_64-unknown-linux-gnu
ARG FEDIMINTD_SHA256=""
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN test -n "$FEDIMINTD_SHA256" \
    || (echo "ERROR: build-arg FEDIMINTD_SHA256 is required (verified upstream hash)"; exit 1)
RUN curl -fsSL "$FEDIMINTD_URL" -o /fedimintd \
    && echo "${FEDIMINTD_SHA256}  /fedimintd" | sha256sum -c - \
    && chmod 0755 /fedimintd

# ── Stage 3 · runtime ────────────────────────────────────────────────
FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="oc-guardian" \
      org.opencontainers.image.source="https://github.com/orangecheck/oc-guardian-kit" \
      org.opencontainers.image.description="OrangeCheck Fedimint guardian (kit + bundled fedimintd)"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 guardian \
    && mkdir -p /data/fedimintd && chown -R guardian:guardian /data
COPY --from=kit-build /build/target/release/oc-guardian /usr/local/bin/oc-guardian
COPY --from=fedimintd-fetch /fedimintd /usr/local/bin/fedimintd
USER guardian
ENV FM_DATA_DIR=/data/fedimintd
# 9000 P2P · 9001 consensus API · (8175 setup/DKG bind is machine-private)
EXPOSE 9000 9001
# The guardian's main process: env → FM_*, supervise fedimintd, attest.
ENTRYPOINT ["oc-guardian", "fedimintd", "run"]
