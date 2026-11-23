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
# fedimintd is installed from the upstream .deb, SHA-256-verified at build
# time against the pin below (fedimintd_0.13.0_amd64.deb, checked against
# GitHub's published digest). A build that moves FEDIMINTD_VERSION passes the
# new hash with it; with an empty hash the build fails, so we never ship an
# unverified consensus binary.

# ── Stage 1 · build the kit (oc-guardian) ────────────────────────────
FROM rust:1.85-slim-bookworm AS kit-build
WORKDIR /build
# libdbus-1-dev: the `keyring` crate (operator-key storage) links the Secret
# Service over D-Bus on Linux → libdbus-sys needs the dbus dev headers to build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev libdbus-1-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin oc-guardian

# ── Stage 2 · fetch + verify fedimintd ───────────────────────────────
FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="oc-guardian" \
      org.opencontainers.image.source="https://github.com/orangecheck/oc-guardian-kit" \
      org.opencontainers.image.description="OrangeCheck Fedimint guardian (kit + bundled fedimintd)"

# fedimintd is installed from the upstream .deb (debian-native; apt
# resolves its runtime deps + puts fedimintd on PATH). The .deb is
# SHA-256-verified before install — the build fails without the verified
# hash, so we never bundle an unverified consensus binary.
ARG FEDIMINTD_VERSION=0.13.0
ARG FEDIMINTD_DEB_URL=https://github.com/fedimint/fedimint/releases/download/v${FEDIMINTD_VERSION}/fedimintd_${FEDIMINTD_VERSION}_amd64.deb
ARG FEDIMINTD_SHA256=f807351adf704548a147b9ecfd09c45a1bac773cf830db57a84a01e8a0450c69
# Runtime shared libs the oc-guardian binary links: libdbus-1-3 (the `keyring`
# crate / Secret Service) + libssl3. Without libdbus-1-3 the binary can't load
# its .so at startup → exit 127. (apt also resolves fedimintd's own deps.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates libdbus-1-3 libssl3 \
    && test -n "$FEDIMINTD_SHA256" \
       || (echo "ERROR: build-arg FEDIMINTD_SHA256 is required (verified upstream .deb hash)"; exit 1) \
    && curl -fsSL "$FEDIMINTD_DEB_URL" -o /tmp/fedimintd.deb \
    && echo "${FEDIMINTD_SHA256}  /tmp/fedimintd.deb" | sha256sum -c - \
    && apt-get install -y --no-install-recommends /tmp/fedimintd.deb \
    && rm -f /tmp/fedimintd.deb \
    && rm -rf /var/lib/apt/lists/* \
    && command -v fedimintd >/dev/null || (echo "ERROR: fedimintd not on PATH after install"; exit 1) \
    && useradd -m -u 10001 guardian \
    && mkdir -p /data/fedimintd && chown -R guardian:guardian /data
COPY --from=kit-build /build/target/release/oc-guardian /usr/local/bin/oc-guardian
# Smoke-check the binary actually LOADS (catches a missing runtime .so at build
# time, so we never publish an image that exit-127s on boot like v0.2.0's first cut).
RUN oc-guardian --help >/dev/null 2>&1 \
    || (echo "ERROR: oc-guardian failed to execute — missing runtime shared library?"; exit 1)
USER guardian
ENV FM_DATA_DIR=/data/fedimintd
# 9000 P2P · 9001 consensus API · (8175 setup/DKG bind is machine-private)
EXPOSE 9000 9001
# The guardian's main process: env → FM_*, supervise fedimintd, attest.
ENTRYPOINT ["oc-guardian", "fedimintd", "run"]
