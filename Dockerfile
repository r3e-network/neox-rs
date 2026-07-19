# syntax=docker.io/docker/dockerfile:1.7-labs

FROM lukemathwalker/cargo-chef:latest-rust-1.95-trixie AS chef
WORKDIR /app

# Install system dependencies
COPY .github/scripts/install_llvm_ubuntu.sh /tmp/install_llvm.sh
RUN /tmp/install_llvm.sh && rm /tmp/install_llvm.sh && \
    apt-get install -y --no-install-recommends libclang-dev m4 pkg-config

# Builds a cargo-chef plan
FROM chef AS planner
COPY --exclude=.git --exclude=dist . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Binary and package to build. Defaults preserve the upstream Reth image.
ARG BINARY=reth
ARG MANIFEST_PATH=bin/reth

# Build profile, maxperf by default
ARG BUILD_PROFILE=maxperf
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS="$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Builds dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build application
# Platform-specific RUSTFLAGS: amd64 uses x86-64-v3 (Haswell+) with pclmulqdq for rocksdb
#
# TARGETPLATFORM is set by BuildKit: https://docs.docker.com/reference/dockerfile#automatic-platform-args-in-the-global-scope
ARG TARGETPLATFORM
COPY --exclude=dist . .
RUN if [ -n "$RUSTFLAGS" ]; then \
        export RUSTFLAGS="$RUSTFLAGS"; \
    elif [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
        export RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq"; \
    fi && \
    cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked \
        --bin "$BINARY" --manifest-path "$MANIFEST_PATH/Cargo.toml"

# ARG is not resolved in COPY, so copy the selected binary to a stable path.
RUN cp "/app/target/$BUILD_PROFILE/$BINARY" /app/node-binary

# Use Ubuntu as the release image
FROM ubuntu:24.04 AS runtime
WORKDIR /app

ARG BINARY=reth
ARG SOURCE_URL=https://github.com/paradigmxyz/reth

LABEL org.opencontainers.image.source=$SOURCE_URL
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Copy the selected node binary and retain a stable entrypoint across image variants.
COPY --from=builder /app/node-binary /usr/local/bin/node-binary
RUN mv /usr/local/bin/node-binary "/usr/local/bin/$BINARY" && \
    ln -s "/usr/local/bin/$BINARY" /usr/local/bin/reth-binary && \
    chmod +x "/usr/local/bin/$BINARY"

# Copy licenses
COPY LICENSE-* ./
COPY LICENSES ./LICENSES
COPY README.md ./README.md

EXPOSE 30303 30303/udp 9001 8545 8546
ENTRYPOINT ["/usr/local/bin/reth-binary"]
