FROM docker.io/library/rust:1.92.0-bookworm AS planner

ENV CARGO_HOME=/app/.cargo
ENV CARGO_TARGET_DIR=/app/target
ENV PATH="/app/.cargo/bin:${PATH}"
WORKDIR /app
RUN mkdir -p /app/.cargo /app/target
RUN cargo install cargo-chef --locked
COPY . .
RUN /bin/bash -c 'printf "%s\n" \
  "[workspace]" \
  "members = [" \
  "  \"crates/zann-core\"," \
  "  \"crates/zann-db\"," \
  "  \"crates/zann-server\"," \
  "]" \
  "resolver = \"2\"" \
  > Cargo.toml'
RUN cargo chef prepare --recipe-path recipe.json --bin zann-server

FROM docker.io/library/rust:1.92.0-bookworm AS cacher

ENV CARGO_HOME=/app/.cargo
ENV CARGO_TARGET_DIR=/app/target
ENV PATH="/app/.cargo/bin:${PATH}"
WORKDIR /app
RUN mkdir -p /app/.cargo /app/target
RUN cargo install cargo-chef --locked
COPY --from=planner /app/recipe.json recipe.json
RUN /bin/bash -c 'set -o pipefail; cargo chef cook --release --recipe-path recipe.json --bin zann-server 2>&1 | grep -vE "unused manifest key:|is set on .*deprecated"; status=${PIPESTATUS[0]}; if [ "$status" -ne 0 ]; then exit "$status"; fi'

FROM docker.io/library/rust:1.92.0-bookworm AS builder

ARG GIT_COMMIT
ENV GIT_COMMIT=${GIT_COMMIT}

ENV CARGO_HOME=/app/.cargo
ENV CARGO_TARGET_DIR=/app/target
ENV PATH="/app/.cargo/bin:${PATH}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app/.cargo /app/target
COPY . .
RUN /bin/bash -c 'printf "%s\n" \
  "[workspace]" \
  "members = [" \
  "  \"crates/zann-core\"," \
  "  \"crates/zann-db\"," \
  "  \"crates/zann-server\"," \
  "]" \
  "resolver = \"2\"" \
  > Cargo.toml'
COPY --from=cacher /app/target /app/target
COPY --from=cacher /app/.cargo /app/.cargo
RUN cargo build -p zann-server --release

FROM docker.io/library/rust:1.92.0-bookworm AS fs
RUN mkdir -p /data /config \
    && chown -R 65532:65532 /data /config

FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app
COPY --from=builder /app/target/release/zann-server /app/zann-server
COPY --from=fs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=fs --chown=65532:65532 /data /data
COPY --from=fs --chown=65532:65532 /config /config

EXPOSE 8080
VOLUME ["/data", "/config"]
ENV RUST_LOG=info

USER nonroot:nonroot
ENTRYPOINT ["/app/zann-server"]
