# syntax=docker/dockerfile:1

FROM rust:1.97 AS build
WORKDIR /src
# Dependency layer: build with stub sources first so cargo caches the deps.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
 && printf 'fn main() {}' > src/main.rs \
 && printf 'fn main() {}' > src/bin/e2e_peer.rs \
 && cargo build --release --bin matrix2078
COPY src ./src
RUN touch src/main.rs src/bin/e2e_peer.rs \
 && cargo build --release --bin matrix2078

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/matrix2078 /usr/local/bin/matrix2078
# /data - persistent sessions, matrix-sdk state, media cache: mount it
VOLUME ["/data"]
ENV MATRIX2078_STATE_DIR=/data
EXPOSE 2078 2079
ENTRYPOINT ["/usr/local/bin/matrix2078"]
