FROM rust AS builder
WORKDIR /usr/src/tlsn
COPY . .

ARG BENCH_TYPE=native

RUN \
  rustup update; \
  if [ "$BENCH_TYPE" = "browser" ]; then \
    # ring's build script needs clang.
    apt update && apt install -y clang; \
    rustup install nightly; \
    rustup component add rust-src --toolchain nightly; \
    cargo install wasm-pack; \
    cd crates/benches/browser/wasm; \
    wasm-pack build --release  --locked --target web; \
    cd ../../binary; \
    cargo build --release --features browser-bench --locked; \
  else \
    cd crates/benches/binary; \
    cargo build --release --locked; \
  fi

FROM debian:latest

ARG BENCH_TYPE=native

RUN apt update && apt upgrade -y && apt install -y --no-install-recommends \
  iproute2 \
  sudo

RUN \
  if [ "$BENCH_TYPE" = "browser" ]; then \
    # Using Chromium since Chrome for Linux is not available on ARM.
    apt install -y chromium; \
  fi

RUN apt clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder \
  ["/usr/src/tlsn/target/release/bench", \
  "/usr/src/tlsn/target/release/prover", \
  "/usr/src/tlsn/target/release/prover-memory", \
  "/usr/src/tlsn/target/release/verifier", \
  "/usr/src/tlsn/target/release/verifier-memory", \
  "/usr/src/tlsn/target/release/plot", \
  "/usr/local/bin/"]

ENV PROVER_PATH="/usr/local/bin/prover"
ENV VERIFIER_PATH="/usr/local/bin/verifier"
ENV PROVER_MEMORY_PATH="/usr/local/bin/prover-memory"
ENV VERIFIER_MEMORY_PATH="/usr/local/bin/verifier-memory"

VOLUME [ "/benches" ]
WORKDIR "/benches"
CMD ["/bin/bash", "-c", "bench && bench --memory-profiling && plot /benches/metrics.csv && cat /benches/metrics.csv"]
