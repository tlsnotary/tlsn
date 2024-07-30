FROM rust AS builder
WORKDIR /usr/src/tlsn
COPY . .

ARG BENCH_TYPE=native

RUN \
  if [ "$BENCH_TYPE" = "browser" ]; then \
    # ring's build script needs clang.
    apt update && apt install -y clang; \
    rustup component add rust-src --toolchain nightly; \
    rustup install nightly; \
    cargo install wasm-pack; \
    cd crates/benches/browser/wasm; \
    rustup run nightly wasm-pack build --release --target web; \
    cd ../../binary; \
    cargo build --release --features browser-bench; \
  else \
    cd crates/benches/binary; \
    cargo build --release; \
  fi

FROM ubuntu:latest

ARG BENCH_TYPE=native

RUN apt update && apt -y upgrade && apt install -y --no-install-recommends \
  iproute2 \
  sudo

RUN \
  if [ "$BENCH_TYPE" = "browser" ]; then \
    apt -y install wget ca-certificates gnupg; \
    wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -; \
    echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list; \
    apt update; \
    apt -y install google-chrome-stable; \
  fi

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder ["/usr/src/tlsn/target/release/bench", "/usr/src/tlsn/target/release/prover", "/usr/src/tlsn/target/release/verifier", "/usr/src/tlsn/target/release/plot", "/usr/local/bin/"]

ENV PROVER_PATH="/usr/local/bin/prover"
ENV VERIFIER_PATH="/usr/local/bin/verifier"

VOLUME [ "/benches" ]
WORKDIR "/benches"
CMD ["/bin/bash", "-c", "bench && plot /benches/metrics.csv && cat /benches/metrics.csv"]
