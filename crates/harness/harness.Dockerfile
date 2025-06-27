FROM rust AS builder
WORKDIR /usr/src/tlsn

RUN \
    rustup update; \
    apt update && apt install -y clang; \
    rustup install nightly; \
    rustup component add rust-src --toolchain nightly; \
    cargo install wasm-pack;
COPY . .
RUN \
    cd crates/harness; \
    ./build.sh;

FROM debian:latest


RUN apt update && apt upgrade -y && apt install -y --no-install-recommends \
  chromium \
  iproute2 \
  sudo \
  procps \
  iptables; \
  apt clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/tlsn/crates/harness/bin/ /usr/local/bin/
COPY --from=builder /usr/src/tlsn/crates/harness/static /static

# RUN /usr/local/bin/runner setup

VOLUME [ "/benches" ]
WORKDIR "/benches"
# CMD ["/usr/local/bin/runner", "test"]