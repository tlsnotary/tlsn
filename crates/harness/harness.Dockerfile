FROM rust AS builder
WORKDIR /usr/src/tlsn

ARG DEBUG=0

RUN \
    rustup update; \
    apt update && apt install -y clang; \
    rustup install nightly; \
    rustup component add rust-src --toolchain nightly; \
    cargo install --git https://github.com/rustwasm/wasm-pack.git --rev 32e52ca;
COPY . .
RUN \
    cd crates/harness; \
    # Pass `--build-arg DEBUG=1` to `docker build` if you need to debug the harness.
    if [ "$DEBUG" = "1" ]; then \
      ./build.sh debug; \
    else \
      ./build.sh; \
    fi

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