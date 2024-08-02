FROM rust AS builder
WORKDIR /usr/src/tlsn
COPY . .
RUN cd crates/benches && cargo build --release

FROM ubuntu:latest

RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  iproute2 \
  sudo \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder ["/usr/src/tlsn/target/release/bench", "/usr/src/tlsn/target/release/prover", "/usr/src/tlsn/target/release/verifier", "/usr/src/tlsn/target/release/plot", "/usr/local/bin/"]

ENV PROVER_PATH="/usr/local/bin/prover"
ENV VERIFIER_PATH="/usr/local/bin/verifier"

VOLUME [ "/benches" ]
WORKDIR "/benches"
CMD ["/bin/bash", "-c", "bench && plot /benches/metrics.csv && cat /benches/metrics.csv"]
