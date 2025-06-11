# !!! To use this file, please run docker run at the root level of this repository
FROM rust:latest AS builder
RUN apt-get update && apt-get install -y clang libclang-dev
WORKDIR /usr/src/tlsn
COPY . .
RUN cargo install --locked --path crates/notary/server

FROM ubuntu:latest
WORKDIR /root/.notary
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  pkg-config \
  libssl-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/notary-server /usr/local/bin/notary-server
# Label to link this image with the repository in Github Container Registry (https://docs.github.com/en/packages/learn-github-packages/connecting-a-repository-to-a-package#connecting-a-repository-to-a-container-image-using-the-command-line)
LABEL org.opencontainers.image.source=https://github.com/tlsnotary/tlsn
LABEL org.opencontainers.image.description="An implementation of the notary server in Rust."
ENTRYPOINT [ "notary-server" ]
