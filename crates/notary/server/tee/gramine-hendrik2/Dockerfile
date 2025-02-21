FROM --platform=linux/amd64 rust:latest AS builder

RUN apt-get update && apt-get install -y \
    git \
    libssl-dev \
    build-essential \
    pkg-config \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Clone the repository
RUN git clone --branch dev https://github.com/tlsnotary/tlsn.git /tlsn

# Set the working directory
WORKDIR /tlsn

# Build notary server with cargo
RUN cargo build --bin notary-server --release --features tee_quote

# Copy the built notary server binary to the next stage

FROM --platform=linux/amd64 gramineproject/gramine

WORKDIR /tlsn
COPY --from=builder /tlsn/target/release/notary-server /tlsn
COPY notary-server.manifest.template /tlsn
COPY config /tlsn/config
ENV DEBIAN_FRONTEND=noninteractive


RUN gramine-sgx-gen-private-key

RUN gramine-manifest \
    -Dlog_level=debug \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dself_exe=/tlsn/notary-server \
    notary-server.manifest.template notary-server.manifest

RUN  gramine-sgx-sign \
    --manifest notary-server.manifest \
    --output notary-server.manifest.sgx

CMD ["bash"]
