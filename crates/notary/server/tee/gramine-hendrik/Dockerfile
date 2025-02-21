# tlsnotary gramine layer

FROM --platform=linux/amd64 rust:latest

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
