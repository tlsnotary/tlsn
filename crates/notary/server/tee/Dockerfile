#tlsnotary server for testing <> gramine sgx (gramine1.7, g++13, libiomp off :()
### notaryserverbuilds.azurecr.io/prod/notary-sgx

FROM            notaryserverbuilds.azurecr.io/prod/gramine AS teesdk

ARG             TOOLCHAIN=1.81.0
ENV             PATH=/root/.cargo/bin:/usr/local/musl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN             set -eux \
                && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=$TOOLCHAIN \
                && rustup target add \
                x86_64-unknown-linux-gnu


RUN             apt update && apt install -y libssl-dev libclang-dev
ARG             TLSN_TAG=quote-presentation
ARG             TLSN_FT=tee_quote
RUN             git clone --depth 1 -b $TLSN_TAG https://github.com/tlsnotary/tlsn /tlsn  && \
                cargo build --release --bin notary-server --features $TLSN_FT --color always --manifest-path /tlsn/Cargo.toml
RUN             cd tlsn/crates/notary/server/tee && gramine-sgx-gen-private-key && SGX=1 make

FROM            notaryserverbuilds.azurecr.io/prod/gramine AS teetime
WORKDIR /tee
COPY            --from=teesdk tlsn/crates/notary/server/tee .
ENTRYPOINT      ["gramine-sgx", "notary-server"]
