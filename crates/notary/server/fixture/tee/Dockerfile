#tlsnotary server for testing <> gramine sgx
### notaryserverbuilds.azurecr.io/prod/sgx-notary

FROM            notaryserverbuilds.azurecr.io/prod/gramine-deps AS teesdk

ARG		TOOLCHAIN=1.81.0
ENV		PATH=/root/.cargo/bin:/usr/local/musl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN		set -eux \
		&& curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=$TOOLCHAIN \
		&& rustup target add \
		x86_64-unknown-linux-gnu


ARG             TLSN_TAG=quote-presentation
ARG             TLSN_FT=tee_quote
RUN             git clone --depth 1 -b $TLSN_TAG https://github.com/tlsnotary/tlsn /tlsn  && \
                cargo build --release --bin notary-server --features $TLSN_FT --color always --manifest-path /tlsn/Cargo.toml
RUN             cd tlsn/crates/notary/server/fixture/tee && gramine-sgx-gen-private-key && SGX=1 make 

FROM            notaryserverbuilds.azurecr.io/builder/gramine AS teetime
COPY            --from=teesdk tlsn/crates/notary/server/fixture/tee tee
RUN		mkdir /tee/config && cp /tee/config.yaml /tee/config/
ENTRYPOINT      ["gramine-sgx", "/tee/notary-server"]
