FROM gramineproject/gramine:latest
WORKDIR /work

# Copies `notary-server-sgx.zip` from the CI build or created locally via `run-gramine-local.sh`.
COPY ./notary-server-sgx /work
RUN chmod +x /work/notary-server

LABEL org.opencontainers.image.source=https://github.com/tlsnotary/tlsn
LABEL org.opencontainers.image.description="TLSNotary notary server in SGX/Gramine."

ENTRYPOINT ["gramine-sgx", "notary-server"]
