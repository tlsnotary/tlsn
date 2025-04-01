FROM gramineproject/gramine:latest
WORKDIR /work

# This copies the contents of `notary-server-sgx.zip` from the ci build step into the container.
# This zip file can also be created locally with `run-gramine-local.sh` in the `crates/notary/server/tee` directory.
# This zip file contains the notary-server binary and the Gramine manifest and signatures.
COPY ./notary-server-sgx /work
RUN chmod +x /work/notary-server

LABEL org.opencontainers.image.source=https://github.com/tlsnotary/tlsn
LABEL org.opencontainers.image.description="TLSNotary notary server in SGX/Gramine."

ENTRYPOINT ["gramine-sgx", "notary-server"]
