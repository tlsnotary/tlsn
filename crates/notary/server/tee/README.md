This folder contains the necessary files to build a Docker image for running the Notary Server on Intel SGX-enabled hardware. 

## Compile the notary server for Intel SGX

We are using [Gramine](https://github.com/gramineproject/gramine) to run the notary server on Intel SGX. Gramine allows to run the notary server in an isolated environment with minimal host requirements.

The isolated environment is defined via the manifest template (`notary-server.manifest.template`).

The notary server for SGX is compiled with an extra Rust feature flag `tee_quote`. This makes the notary server use an ephemeral private notary key for signing attestations (`private_key_pem_path: "/ephemeral/notary.key"`) and also adds the SGX *quote* to the notary server's `/info` end point.

### CI 

The container is built as part of the CI pipeline. For details on the build process, refer to the [CI workflow configuration](../../../../.github/workflows/ci.yml).

CI builds a zip-file `notary-server-sgx.zip` (which contains the compiled binary and the signed manifest). You can find this zip file for all releases and the `dev` builds in the build Artifacts. We also publish a docker image `notary-server-sgx` to <https://github.com/tlsnotary/tlsn/pkgs/container/tlsn%2Fnotary-server-sgx>. Check the #how for more details on running this container.

### Development

You can also build everything locally with `run-gramine-local.sh`. 

This script creates and signs the Gramine manifest for the Notary server in a local development environment. This scripts requires the Gramine SDK, so it is most convenient to run it in a Docker container with the necessary dependencies and tools.

> ⚠️ This script assumes that the `notary-server` binary is already built (for linux/amd64) and available in the current directory. Make sure it is built with the `tee_quote` feature (On Linux: `cargo build --bin notary-server --release --features tee_quote`).

#### Build the Docker Image

To build the Docker image for local development, run:
```
docker build -f gramine-local.Dockerfile -t gramine-local .
```
#### Run the Gramine Script

Once the image is built, you can run the `run-gramine-local.sh` script inside the container:
```
docker run --rm -it \
  --platform=linux/amd64 \
  -v "${PWD}:/app" \
  -w /app/ \
  gramine-local \
  "bash -c ./run-gramine-local.sh"
```

If successful, the script will generate the following files:
* `notary-server.sig`
* `notary-server-sigstruct.json`
* `notary-server.manifest`
* `notary-server.manifest.sgx`


You can verify that the provided **enclave signature (`.sig`)** matches the expected **`MR_ENCLAVE` and `MR_SIGNER`** values, by running the following command inside a **Gramine Docker container** to inspect the enclave's signature:

```sh
docker run --rm -v "$(pwd):/work" -w /work gramineproject/gramine:latest \
  "gramine-sgx-sigstruct-view --verbose --output-format=json notary-server.sig"
```

The output should be the same as `notary-server-sigstruct.json`

## How to Run TLSNotary on Intel SGX?

Before you can run the notary server on Intel SGX hardware, you need to ensure that your system has the required Intel SGX components installed:

```sh
wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null

# Add the repository to your sources:
echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql -y
```

For more details, refer to the official **[Intel SGX Installation Guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf).**

### Docker Compose

To run the notary server with Docker Compose. Create a `docker-compose.yml` file with a configuration like:
```
services:
  dev:
    container_name: dev
    image: ghcr.io/tlsnotary/tlsn/notary-server-sgx:dev
    restart: unless-stopped
    devices:
      - /dev/sgx_enclave
      - /dev/sgx_provision
    volumes:
      - /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket
    ports:
      - "7047:7047"
    entrypoint: [ "gramine-sgx", "notary-server" ]
```

To retrieve the SGX attestation quote, navigate to `<your notary server>:7047/info`:
```
curl localhost:7047/info | jq
```

### Run local build, directly with gramine

To run a local build, you can start the Notary Server inside a **Gramine-protected SGX enclave** with:

```sh
docker run --detach \
  --restart=unless-stopped \
  --device=/dev/sgx_enclave \
  --device=/dev/sgx_provision \
  --volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
  --publish=7047:7047 \
  --volume="$(pwd):/work" \
  --workdir=/work \
  gramineproject/gramine:latest \
  "gramine-sgx notary-server"
```