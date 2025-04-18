This folder contains the necessary files to build a Docker image for running the Notary Server on Intel SGX-enabled hardware.

## Compile the Notary Server for Intel SGX

We use [Gramine](https://github.com/gramineproject/gramine) to run the Notary Server on Intel SGX. Gramine allows the Notary Server to run in an isolated environment with minimal host requirements.

The isolated environment is defined via the manifest template (`notary-server.manifest.template`).

The Notary Server for SGX is compiled with the Rust feature flag `tee_quote`. This enables the server to use an ephemeral private notary key for signing attestations (`private_key_pem_path: "/ephemeral/notary.key"`) and also adds the SGX *quote* to the server's `/info` endpoint.

### CI

The [notary-server-sgx Docker container](https://github.com/tlsnotary/tlsn/pkgs/container/tlsn%2Fnotary-server-sgx) is built as part of the CI pipeline. For details on the build process, refer to the [CI workflow configuration](../../../../.github/workflows/ci.yml).

CI builds a zip file named `notary-server-sgx.zip`, which contains the compiled binary and the signed manifest. This zip file is available for all releases and `dev` builds in the build artifacts. We also publish a Docker image `notary-server-sgx` at <https://github.com/tlsnotary/tlsn/pkgs/container/tlsn%2Fnotary-server-sgx>. Check the section below for details on running this container.

### Development

You can also build everything locally using the `run-gramine-local.sh` script.

This script creates and signs the Gramine manifest for the Notary Server in a local development environment. It requires the Gramine SDK, so the most convenient way to use it is within a Docker container that includes the necessary dependencies and tools.

> ⚠️ This script assumes that the `notary-server` binary is already built (for `linux/amd64`) and available in the current directory. Make sure it is built with the `tee_quote` feature:  
> `cargo build --bin notary-server --release --features tee_quote`

#### Build the Docker Image

To build the Docker image for local development, run:
```sh
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


You can verify that the provided **enclave signature (`notary-server.sig`)** matches the expected **`MR_ENCLAVE` and `MR_SIGNER`** values in `notary-server-sigstruct.json`, by running the following command inside a **Gramine Docker container** to inspect the enclave's signature:

```sh
docker run --rm -v "$(pwd):/work" -w /work gramineproject/gramine:latest \
  "gramine-sgx-sigstruct-view --verbose --output-format=json notary-server.sig"
```

The output should be the same as `notary-server-sigstruct.json`

## How to Run TLSNotary on Intel SGX?

Before running the Notary Server on Intel SGX hardware, ensure your system has the required Intel SGX components installed:
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

To run the Notary Server using Docker Compose, create a docker-compose.yml file like the following:
```yaml
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

To retrieve the SGX attestation quote, query the `/info` endpoint:
```sh
curl localhost:7047/info | jq
```

### Run local build directly with Gramine

To run a locally built Notary Server inside a Gramine-protected SGX enclave, execute:
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