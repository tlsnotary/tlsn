# TLSNotary Notary Server for Intel SGX

This package contains the **SGX-enabled version of the TLSNotary Notary Server**, built with **Gramine** to run securely on Intel SGX hardware. Follow the instructions below to install dependencies, verify the integrity of the enclave, and launch the server.

## Install Intel SGX Drivers & Runtime Dependencies

Ensure your system has the required Intel SGX components installed.

```sh
wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null

# Add the repository to your sources:
echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql -y
```

For more details, refer to the official **[Intel SGX Installation Guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf).**

## Verify the Enclave Signature (`MR_ENCLAVE`, `MR_SIGNER`)

Before running the Notary Server, verify that the provided **enclave signature (`.sig`)** matches the expected **`MR_ENCLAVE` and `MR_SIGNER`** values.

Run the following command inside a **Gramine Docker container** to inspect the enclave's signature:

```sh
docker run --rm -v "$(pwd):/work" -w /work gramineproject/gramine:latest \
  "gramine-sgx-sigstruct-view --verbose --output-format=json notary-server.sig"
```

The output should be the same as `notary-server-sigstruct.json`

## Run the Notary Server in SGX

Once verification is complete, you can start the Notary Server inside a **Gramine-protected SGX enclave**.

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
  "bash -c \"chmod u+x notary-server && gramine-sgx notary-server\""
```

Notes:
- `--device /dev/sgx_enclave --device /dev/sgx_provision` → Exposes SGX devices.
- `--volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket` → Enables access to **Intel's AESM daemon** (required for remote attestation).
- `-p 7047:7047` → Exposes the notary server on port **7047**.

## Attestation & Verification

The Notary Server runs inside an **Intel SGX enclave**, which supports **remote attestation**. When connecting to it, clients should request an **SGX quote** to verify:

- **MR_ENCLAVE** (ensures the correct enclave binary is running).
- **MR_SIGNER** (ensures the enclave was signed by the expected key).
- **Quote Freshness** (prevents replay attacks).

To retrieve the SGX attestation quote, navigate to `<your notary server>:7047/info`