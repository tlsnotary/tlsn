#!/bin/bash

# This script is used to build and run the Gramine manifest for the Notary server in a local development environment.
# It is intended to be run inside a Docker container with the Gramine SDK installed.

# The Dockerfile used to build the container is located in the same directory as this script.
# The Dockerfile is named "Dockerfile.gramine-local" and is used to create a container with the necessary dependencies
# and tools to build and run the Gramine manifest.

# To build the Docker image, run the following command:
# ```
# docker build -f Dockerfile.gramine-local -t gramine-local .
# ```

# ⚠️ This script assumes that the notary-server binary is already built (for linux/amd64) and available in the current directory.

# To run the script inside the Docker container, use the following command:
# ```
# docker run --rm -it --platform=linux/amd64 -v "${PWD}:/app" -w /app/ gramine-local "bash -c ./run-gramine-local.sh"
# ```

set -euo pipefail

echo "[*] Generating SGX signing key..."
gramine-sgx-gen-private-key

chmod +x notary-server

echo "[*] Creating Gramine manifest..."
gramine-manifest \
    -Dlog_level=debug \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dself_exe=notary-server \
    notary-server.manifest.template \
    notary-server.manifest

echo "[*] Signing manifest..."
gramine-sgx-sign \
    --manifest notary-server.manifest \
    --output notary-server.manifest.sgx

echo "[*] Viewing SIGSTRUCT..."
gramine-sgx-sigstruct-view --verbose --output-format=json notary-server.sig >notary-server-sigstruct.json

cat notary-server-sigstruct.json | jq .

mr_enclave=$(jq -r ".mr_enclave" notary-server-sigstruct.json)
mr_signer=$(jq -r ".mr_signer" notary-server-sigstruct.json)

echo "=============================="
echo "MRENCLAVE: $mr_enclave"
echo "MRSIGNER:  $mr_signer"
echo "=============================="

zip -r notary-server-sgx.zip \
    notary-server \
    notary-server-sigstruct.json \
    notary-server.sig \
    notary-server.manifest \
    notary-server.manifest.sgx \
    config \
    notary-server-sgx.md
