#!/bin/bash

set -euo pipefail

echo "[*] Generating SGX signing key..."
gramine-sgx-gen-private-key

if [ ! -f notary-server ]; then
    echo "[!] notary-server binary not found. Please copy it from ci, or build it first."
    echo "Note that notary-server must be built for linux/amd64 with tee_quote feature enabled"
    exit 1
fi

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
    README.md
