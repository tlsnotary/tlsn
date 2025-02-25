#/bin/sh
# this is to be ran in a docker container via an github action that has gramine set-up already e.g.,
# notaryserverbuilds.azurecr.io/builder/gramine
# with sgx hardware:
# ./gramine.sh sgx
#
# without:
# ./gramine.sh
##

set -e

if [ -z "$1" ]; then
  run='gramine-direct  notary-server &'

else
  run='gramine-sgx  notary-server &'
fi

curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"
apt install libssl-dev

echo "gramine-sgx-gen-private-key"
gramine-sgx-gen-private-key
ls -als
echo "make"

cargo build --bin notary-server --release --features tee_quote
cp ../../../../target/release/notary-server . &&
  gramine-manifest -Dlog_level=info \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dself_exe=notary-server \
    notary-server.manifest.template \
    notary-server.manifest
gramine-sgx-sign -m notary-server.manifest -o notary-server.sgx

mr_enclave=$(gramine-sgx-sigstruct-view --verbose --output-format=json notary-server.sig | jq .mr_enclave)
echo "mrenclave=$mr_enclave" >>"$GITHUB_OUTPUT"
echo "#### sgx mrenclave" | tee >>$GITHUB_STEP_SUMMARY
echo "\`\`\`${mr_enclave}\`\`\`" | tee >>$GITHUB_STEP_SUMMARY
eval "$run"
sleep 5

if [ "$1" ]; then
  curl 127.0.0.1:7047/info
else
  quote=$(curl 127.0.0.1:7047/info | jq .quote.rawQuote)
  echo $quote
  echo "quote=$quote" >>$GITHUB_OUTPUT
  echo "#### 🔒 signed quote ${quote}" | tee >>$GITHUB_STEP_SUMMARY
  echo "${quote}" | tee >>$GITHUB_STEP_SUMMARY
fi
