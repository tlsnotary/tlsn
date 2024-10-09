#/bin/sh
if [ -z "$1" ]
  then
     run='gramine-direct  notary-server &'

   else
      run='gramine-sgx  notary-server &'
fi

curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"
apt install libssl-dev
gramine-sgx-gen-private-key
SGX=1 make
gramine-sgx-sign -m notary-server.manifest -o notary-server.sgx
mr_enclave=$(gramine-sgx-sigstruct-view --verbose --output-format=json notary-server.sig |jq .mr_enclave)
echo "mrenclave=$mr_enclave" >> "$GITHUB_OUTPUT"
echo "#### sgx mrenclave" | tee >> $GITHUB_STEP_SUMMARY
echo "\`\`\`${mr_enclave}\`\`\`" | tee >> $GITHUB_STEP_SUMMARY
mkdir config && cp config.yaml config && mkdir /tee && cp -R ../tee/* /tee/ && cd /tee &&
eval "$run"
sleep 5
quote=$(curl 127.0.0.1:7047/info | jq .quote.rawQuote)
echo $quote
echo "quote=$quote" >> $GITHUB_OUTPUT
echo "#### 🔒 signed quote ${quote}" | tee >> $GITHUB_STEP_SUMMARY
echo "${quote}" | tee >> $GITHUB_STEP_SUMMARY
