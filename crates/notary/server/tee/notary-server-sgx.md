To run the TLSNotary notary server in secure Intel SGX hardware,  do ...

## Make sure ... is installed

```
wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null

# Add the following repository to your sources:
echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list


sudo apt-get update
sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql -y
```

[More info](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)

## Verify the signature

docker run --rm -v "$(pwd):/work" -w /work gramineproject/gramine:latest "gramine-sgx-sigstruct-view notary-server.sig"


## To run the notary 

```
docker run -it --device /dev/sgx_enclave --device /dev/sgx_provision \
  --volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
  -p 7047:7047 --rm -v "$(pwd):/work" -w /work gramineproject/gramine:latest \
  "bash -c \"mkdir -p /ephemeral && chmod u+x notary-server && gramine-sgx notary-server\""
```