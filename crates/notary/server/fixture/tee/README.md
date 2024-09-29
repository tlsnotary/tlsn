#gramine with intel SGX
SGX=1 make
SGX=1 make start-gramine-server

#gramine emulating SGX
make
make start-gramine-server

#generate measurement without SGX hardware
make
gramine-sgx-sigstruct-view --verbose --output-format=toml notary-server.sig