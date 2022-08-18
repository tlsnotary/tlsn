# tlsn-mpc-circuits
This crate includes models for dealing with logic circuits.


## Bristol-fashion conversion
A binary is provided to convert circuits from bristol-fashion format to this crates binary format (protobuf)

Simply run the compile binary to convert all circuits present in the input directory.

```bash
cargo r --bin compile -- -i circuits/ -o out/
```