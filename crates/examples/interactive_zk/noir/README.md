Experimenting with Noir circuit for TLSNotary commitments

The Noir version has to match the version support in Mopro's `noir_rs`:
```
noirup --version 1.0.0-beta.8
bbup -v 1.0.0-nightly.20250723
```

## Execute Circuit
```bash
nargo execute
```
Runs the circuit and generates witness data from `Prover.toml` inputs.

## Generate Proof
```bash
bb prove --bytecode_path ./target/noir.json --witness_path ./target/noir.gz -o ./target
```
Creates a zero-knowledge proof using the circuit and witness data.

## Generate Verification Key
```bash
bb write_vk -b ./target/noir.json -o ./target
```
Creates the verification key needed to verify proofs (run once per circuit).

## Verify Proof
```bash
bb verify -k ./target/vk -p ./target/proof
```
Verifies that a proof is valid using the verification key.


## Testing

```
nargo test --show-output
```

Create tests: use `generate_test_data.rs` to create extra test data



