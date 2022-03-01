# pop-mpc-circuits
This crate assists with converting circuits from Bristol-fashion Format to Protobuf models.

## Usage
Simply run cargo build to convert all circuits present in the `circuits/` directory.

```bash
cargo build
```

The protobuf models will be saved into the build directory, e.g. `target/debug/build/pop-mpc-circuits-*/out/`