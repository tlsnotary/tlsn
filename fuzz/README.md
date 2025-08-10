# TLSN Continuous Fuzzing
This directory contains the fuzzing harnesses designed to continuously test the robustness of core components against malformed or unexpected inputs using `cargo-fuzz / libFuzzer`.

---

### How to run the fuzzers
```bash
~/tlsn/fuzz$ cargo fuzz run <target-name>
~/tlsn/fuzz$ cargo fuzz run <target-name> -- --corpus <corpus-dir>
```

### Running existing tests:
```bash
cargo fuzz run compressed_partial_transcript
cargo fuzz run http_transcript_parse_with_secrets -- --corpus ./corpus/http_transcript_parse_with_secrets/
```

## Adding a new fuzz target
- Create the new fuzz harness file in `./src/my_new_fuzz_target.rs`
  - Use the ```#![no_main]```  attribute and `fuzz_target!` macro
- Add a `[[bin]]` entry in `fuzz/Cargo.toml` like this:
```toml
[[bin]]
name = "my_new_fuzz_target"
path = "src/my_new_fuzz_target.rs"
```




