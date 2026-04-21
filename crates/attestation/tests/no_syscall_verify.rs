//! Tests that presentation verification works without getrandom syscalls.
//!
//! This test is run in CI with `RUSTFLAGS='--cfg
//! getrandom_backend="unsupported"'` to prove the verification path does not
//! depend on OS-level RNG.
//!
//! To regenerate the fixture:
//!     ./crates/attestation/tests/fixtures/generate_presentation_fixture.rs

use tlsn_attestation::{CryptoProvider, presentation::Presentation};

#[test]
fn test_verify_presentation_without_syscalls() {
    let bytes = include_bytes!("fixtures/presentation.bin");
    let presentation: Presentation = bincode::deserialize(bytes).unwrap();

    let provider = CryptoProvider::default();
    let output = presentation.verify(&provider).unwrap();

    assert!(output.server_name.is_some());
    assert!(output.transcript.is_some());
}
