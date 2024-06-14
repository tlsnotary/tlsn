//! HMAC-SHA256 circuits.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod hmac_sha256;
mod prf;
mod session_keys;
mod verify_data;

pub use hmac_sha256::{
    hmac_sha256_finalize, hmac_sha256_finalize_trace, hmac_sha256_partial,
    hmac_sha256_partial_trace,
};

pub use prf::{prf, prf_trace};
pub use session_keys::{session_keys, session_keys_trace};
pub use verify_data::{verify_data, verify_data_trace};

use mpz_circuits::{Circuit, CircuitBuilder, Tracer};
use std::sync::Arc;

/// Builds session key derivation circuit.
#[tracing::instrument(level = "trace")]
pub fn build_session_keys() -> Arc<Circuit> {
    let builder = CircuitBuilder::new();
    let pms = builder.add_array_input::<u8, 32>();
    let client_random = builder.add_array_input::<u8, 32>();
    let server_random = builder.add_array_input::<u8, 32>();
    let (cwk, swk, civ, siv, outer_state, inner_state) =
        session_keys_trace(builder.state(), pms, client_random, server_random);
    builder.add_output(cwk);
    builder.add_output(swk);
    builder.add_output(civ);
    builder.add_output(siv);
    builder.add_output(outer_state);
    builder.add_output(inner_state);
    Arc::new(builder.build().expect("session keys should build"))
}

/// Builds a verify data circuit.
#[tracing::instrument(level = "trace")]
pub fn build_verify_data(label: &[u8]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();
    let outer_state = builder.add_array_input::<u32, 8>();
    let inner_state = builder.add_array_input::<u32, 8>();
    let handshake_hash = builder.add_array_input::<u8, 32>();
    let vd = verify_data_trace(
        builder.state(),
        outer_state,
        inner_state,
        &label
            .iter()
            .map(|v| Tracer::new(builder.state(), builder.get_constant(*v).to_inner()))
            .collect::<Vec<_>>(),
        handshake_hash,
    );
    builder.add_output(vd);
    Arc::new(builder.build().expect("verify data should build"))
}
