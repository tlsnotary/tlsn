//! Common code shared between `tlsn-prover` and `tlsn-verifier`.

pub mod mux;

/// The parties role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
pub enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}
