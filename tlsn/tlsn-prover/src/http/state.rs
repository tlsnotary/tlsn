//! HTTP prover state.

use tlsn_formats::http::HttpTranscript;

use crate::tls::{state as prover_state, Prover};

/// The state of an HTTP prover
pub trait State: sealed::Sealed {}

/// Connection closed state.
pub struct Closed {
    pub(super) prover: Prover<prover_state::Closed>,
    pub(super) transcript: HttpTranscript,
}

/// Notarizing state.
pub struct Notarize {
    pub(super) prover: Prover<prover_state::Notarize>,
    pub(super) transcript: HttpTranscript,
}

impl State for Closed {}
impl State for Notarize {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
}
