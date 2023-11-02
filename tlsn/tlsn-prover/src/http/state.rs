//! HTTP prover state.

use tlsn_formats::http::{Body, Request, Response};

use crate::tls::{state as prover_state, Prover};

/// The state of an HTTP prover
pub trait State: sealed::Sealed {}

/// Connection closed state.
pub struct Closed {
    pub(super) prover: Prover<prover_state::Closed>,
    pub(super) requests: Vec<(Request, Option<Body>)>,
    pub(super) responses: Vec<(Response, Option<Body>)>,
}

/// Notarizing state.
pub struct Notarize {
    pub(super) prover: Prover<prover_state::Notarize>,
    pub(super) requests: Vec<(Request, Option<Body>)>,
    pub(super) responses: Vec<(Response, Option<Body>)>,
}

impl State for Closed {}
impl State for Notarize {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
}
