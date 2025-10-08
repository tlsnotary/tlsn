//! TLS Verifier state.

use std::sync::Arc;

use crate::mux::{MuxControl, MuxFuture};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::verifier::{Mpc, Zk};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

/// State after the TLS connection has been closed.
pub struct Committed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
}

opaque_debug::implement!(Committed);

impl VerifierState for Initialized {}
impl VerifierState for Setup {}
impl VerifierState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Committed {}
}
