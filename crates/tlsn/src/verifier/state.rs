//! TLS Verifier state.

use std::sync::Arc;

use crate::{
    config::ProtocolConfig,
    mux::{MuxControl, MuxFuture},
};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use tlsn_core::{ProveRequest, transcript::TlsTranscript};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::verifier::{Mpc, Zk};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after receiving protocol configuration from the prover.
pub struct Config {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) config: ProtocolConfig,
}

opaque_debug::implement!(Config);

/// State after setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

opaque_debug::implement!(Setup);

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

/// State after receiving a proving request.
pub struct Verify {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) request: ProveRequest,
}

opaque_debug::implement!(Verify);

impl VerifierState for Initialized {}
impl VerifierState for Config {}
impl VerifierState for Setup {}
impl VerifierState for Committed {}
impl VerifierState for Verify {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Config {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Verify {}
}
