//! TLS Verifier state.

use mpz_core::hash::Hash;
use mpz_garble::protocol::deap::DEAPVm;
use mpz_ot::actor::kos::{SharedReceiver, SharedSender};
use mpz_share_conversion::{ConverterReceiver, Gf2_128};
use tls_core::key::PublicKey;
use tls_mpc::MpcTlsFollower;

use crate::{
    tls::{MuxFuture, OTFuture},
    Mux,
};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) mux: Mux,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_send: SharedSender,
    pub(crate) ot_recv: SharedReceiver,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterReceiver<Gf2_128, SharedReceiver>,

    pub(crate) encoder_seed: [u8; 32],
}

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) mux: Mux,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_send: SharedSender,
    pub(crate) ot_recv: SharedReceiver,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterReceiver<Gf2_128, SharedReceiver>,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) start_time: u64,
    pub(crate) server_ephemeral_key: PublicKey,
    pub(crate) handshake_commitment: Hash,
    pub(crate) sent_len: usize,
    pub(crate) recv_len: usize,
}

opaque_debug::implement!(Closed);

impl VerifierState for Initialized {}
impl VerifierState for Setup {}
impl VerifierState for Closed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
}
