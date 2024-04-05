//! TLS Verifier state.

use mpz_core::hash::Hash;
use mpz_garble::protocol::deap::{DEAPThread, DEAPVm};
use mpz_ot::actor::kos::{SharedReceiver, SharedSender};
use mpz_share_conversion::{ConverterReceiver, Gf2_128};
use tls_core::key::PublicKey;
use tls_mpc::{MpcTlsFollower, MpcTlsFollowerData};
use tlsn_common::{msg::TlsnMessage, mux::MuxControl};
use utils_aio::duplex::Duplex;

use crate::tls::future::{MuxFuture, OTFuture};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
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
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_send: SharedSender,
    pub(crate) ot_recv: SharedReceiver,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterReceiver<Gf2_128, SharedReceiver>,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) start_time: u64,
    pub(crate) mpc_tls_data: MpcTlsFollowerData,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_send: SharedSender,
    pub(crate) ot_recv: SharedReceiver,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterReceiver<Gf2_128, SharedReceiver>,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) start_time: u64,
    pub(crate) mpc_tls_data: MpcTlsFollowerData,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(value: Closed) -> Self {
        Self {
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            vm: value.vm,
            ot_send: value.ot_send,
            ot_recv: value.ot_recv,
            ot_fut: value.ot_fut,
            gf2: value.gf2,
            encoder_seed: value.encoder_seed,
            start_time: value.start_time,
            mpc_tls_data: value.mpc_tls_data,
        }
    }
}

/// Verifying state.
pub struct Verify {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_send: SharedSender,
    pub(crate) ot_recv: SharedReceiver,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterReceiver<Gf2_128, SharedReceiver>,

    pub(crate) start_time: u64,
    pub(crate) mpc_tls_data: MpcTlsFollowerData,

    pub(crate) channel: Option<Box<dyn Duplex<TlsnMessage>>>,
    pub(crate) verify_thread: Option<DEAPThread<SharedSender, SharedReceiver>>,
}

opaque_debug::implement!(Verify);

impl From<Closed> for Verify {
    fn from(value: Closed) -> Self {
        Self {
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            vm: value.vm,
            ot_send: value.ot_send,
            ot_recv: value.ot_recv,
            ot_fut: value.ot_fut,
            gf2: value.gf2,
            start_time: value.start_time,
            mpc_tls_data: value.mpc_tls_data,
            channel: None,
            verify_thread: None,
        }
    }
}

impl VerifierState for Initialized {}
impl VerifierState for Setup {}
impl VerifierState for Closed {}
impl VerifierState for Notarize {}
impl VerifierState for Verify {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
    impl Sealed for super::Verify {}
}
