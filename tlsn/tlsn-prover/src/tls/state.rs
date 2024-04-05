//! TLS prover states.

use crate::tls::{encoding_provider::CachedEncodingProvider, MuxFuture, OTFuture};

use mpz_garble::protocol::deap::{DEAPThread, DEAPVm};
use mpz_ot::actor::kos::{SharedReceiver, SharedSender};
use mpz_share_conversion::{ConverterSender, Gf2_128};
use tls_mpc::{MpcTlsData, MpcTlsLeader};
use tlsn_common::{msg::TlsnMessage, mux::MuxControl};
use tlsn_core::{
    substring::{SubstringCommitConfigBuilder, SubstringProofConfigBuilder},
    Transcript,
};
use utils_aio::duplex::Duplex;

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    /// A muxer for communication with the Notary
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) start_time: u64,
    pub(crate) mpc_tls_data: MpcTlsData,

    pub(crate) transcript: Transcript,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    /// A muxer for communication with the Notary
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) start_time: u64,
    pub(crate) mpc_tls_data: MpcTlsData,

    pub(crate) transcript: Transcript,

    pub(crate) encoding_provider: CachedEncodingProvider,
    pub(crate) substring_commitment_builder: SubstringCommitConfigBuilder,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(state: Closed) -> Self {
        let encoding_provider = CachedEncodingProvider::new(&state.vm, &state.transcript);
        let substring_commitment_builder = SubstringCommitConfigBuilder::new(&state.transcript);

        Self {
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            vm: state.vm,
            ot_fut: state.ot_fut,
            gf2: state.gf2,
            start_time: state.start_time,
            mpc_tls_data: state.mpc_tls_data,
            transcript: state.transcript,
            encoding_provider,
            substring_commitment_builder,
        }
    }
}

/// Proving state.
pub struct Prove {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) transcript: Transcript,
    pub(crate) mpc_tls_data: MpcTlsData,

    pub(crate) channel: Option<Box<dyn Duplex<TlsnMessage>>>,
    pub(crate) prove_thread: Option<DEAPThread<SharedSender, SharedReceiver>>,

    pub(crate) substring_proof_builder: SubstringProofConfigBuilder,
}

impl From<Closed> for Prove {
    fn from(state: Closed) -> Self {
        let substring_proof_builder = SubstringProofConfigBuilder::new(&state.transcript);
        Self {
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            vm: state.vm,
            ot_fut: state.ot_fut,
            gf2: state.gf2,
            transcript: state.transcript,
            mpc_tls_data: state.mpc_tls_data,
            channel: None,
            prove_thread: None,
            substring_proof_builder,
        }
    }
}

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Setup {}
impl ProverState for Closed {}
impl ProverState for Notarize {}
impl ProverState for Prove {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
    impl Sealed for super::Prove {}
}
