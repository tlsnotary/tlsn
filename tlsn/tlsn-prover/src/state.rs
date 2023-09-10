use mpz_ot::actor::kos::{SharedReceiver, SharedSender};

use mpz_core::{commit::Decommitment, hash::Hash};
use mpz_garble::protocol::deap::DEAPVm;
use mpz_share_conversion::{ConverterSender, Gf2_128};
use tls_core::{handshake::HandshakeData, key::PublicKey};
use tls_mpc::MpcTlsLeader;
use tlsn_core::{SubstringsCommitment, Transcript};

use crate::{Mux, MuxFuture, OTFuture};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) notary_mux: Mux,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) notary_mux: Mux,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

opaque_debug::implement!(Closed);

/// The state for the [Prover](crate::Prover) during notarization
pub struct Notarize {
    pub(crate) notary_mux: Mux,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,

    pub(crate) commitments: Vec<Hash>,
    pub(crate) substring_commitments: Vec<SubstringsCommitment>,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(value: Closed) -> Self {
        Self {
            notary_mux: value.notary_mux,
            mux_fut: value.mux_fut,

            vm: value.vm,
            ot_fut: value.ot_fut,
            gf2: value.gf2,

            start_time: value.start_time,
            handshake_decommitment: value.handshake_decommitment,
            server_public_key: value.server_public_key,

            transcript_tx: value.transcript_tx,
            transcript_rx: value.transcript_rx,

            commitments: Vec::new(),
            substring_commitments: Vec::new(),
        }
    }
}

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Setup {}
impl ProverState for Closed {}
impl ProverState for Notarize {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
}
