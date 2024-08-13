//! TLS prover states.

use mpz_core::commit::Decommitment;
use mpz_garble::protocol::deap::PeerEncodings;
use mpz_garble_core::{encoding_state, EncodedValue};
use std::collections::HashMap;
use tls_core::{handshake::HandshakeData, key::PublicKey};
use tls_tee::TeeTlsLeader;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    Context, DEAPThread, Io, OTReceiver,
};
use tlsn_core::{commitment::TranscriptCommitmentBuilder, msg::ProvingInfo, Transcript};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) mpc_tls: TeeTlsLeader,
    pub(crate) ctx: Context,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) ctx: Context,

    pub(crate) start_time: u64,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) ctx: Context,

    pub(crate) start_time: u64,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(state: Closed) -> Self {
        Self {
            io: state.io,
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            ctx: state.ctx,
            start_time: state.start_time,
        }
    }
}

/// Proving state.
pub struct Prove {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) ctx: Context,
}

impl From<Closed> for Prove {
    fn from(state: Closed) -> Self {
        Self {
            io: state.io,
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            ctx: state.ctx,
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

fn collect_encodings(
    vm: &impl PeerEncodings,
    transcript_tx: &Transcript,
    transcript_rx: &Transcript,
) -> HashMap<String, EncodedValue<encoding_state::Active>> {
    let tx_ids = (0..transcript_tx.data().len()).map(|id| format!("tx/{id}"));
    let rx_ids = (0..transcript_rx.data().len()).map(|id| format!("rx/{id}"));

    let ids = tx_ids.chain(rx_ids).collect::<Vec<_>>();
    let id_refs = ids.iter().map(|id| id.as_ref()).collect::<Vec<_>>();

    vm.get_peer_encodings(&id_refs)
        .expect("encodings for all transcript values should be present")
        .into_iter()
        .zip(ids)
        .map(|(encoding, id)| (id, encoding))
        .collect()
}
