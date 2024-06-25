//! TLS prover states.

use mpz_core::commit::Decommitment;
use mpz_garble::protocol::deap::PeerEncodings;
use mpz_garble_core::{encoding_state, EncodedValue};
use std::collections::HashMap;
use tls_core::{handshake::HandshakeData, key::PublicKey};
use tls_mpc::MpcTlsLeader;
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

    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) vm: DEAPThread,
    pub(crate) ot_recv: OTReceiver,
    pub(crate) ctx: Context,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPThread,
    pub(crate) ot_recv: OTReceiver,
    pub(crate) ctx: Context,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPThread,
    pub(crate) ot_recv: OTReceiver,
    pub(crate) ctx: Context,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,

    pub(crate) builder: TranscriptCommitmentBuilder,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(state: Closed) -> Self {
        let encodings = collect_encodings(&state.vm, &state.transcript_tx, &state.transcript_rx);

        let encoding_provider = Box::new(move |ids: &[&str]| {
            ids.iter().map(|id| encodings.get(*id).cloned()).collect()
        });

        let builder = TranscriptCommitmentBuilder::new(
            encoding_provider,
            state.transcript_tx.data().len(),
            state.transcript_rx.data().len(),
        );

        Self {
            io: state.io,
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            vm: state.vm,
            ot_recv: state.ot_recv,
            ctx: state.ctx,
            start_time: state.start_time,
            handshake_decommitment: state.handshake_decommitment,
            server_public_key: state.server_public_key,
            transcript_tx: state.transcript_tx,
            transcript_rx: state.transcript_rx,
            builder,
        }
    }
}

/// Proving state.
pub struct Prove {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPThread,
    pub(crate) ot_recv: OTReceiver,
    pub(crate) ctx: Context,

    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,

    pub(crate) proving_info: ProvingInfo,
}

impl From<Closed> for Prove {
    fn from(state: Closed) -> Self {
        Self {
            io: state.io,
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            vm: state.vm,
            ot_recv: state.ot_recv,
            ctx: state.ctx,
            handshake_decommitment: state.handshake_decommitment,
            transcript_tx: state.transcript_tx,
            transcript_rx: state.transcript_rx,
            proving_info: ProvingInfo::default(),
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
