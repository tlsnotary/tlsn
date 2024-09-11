//! TLS prover states.

use mpz_core::serialize::CanonicalSerialize;
use mpz_garble::protocol::deap::PeerEncodings;
use mpz_garble_core::{encoding_state, EncodedValue};
use std::collections::HashMap;
use tls_mpc::MpcTlsLeader;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    Context, DEAPThread, Io, OTReceiver,
};
use tlsn_core::{
    connection::{ConnectionInfo, ServerCertData},
    transcript::{encoding::EncodingProvider, Direction, Idx, Transcript, TranscriptCommitConfig},
};

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

    pub(crate) connection_info: ConnectionInfo,
    pub(crate) server_cert_data: ServerCertData,

    pub(crate) transcript: Transcript,
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

    pub(crate) connection_info: ConnectionInfo,
    pub(crate) server_cert_data: ServerCertData,

    pub(crate) transcript: Transcript,
    pub(crate) encoding_provider: Box<dyn EncodingProvider + Send + Sync>,

    pub(crate) transcript_commit_config: Option<TranscriptCommitConfig>,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(state: Closed) -> Self {
        struct HashMapProvider(HashMap<String, EncodedValue<encoding_state::Active>>);

        impl EncodingProvider for HashMapProvider {
            fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>> {
                let mut encoding = Vec::new();
                let prefix = match direction {
                    Direction::Sent => "tx/",
                    Direction::Received => "rx/",
                };
                for i in idx.iter() {
                    encoding
                        .extend_from_slice(&self.0.get(&format!("{}{}", prefix, i))?.to_bytes());
                }

                Some(encoding)
            }
        }

        let encoding_provider = HashMapProvider(collect_encodings(&state.vm, &state.transcript));

        Self {
            io: state.io,
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            vm: state.vm,
            ot_recv: state.ot_recv,
            ctx: state.ctx,
            connection_info: state.connection_info,
            server_cert_data: state.server_cert_data,
            transcript: state.transcript,
            encoding_provider: Box::new(encoding_provider),
            transcript_commit_config: None,
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

    pub(crate) server_cert_data: ServerCertData,

    pub(crate) transcript: Transcript,
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
            server_cert_data: state.server_cert_data,
            transcript: state.transcript,
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
    transcript: &Transcript,
) -> HashMap<String, EncodedValue<encoding_state::Active>> {
    let tx_ids = (0..transcript.sent().len()).map(|id| format!("tx/{id}"));
    let rx_ids = (0..transcript.received().len()).map(|id| format!("rx/{id}"));

    let ids = tx_ids.chain(rx_ids).collect::<Vec<_>>();
    let id_refs = ids.iter().map(|id| id.as_ref()).collect::<Vec<_>>();

    vm.get_peer_encodings(&id_refs)
        .expect("encodings for all transcript values should be present")
        .into_iter()
        .zip(ids)
        .map(|(encoding, id)| (id, encoding))
        .collect()
}
