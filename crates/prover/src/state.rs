//! TLS prover states.

use std::sync::Arc;

use mpz_common::{context::Multithread, Context};

use mpc_tls::{MpcTlsLeader, SessionKeys};
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    transcript::TranscriptRefs,
    zk_aes::ZkAesCtr,
};
use tlsn_core::{
    connection::{ConnectionInfo, ServerCertData},
    transcript::{Transcript, TranscriptCommitConfig},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::{Mpc, Zk};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mt: Multithread,
    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) zk_aes: ZkAesCtr,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mt: Multithread,
    pub(crate) ctx: Context,
    pub(crate) _keys: SessionKeys,
    pub(crate) vm: Zk,
    pub(crate) connection_info: ConnectionInfo,
    pub(crate) server_cert_data: ServerCertData,
    pub(crate) transcript: Transcript,
    pub(crate) transcript_refs: TranscriptRefs,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) _mt: Multithread,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) connection_info: ConnectionInfo,
    pub(crate) server_cert_data: ServerCertData,
    pub(crate) transcript: Transcript,
    pub(crate) transcript_refs: TranscriptRefs,
    pub(crate) transcript_commit_config: Option<TranscriptCommitConfig>,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(state: Closed) -> Self {
        Self {
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            _mt: state.mt,
            ctx: state.ctx,
            vm: state.vm,
            connection_info: state.connection_info,
            server_cert_data: state.server_cert_data,
            transcript: state.transcript,
            transcript_refs: state.transcript_refs,
            transcript_commit_config: None,
        }
    }
}

/// Proving state.
pub struct Prove {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) _mt: Multithread,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) _connection_info: ConnectionInfo,
    pub(crate) server_cert_data: ServerCertData,
    pub(crate) transcript: Transcript,
    pub(crate) transcript_refs: TranscriptRefs,
}

impl From<Closed> for Prove {
    fn from(state: Closed) -> Self {
        Self {
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
            _mt: state.mt,
            ctx: state.ctx,
            vm: state.vm,
            _connection_info: state.connection_info,
            server_cert_data: state.server_cert_data,
            transcript: state.transcript,
            transcript_refs: state.transcript_refs,
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
