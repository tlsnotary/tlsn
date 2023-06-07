use std::pin::Pin;

use actor_ot::{ReceiverActorControl, SenderActorControl};
use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    future::FusedFuture,
};

use mpc_core::{commit::Decommitment, hash::Hash};
use mpc_garble::protocol::deap::DEAPVm;
use mpc_share_conversion::{ConverterSender, Gf2_128};
use tls_core::{dns::ServerName, handshake::HandshakeData, key::PublicKey};
use tlsn_core::{SubstringsCommitment, Transcript};

pub struct Initialized<S, T> {
    pub(crate) server_name: ServerName,

    pub(crate) server_socket: S,
    pub(crate) notary_mux: T,

    pub(crate) tx_receiver: Receiver<Bytes>,
    pub(crate) rx_sender: Sender<Result<Bytes, std::io::Error>>,
    pub(crate) close_recv: oneshot::Receiver<oneshot::Sender<()>>,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

pub struct Notarizing<T> {
    pub(crate) notary_mux: T,

    pub(crate) vm: DEAPVm<SenderActorControl, ReceiverActorControl>,
    pub(crate) ot_fut: Pin<Box<dyn FusedFuture<Output = ()> + Send + 'static>>,
    pub(crate) gf2: ConverterSender<Gf2_128, SenderActorControl>,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,

    pub(crate) commitments: Vec<Hash>,
    pub(crate) substring_commitments: Vec<SubstringsCommitment>,
}

impl<T> std::fmt::Debug for Notarizing<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notarizing")
            .field("transcript_tx", &self.transcript_tx)
            .field("transcript_rx", &self.transcript_rx)
            .finish()
    }
}

#[derive(Debug)]
pub struct Finalized {}

pub trait ProverState: sealed::Sealed {}

impl<S, T> ProverState for Initialized<S, T> {}
impl<T> ProverState for Notarizing<T> {}
impl ProverState for Finalized {}

mod sealed {
    pub trait Sealed {}
    impl<S, T> Sealed for super::Initialized<S, T> {}
    impl<T> Sealed for super::Notarizing<T> {}
    impl Sealed for super::Finalized {}
}
