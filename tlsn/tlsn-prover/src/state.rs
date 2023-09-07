use std::pin::Pin;

use mpz_ot::actor::kos::{SharedReceiver, SharedSender};

use futures::future::FusedFuture;

use mpz_core::{commit::Decommitment, hash::Hash};
use mpz_garble::protocol::deap::DEAPVm;
use mpz_share_conversion::{ConverterSender, Gf2_128};
use tls_core::{dns::ServerName, handshake::HandshakeData, key::PublicKey};
use tlsn_core::{SubstringsCommitment, Transcript};

use crate::{Mux, ProverError};

/// The state for the initialized [Prover](crate::Prover)
pub struct Initialized {
    pub(crate) server_name: ServerName,
    pub(crate) notary_mux: Mux,
}

opaque_debug::implement!(Initialized);

/// The state for the [Prover](crate::Prover) during notarization
pub struct Notarize {
    pub(crate) notary_mux: Mux,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: Pin<Box<dyn FusedFuture<Output = Result<(), ProverError>> + Send + 'static>>,
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

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Notarize {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Notarize {}
}
