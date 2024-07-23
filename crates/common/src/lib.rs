//! Common code shared between `tlsn-prover` and `tlsn-verifier`.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod config;
pub mod mux;

use serio::codec::Codec;

use crate::mux::MuxControl;

/// IO type.
pub type Io = <serio::codec::Bincode as Codec<uid_mux::yamux::Stream>>::Framed;
/// Base OT sender.
pub type BaseOTSender = mpz_ot::chou_orlandi::Sender;
/// Base OT receiver.
pub type BaseOTReceiver = mpz_ot::chou_orlandi::Receiver;
/// OT sender.
pub type OTSender = mpz_ot::kos::SharedSender<BaseOTReceiver>;
/// OT receiver.
pub type OTReceiver = mpz_ot::kos::SharedReceiver<BaseOTSender>;
/// MPC executor.
pub type Executor = mpz_common::executor::MTExecutor<MuxControl>;
/// MPC thread context.
pub type Context = mpz_common::executor::MTContext<MuxControl, Io>;
/// DEAP thread.
pub type DEAPThread = mpz_garble::protocol::deap::DEAPThread<Context, OTSender, OTReceiver>;

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
pub enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}
