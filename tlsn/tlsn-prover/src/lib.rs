//! The prover library
//!
//! This library provides the [Prover] type. It can be used for creating TLS connections with a
//! server which can be notarized with the help of a notary.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

#[cfg(feature = "formats")]
pub mod http;
mod tls;

pub use tls::{
    state as prover_state, Prover, ProverConfig, ProverConfigBuilder, ProverConfigBuilderError,
    ProverError, ProverFuture,
};

use uid_mux::UidYamuxControl;
use utils_aio::codec::BincodeMux;

/// A muxer which uses Bincode for serialization, Yamux for multiplexing.
type Mux = BincodeMux<UidYamuxControl>;
