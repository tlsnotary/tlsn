//! TLSNotary verifier library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod tls;

use uid_mux::UidYamuxControl;
use utils_aio::codec::BincodeMux;

/// A muxer which uses Bincode for serialization, Yamux for multiplexing.
pub(crate) type Mux = BincodeMux<UidYamuxControl>;
