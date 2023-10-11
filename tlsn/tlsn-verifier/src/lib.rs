//! TLSNotary verifier library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod tls;

use uid_mux::UidYamuxControl;
use utils_aio::codec::BincodeMux;

/// Bincode for serialization, multiplexing with Yamux.
pub(crate) type Mux = BincodeMux<UidYamuxControl>;
