//! Transport error classification shared by the prover and verifier.

use std::io;

/// Returns whether an I/O error means the transport peer is gone.
///
/// TCP reports `BrokenPipe`/`ConnectionReset`/`ConnectionAborted`, while the
/// wasm WebSocket transport reports `NotConnected` when writing after close.
pub(crate) fn is_transport_gone(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
    )
}
