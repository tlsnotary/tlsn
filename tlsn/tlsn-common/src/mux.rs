//! Multiplexer used in the TLSNotary protocol.

use utils_aio::codec::BincodeMux;

use futures::{AsyncRead, AsyncWrite};
use uid_mux::{yamux, UidYamux, UidYamuxControl};

use crate::Role;

/// Multiplexer supporting unique deterministic stream IDs.
pub type Mux<T> = UidYamux<T>;
/// Multiplexer controller providing streams with a codec attached.
pub type MuxControl = BincodeMux<UidYamuxControl>;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// Attach a multiplexer to the provided socket.
///
/// Returns the multiplexer and a controller for creating streams with a codec attached.
///
/// # Arguments
///
/// * `socket` - The socket to attach the multiplexer to.
/// * `role` - The role of the party using the multiplexer.
pub fn attach_mux<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    role: Role,
) -> (Mux<T>, MuxControl) {
    let mut mux_config = yamux::Config::default();
    // See PR #418
    mux_config.set_max_num_streams(40);
    mux_config.set_max_buffer_size(16 * MB);
    mux_config.set_receive_window(16 * MB as u32);

    let mux_role = match role {
        Role::Prover => yamux::Mode::Client,
        Role::Verifier => yamux::Mode::Server,
    };

    let mux = UidYamux::new(mux_config, socket, mux_role);
    let ctrl = BincodeMux::new(mux.control());

    (mux, ctrl)
}
