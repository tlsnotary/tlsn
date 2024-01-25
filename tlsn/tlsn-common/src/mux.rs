use futures::{AsyncRead, AsyncWrite};
use uid_mux::{yamux, UidYamux};

use crate::Role;

pub type Mux<T> = UidYamux<T>;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// Attach a multiplexer to the provided socket.
///
/// # Arguments
///
/// * `socket` - The socket to attach the multiplexer to.
/// * `role` - The role of the party using the multiplexer.
pub fn attach_mux<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    role: Role,
) -> Mux<T> {
    let mut mux_config = yamux::Config::default();
    // See PR #418
    mux_config.set_max_num_streams(40);
    mux_config.set_max_buffer_size(16 * MB);
    mux_config.set_receive_window(16 * MB as u32);

    let mux_role = match role {
        Role::Prover => yamux::Mode::Client,
        Role::Verifier => yamux::Mode::Server,
    };

    UidYamux::new(mux_config, socket, mux_role)
}
