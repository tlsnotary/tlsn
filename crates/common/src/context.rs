use mpz_common::context::Multithread;

use crate::mux::MuxControl;

/// Builds a multi-threaded context with the given muxer.
pub fn build_mt_context(mux: MuxControl) -> Multithread {
    Multithread::builder()
        .mux(mux)
        .concurrency(8)
        .build()
        .unwrap()
}
