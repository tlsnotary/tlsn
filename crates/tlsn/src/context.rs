//! Execution context.

use mpz_common::context::Multithread;

use crate::mux::MuxControl;

/// Maximum concurrency for multi-threaded context.
pub(crate) const MAX_CONCURRENCY: usize = 8;

/// Builds a multi-threaded context with the given muxer.
pub(crate) fn build_mt_context(mux: MuxControl) -> Multithread {
    let builder = Multithread::builder().mux(mux).concurrency(MAX_CONCURRENCY);

    #[cfg(target_arch = "wasm32")]
    let builder = builder.spawn_handler(|f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    builder.build().unwrap()
}
