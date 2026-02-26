//! Platform-aware task spawning.

use std::future::Future;

/// Spawns a future on the appropriate runtime.
#[cfg(feature = "wasm")]
pub(crate) fn spawn(future: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(future);
}

/// Spawns a future on the appropriate runtime.
#[cfg(not(feature = "wasm"))]
pub(crate) fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(future);
}
