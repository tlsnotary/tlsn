use cfg_if::cfg_if;
use std::future::Future;

/// Spawns a future.
pub(crate) fn spawn<F>(f: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    cfg_if! {
        if #[cfg(target_arch = "wasm32")] {
            wasm_bindgen_futures::spawn_local(f);
        } else {
            tokio::spawn(f);
        }
    }
}
