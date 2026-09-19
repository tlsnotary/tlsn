//! Platform-aware task spawning.

use std::future::Future;

use futures::channel::oneshot;
use tlsn::SessionDriver;

use crate::{
    error::{Result, SdkError},
    io::Io,
};

pub(crate) type BoxIo = Box<dyn Io>;

pub(crate) struct DriverTask(oneshot::Receiver<tlsn::Result<BoxIo>>);

impl DriverTask {
    pub(crate) fn spawn(driver: SessionDriver<BoxIo>) -> Self {
        let (sender, receiver) = oneshot::channel();
        spawn(async move {
            let result = driver.await;
            match &result {
                Ok(_) => tracing::warn!("session driver completed (mux closed)"),
                Err(error) => tracing::error!("session driver error: {error}"),
            }
            let _ = sender.send(result);
        });
        Self(receiver)
    }

    pub(crate) async fn finish(self) -> Result<BoxIo> {
        self.0
            .await
            .map_err(|_| SdkError::internal("session driver task dropped"))?
            .map_err(Into::into)
    }
}

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
