use crate::protocol::ot::{OTError, OTSenderSetupProcessor};
use async_trait::async_trait;
use futures::channel::oneshot;
use mpc_core::{
    msgs::ot::BaseReceiverSetupWrapper,
    ot::{s_state, Kos15Sender},
};

/// Backend using Rayon to help setup OTs asynchronously and in parallel
#[derive(Copy, Clone, Debug)]
pub struct RayonBackend;

#[async_trait]
impl
    OTSenderSetupProcessor<
        Result<(Kos15Sender<s_state::BaseSetup>, BaseReceiverSetupWrapper), OTError>,
        Result<Kos15Sender<s_state::RandSetup>, OTError>,
    > for RayonBackend
{
    async fn base_setup<V>(
        func: V,
    ) -> Result<(Kos15Sender<s_state::BaseSetup>, BaseReceiverSetupWrapper), OTError>
    where
        V: FnOnce() -> Result<(Kos15Sender<s_state::BaseSetup>, BaseReceiverSetupWrapper), OTError>
            + Send
            + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            _ = sender.send(func());
        });
        receiver
            .await
            .map_err(|_| OTError::BackendError("Channel error".to_string()))?
    }

    async fn extension_setup<V>(func: V) -> Result<Kos15Sender<s_state::RandSetup>, OTError>
    where
        V: FnOnce() -> Result<Kos15Sender<s_state::RandSetup>, OTError> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            _ = sender.send(func());
        });
        receiver
            .await
            .map_err(|_| OTError::BackendError("Channel error".to_string()))?
    }
}
