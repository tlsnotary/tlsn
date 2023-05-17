use std::sync::{Arc, Weak};

use async_trait::async_trait;
use mpc_share_conversion_core::{Field, Share};

use crate::{
    AdditiveToMultiplicative, GilboaReceiver, GilboaSender, MultiplicativeToAdditive,
    OTReceiveElement, OTSendElement, ReceiverConfig, SenderConfig, ShareConversionChannel,
    ShareConversionError,
};

/// The share conversion sender
pub struct ConverterSender<F: Field, OT> {
    ot: OT,
    // Sender is wrapped in an option so that we can take ownership of it in `finalize`
    // This prevents the sender from being used after finalization
    sender: Option<Arc<GilboaSender<F>>>,
    channel: ShareConversionChannel<F>,
}

impl<F: Field, OT> std::fmt::Debug for ConverterSender<F, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sender {{ .. }}")
    }
}

impl<F, OT> ConverterSender<F, OT>
where
    F: Field,
    OT: OTSendElement<F> + Clone,
{
    /// Create a new sender
    pub fn new(config: SenderConfig, ot: OT, channel: ShareConversionChannel<F>) -> Self {
        Self {
            ot,
            sender: Some(Arc::new(GilboaSender::new(config))),
            channel,
        }
    }

    /// Returns a handle to the sender
    pub fn handle(&self) -> Result<ConverterSenderHandle<F, OT>, ShareConversionError> {
        Ok(ConverterSenderHandle {
            ot: self.ot.clone(),
            sender: Arc::downgrade(
                self.sender
                    .as_ref()
                    .ok_or(ShareConversionError::AlreadyFinalized)?,
            ),
        })
    }

    /// Reveals the Sender's seed and tape to the Receiver for verification.
    pub async fn reveal(&mut self) -> Result<(), ShareConversionError> {
        let sender = self
            .sender
            .take()
            .ok_or(ShareConversionError::AlreadyFinalized)?;

        let mut sender = Arc::try_unwrap(sender).expect("only one strong reference");

        sender.reveal(&mut self.channel).await
    }
}

#[async_trait]
impl<F, OT> AdditiveToMultiplicative<F> for ConverterSender<F, OT>
where
    F: Field,
    OT: OTSendElement<F>,
{
    async fn to_multiplicative(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.sender
            .as_ref()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_add).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

#[async_trait]
impl<F, OT> MultiplicativeToAdditive<F> for ConverterSender<F, OT>
where
    F: Field,
    OT: OTSendElement<F>,
{
    async fn to_additive(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.sender
            .as_ref()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_mul).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

/// A handle to a sender
#[derive(Clone)]
pub struct ConverterSenderHandle<F: Field, OT> {
    ot: OT,
    sender: Weak<GilboaSender<F>>,
}

#[async_trait]
impl<F, OT> AdditiveToMultiplicative<F> for ConverterSenderHandle<F, OT>
where
    F: Field,
    OT: OTSendElement<F>,
{
    async fn to_multiplicative(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.sender
            .upgrade()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_add).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

#[async_trait]
impl<F, OT> MultiplicativeToAdditive<F> for ConverterSenderHandle<F, OT>
where
    F: Field,
    OT: OTSendElement<F>,
{
    async fn to_additive(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.sender
            .upgrade()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_mul).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

/// The share conversion receiver
pub struct ConverterReceiver<F: Field, OT> {
    ot: OT,
    // Receiver is wrapped in an option so that we can take ownership of it in `finalize`
    // This prevents the receiver from being used after finalization
    receiver: Option<Arc<GilboaReceiver<F>>>,
    channel: ShareConversionChannel<F>,
}

impl<F: Field, OT> std::fmt::Debug for ConverterReceiver<F, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Receiver {{ .. }}")
    }
}

impl<F, OT> ConverterReceiver<F, OT>
where
    F: Field,
    OT: OTReceiveElement<F> + Clone,
{
    /// Create a new receiver
    pub fn new(config: ReceiverConfig, ot: OT, channel: ShareConversionChannel<F>) -> Self {
        Self {
            ot,
            receiver: Some(Arc::new(GilboaReceiver::new(config))),
            channel,
        }
    }

    /// Returns a handle to the receiver
    pub fn handle(&self) -> Result<ConverterReceiverHandle<F, OT>, ShareConversionError> {
        Ok(ConverterReceiverHandle {
            ot: self.ot.clone(),
            receiver: Arc::downgrade(
                self.receiver
                    .as_ref()
                    .ok_or(ShareConversionError::AlreadyFinalized)?,
            ),
        })
    }

    /// Verifies the Sender's seed and tape.
    pub async fn verify(&mut self) -> Result<(), ShareConversionError> {
        let receiver = self
            .receiver
            .take()
            .ok_or(ShareConversionError::AlreadyFinalized)?;

        let mut receiver = Arc::try_unwrap(receiver).expect("only one strong reference");

        receiver.verify(&mut self.channel).await
    }
}

#[async_trait]
impl<F, OT> AdditiveToMultiplicative<F> for ConverterReceiver<F, OT>
where
    F: Field,
    OT: OTReceiveElement<F>,
{
    async fn to_multiplicative(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.receiver
            .as_ref()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_add).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

#[async_trait]
impl<F, OT> MultiplicativeToAdditive<F> for ConverterReceiver<F, OT>
where
    F: Field,
    OT: OTReceiveElement<F>,
{
    async fn to_additive(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.receiver
            .as_ref()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_mul).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

/// A handle to a receiver
#[derive(Clone)]
pub struct ConverterReceiverHandle<F: Field, OT> {
    ot: OT,
    receiver: Weak<GilboaReceiver<F>>,
}

#[async_trait]
impl<F, OT> AdditiveToMultiplicative<F> for ConverterReceiverHandle<F, OT>
where
    F: Field,
    OT: OTReceiveElement<F>,
{
    async fn to_multiplicative(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.receiver
            .upgrade()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_add).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}

#[async_trait]
impl<F, OT> MultiplicativeToAdditive<F> for ConverterReceiverHandle<F, OT>
where
    F: Field,
    OT: OTReceiveElement<F>,
{
    async fn to_additive(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.receiver
            .upgrade()
            .ok_or(ShareConversionError::AlreadyFinalized)?
            .convert_from(
                &self.ot,
                &input.into_iter().map(Share::new_mul).collect::<Vec<_>>(),
            )
            .await
            .map(|shares| shares.into_iter().map(|share| share.to_inner()).collect())
    }
}
