use std::assert_eq;

use futures::{Future, FutureExt};
use mpz_ot_core::msgs::OTMessage;
use utils_aio::mux::MuxChannel;
use xtra::Mailbox;

use crate::{
    KOSReceiverActor, KOSSenderActor, OTActorError, OTActorReceiverConfig, OTActorSenderConfig,
    ReceiverActorControl, SenderActorControl,
};

/// Creates a new OT sender, returning a handle to the actor and a future which resolves when the
/// actor is done.
///
/// # Arguments
///
/// * `id` - The ID of the sender
/// * `mux` - The muxer which sets up channels with the remote receiver
/// * `config` - The configuration for the sender
pub async fn create_ot_sender(
    mut mux: impl MuxChannel<OTMessage> + Send + 'static,
    config: OTActorSenderConfig,
) -> Result<(SenderActorControl, impl Future<Output = ()>), OTActorError> {
    let channel = mux.get_channel(config.id()).await?;
    let (addr, mailbox) = Mailbox::unbounded();
    let (actor, fut) = KOSSenderActor::new(config, addr.clone(), channel, Box::new(mux));

    let fut = futures::future::join(fut, xtra::run(mailbox, actor)).map(|_| ());

    Ok((SenderActorControl::new(addr), fut))
}

/// Creates a new OT receiver, returning a handle to the actor and a future which resolves when the
/// actor is done.
///
/// # Arguments
///
/// * `id` - The ID of the receiver
/// * `mux` - The muxer which sets up channels with the remote sender
/// * `config` - The configuration for the receiver
pub async fn create_ot_receiver(
    mut mux: impl MuxChannel<OTMessage> + Send + 'static,
    config: OTActorReceiverConfig,
) -> Result<(ReceiverActorControl, impl Future<Output = ()>), OTActorError> {
    let channel = mux.get_channel(config.id()).await?;
    let (addr, mailbox) = Mailbox::unbounded();
    let (actor, fut) = KOSReceiverActor::new(config, addr.clone(), channel, Box::new(mux));

    let fut = futures::future::join(fut, xtra::run(mailbox, actor)).map(|_| ());

    Ok((ReceiverActorControl::new(addr), fut))
}

/// Creates a new OT pair, returning handles to the actors.
///
/// # Arguments
///
/// * `id` - The ID of the sender and receiver
/// * `sender_mux` - The muxer which sets up channels with the remote receiver
/// * `receiver_mux` - The muxer which sets up channels with the remote sender
/// * `sender_config` - The configuration for the sender
/// * `receiver_config` - The configuration for the receiver
pub async fn create_ot_pair(
    sender_mux: impl MuxChannel<OTMessage> + Send + 'static,
    receiver_mux: impl MuxChannel<OTMessage> + Send + 'static,
    sender_config: OTActorSenderConfig,
    receiver_config: OTActorReceiverConfig,
) -> Result<
    (
        (SenderActorControl, impl Future<Output = ()>),
        (ReceiverActorControl, impl Future<Output = ()>),
    ),
    OTActorError,
> {
    assert_eq!(sender_config.id(), receiver_config.id());
    futures::try_join!(
        create_ot_sender(sender_mux, sender_config),
        create_ot_receiver(receiver_mux, receiver_config)
    )
}
