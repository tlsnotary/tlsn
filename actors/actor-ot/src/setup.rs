use futures::task::{Spawn, SpawnExt};
use mpc_ot_core::msgs::OTMessage;
use utils_aio::mux::MuxChannel;
use xtra::Mailbox;

use crate::{
    KOSReceiverActor, KOSSenderActor, OTActorError, OTActorReceiverConfig, OTActorSenderConfig,
    ReceiverActorControl, SenderActorControl,
};

/// Creates a new OT sender, returning a handle to the actor.
///
/// # Arguments
///
/// * `id` - The ID of the sender
/// * `spawner` - The spawner to spawn the internal tasks
/// * `mux` - The muxer which sets up channels with the remote receiver
/// * `config` - The configuration for the sender
pub async fn create_ot_sender(
    id: &str,
    spawner: &impl Spawn,
    mut mux: impl MuxChannel<OTMessage> + Send + 'static,
    config: OTActorSenderConfig,
) -> Result<SenderActorControl, OTActorError> {
    let channel = mux.get_channel(id).await.unwrap();
    let (addr, mailbox) = Mailbox::unbounded();
    let actor = KOSSenderActor::new(config, addr.clone(), &spawner, channel, Box::new(mux));

    spawner
        .spawn(xtra::run(mailbox, actor))
        .expect("spawner can spawn");

    Ok(SenderActorControl::new(addr))
}

/// Creates a new OT receiver, returning a handle to the actor.
///
/// # Arguments
///
/// * `id` - The ID of the receiver
/// * `spawner` - The spawner to spawn the internal tasks
/// * `mux` - The muxer which sets up channels with the remote sender
/// * `config` - The configuration for the receiver
pub async fn create_ot_receiver(
    id: &str,
    spawner: &impl Spawn,
    mut mux: impl MuxChannel<OTMessage> + Send + 'static,
    config: OTActorReceiverConfig,
) -> Result<ReceiverActorControl, OTActorError> {
    let channel = mux.get_channel(id).await.unwrap();
    let (addr, mailbox) = Mailbox::unbounded();
    let actor = KOSReceiverActor::new(config, addr.clone(), &spawner, channel, Box::new(mux));

    spawner
        .spawn(xtra::run(mailbox, actor))
        .expect("spawner can spawn");

    Ok(ReceiverActorControl::new(addr))
}

/// Creates a new OT pair, returning handles to the actors.
///
/// # Arguments
///
/// * `id` - The ID of the sender and receiver
/// * `spawner` - The spawner to spawn the internal tasks
/// * `sender_mux` - The muxer which sets up channels with the remote receiver
/// * `receiver_mux` - The muxer which sets up channels with the remote sender
/// * `sender_config` - The configuration for the sender
/// * `receiver_config` - The configuration for the receiver
pub async fn create_ot_pair(
    id: &str,
    spawner: &impl Spawn,
    sender_mux: impl MuxChannel<OTMessage> + Send + 'static,
    receiver_mux: impl MuxChannel<OTMessage> + Send + 'static,
    sender_config: OTActorSenderConfig,
    receiver_config: OTActorReceiverConfig,
) -> Result<(SenderActorControl, ReceiverActorControl), OTActorError> {
    futures::try_join!(
        create_ot_sender(id, spawner, sender_mux, sender_config),
        create_ot_receiver(id, spawner, receiver_mux, receiver_config)
    )
}
