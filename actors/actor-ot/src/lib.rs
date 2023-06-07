//! This crate provides a pair of OT actors for provisioning bulk oblivious transfers using [KOS15](https://eprint.iacr.org/2015/546.pdf).
//!
//! It supports an initial setup procedure to provision a configurable number of Random OTs which can be
//! partitioned (or "split") and distributed as required.
//!
//! # Committed OT
//!
//! This crate also supports a weak flavor of "Committed OT" which allows the Sender to reveal their private inputs
//! so the Receiver can verify messages sent during OT were correct.
//!
//! # Partitioning Synchronization
//!
//! Both the Sender and Receiver provide an async API, however, both must synchronize the order in which they
//! partition the pre-allocated OTs. To do this, the Sender dictates the order of this process.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod msg;
mod receiver;
mod sender;
mod setup;

pub use config::{
    OTActorReceiverConfig, OTActorReceiverConfigBuilder, OTActorSenderConfig,
    OTActorSenderConfigBuilder,
};
pub use mpc_ot::{ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify};
pub use mpc_ot_core::msgs::OTMessage;
pub(crate) use msg::{
    GetReceiver, GetSender, Reveal, SendBackReceiver, SendBackSender, Setup, Verify,
};
pub use receiver::{KOSReceiverActor, ReceiverActorControl};
pub use sender::{KOSSenderActor, SenderActorControl};
pub use setup::{create_ot_pair, create_ot_receiver, create_ot_sender};

/// Errors which can occur when working with the OT actors
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OTActorError {
    #[error(transparent)]
    OTError(#[from] mpc_ot::OTError),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
}

#[cfg(test)]
mod test {
    use crate::setup::create_ot_pair;

    use super::*;

    use mpc_core::Block;
    use mpc_ot::{ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify};
    use utils_aio::mux::mock::MockMuxChannelFactory;

    async fn create_setup_pair(
        sender_config: OTActorSenderConfig,
        receiver_config: OTActorReceiverConfig,
    ) -> (SenderActorControl, ReceiverActorControl) {
        let mux_factory = MockMuxChannelFactory::new();

        let ((mut sender_control, sender_fut), (mut receiver_control, receiver_fut)) =
            create_ot_pair(
                mux_factory.clone(),
                mux_factory,
                sender_config,
                receiver_config,
            )
            .await
            .unwrap();

        let rt = tokio::runtime::Handle::current();
        rt.spawn(sender_fut);
        rt.spawn(receiver_fut);

        futures::try_join!(sender_control.setup(), receiver_control.setup()).unwrap();

        (sender_control, receiver_control)
    }

    #[tokio::test]
    async fn test_ot_actor() {
        let sender_config = OTActorSenderConfig::builder()
            .id("test")
            .initial_count(10)
            .build()
            .unwrap();
        let receiver_config = OTActorReceiverConfig::builder()
            .id("test")
            .initial_count(10)
            .build()
            .unwrap();

        let (sender_control, receiver_control) =
            create_setup_pair(sender_config, receiver_config).await;

        let data: Vec<[Block; 2]> = (0..10).map(|_| [Block::new(0), Block::new(1)]).collect();
        let choices = vec![
            false, false, true, true, false, true, true, false, true, false,
        ];

        let expected: Vec<Block> = data
            .iter()
            .zip(&choices)
            .map(|(data, choice)| data[*choice as usize])
            .collect();

        let (_, received) = futures::try_join!(
            sender_control.send("", data.clone()),
            ObliviousReceive::<bool, Block>::receive(&receiver_control, "", choices)
        )
        .unwrap();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_ot_actor_many_splits() {
        let sender_config = OTActorSenderConfig::builder()
            .id("test")
            .initial_count(100)
            .build()
            .unwrap();
        let receiver_config = OTActorReceiverConfig::builder()
            .id("test")
            .initial_count(100)
            .build()
            .unwrap();

        let (sender_control, receiver_control) =
            create_setup_pair(sender_config, receiver_config).await;

        let data: Vec<[Block; 2]> = (0..10).map(|_| [Block::new(0), Block::new(1)]).collect();
        let choices = vec![
            false, false, true, true, false, true, true, false, true, false,
        ];
        for id in 0..10 {
            let id = id.to_string();
            _ = futures::try_join!(
                sender_control.send(&id, data.clone()),
                ObliviousReceive::<bool, Block>::receive(&receiver_control, &id, choices.clone())
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn test_ot_actor_committed_ot() {
        let sender_config = OTActorSenderConfig::builder()
            .id("test")
            .initial_count(100)
            .committed()
            .build()
            .unwrap();
        let receiver_config = OTActorReceiverConfig::builder()
            .id("test")
            .initial_count(100)
            .committed()
            .build()
            .unwrap();

        let (sender_control, receiver_control) =
            create_setup_pair(sender_config, receiver_config).await;

        let data: Vec<[Block; 2]> = (0..10).map(|_| [Block::new(0), Block::new(1)]).collect();
        let choices = vec![
            false, false, true, true, false, true, true, false, true, false,
        ];

        _ = futures::try_join!(
            sender_control.send("", data.clone()),
            ObliviousReceive::<bool, Block>::receive(&receiver_control, "", choices)
        )
        .unwrap();

        _ = futures::try_join!(
            sender_control.reveal(),
            receiver_control.verify("", data.clone())
        )
        .unwrap();
    }
}
