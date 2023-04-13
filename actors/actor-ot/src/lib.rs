//! This crate provides a pair of OT actors for provisioning bulk oblivious transfers using [KOS15](https://eprint.iacr.org/2015/546.pdf).
//!
//! It supports an initial setup procedure to provision a configurable number of Random OTs which can be
//! partitioned (or "split") and distributed as required.
//!
//! # Committed OT
//!
//! This crate also supports a weak flavor of "Committed OT" which allows the Sender to reveal their private inputs
//! so the Receiver can verify messages sent during OT were correct. This procedure is synchronized in such a way to
//! require unanimous agreement across all "split" OTs prior to revealing the Sender's private inputs.
//!
//! # Partitioning Synchronization
//!
//! Both the Sender and Receiver provide an async API, however, both must synchronize the order in which they
//! partition the pre-allocated OTs. To do this, the Sender dictates the order of this process.

mod actor_msg;
mod config;
mod receiver;
mod sender;

pub use actor_msg::{
    GetReceiver, GetSender, MarkForReveal, Reveal, SendBackReceiver, SendBackSender, Setup, Verify,
};
use async_trait::async_trait;
pub use config::{
    OTActorReceiverConfig, OTActorReceiverConfigBuilder, OTActorSenderConfig,
    OTActorSenderConfigBuilder,
};
use mpc_ot::OTError;
pub use receiver::{KOSReceiverActor, ReceiverActorControl};
pub use sender::{KOSSenderActor, SenderActorControl};

#[cfg(test)]
mod test {
    use super::*;
    use actor_mux::{
        MockClientChannelMuxer, MockClientControl, MockServerChannelMuxer, MockServerControl,
    };
    use mpc_core::Block;
    use mpc_ot_core::msgs::OTMessage;
    use utils_aio::{mux::MuxChannelControl, Channel};
    use xtra::prelude::*;

    type OTChannel = Box<dyn Channel<OTMessage, Error = std::io::Error>>;

    async fn create_pair(
        sender_config: OTActorSenderConfig,
        receiver_config: OTActorReceiverConfig,
    ) -> (
        Address<KOSSenderActor<OTChannel, MockClientControl>>,
        Address<KOSReceiverActor<OTChannel, MockServerControl>>,
    ) {
        let receiver_mux_addr =
            xtra::spawn_tokio(MockServerChannelMuxer::default(), Mailbox::unbounded());
        let mut receiver_mux = MockServerControl::new(receiver_mux_addr.clone());

        let mut sender_mux = MockClientControl::new(xtra::spawn_tokio(
            MockClientChannelMuxer::new(receiver_mux_addr),
            Mailbox::unbounded(),
        ));

        let sender_channel = sender_mux.get_channel("KOS".to_string()).await.unwrap();
        let (sender_addr, sender_mailbox) = Mailbox::unbounded();
        let (sender_actor, sender_fut) = KOSSenderActor::new(
            sender_config,
            sender_addr.clone(),
            sender_channel,
            sender_mux,
        );

        let receiver_channel = receiver_mux.get_channel("KOS".to_string()).await.unwrap();
        let (receiver_addr, receiver_mailbox) = Mailbox::unbounded();
        let (receiver_actor, receiver_fut) = KOSReceiverActor::new(
            receiver_config,
            receiver_addr.clone(),
            receiver_channel,
            receiver_mux,
        );

        tokio::spawn(sender_fut);
        tokio::spawn(receiver_fut);
        let sender_addr = xtra::spawn_tokio(sender_actor, (sender_addr, sender_mailbox));
        let receiver_addr = xtra::spawn_tokio(receiver_actor, (receiver_addr, receiver_mailbox));

        (sender_addr, receiver_addr)
    }

    async fn create_pair_controls(
        sender_config: OTActorSenderConfig,
        receiver_config: OTActorReceiverConfig,
    ) -> (
        SenderActorControl<KOSSenderActor<OTChannel, MockClientControl>>,
        ReceiverActorControl<KOSReceiverActor<OTChannel, MockServerControl>>,
    ) {
        let (sender_addr, receiver_addr) = create_pair(sender_config, receiver_config).await;
        (
            SenderActorControl::new(sender_addr),
            ReceiverActorControl::new(receiver_addr),
        )
    }

    async fn create_setup_pair(
        sender_config: OTActorSenderConfig,
        receiver_config: OTActorReceiverConfig,
    ) -> (
        SenderActorControl<KOSSenderActor<OTChannel, MockClientControl>>,
        ReceiverActorControl<KOSReceiverActor<OTChannel, MockServerControl>>,
    ) {
        let (mut sender_control, mut receiver_control) =
            create_pair_controls(sender_config, receiver_config).await;

        let (sender_setup_result, receiver_setup_result) =
            futures::join!(sender_control.setup(), receiver_control.setup());
        sender_setup_result.unwrap();
        receiver_setup_result.unwrap();

        (sender_control, receiver_control)
    }

    #[tokio::test]
    async fn test_ot_actor() {
        let sender_config = OTActorSenderConfigBuilder::default()
            .initial_count(10)
            .build()
            .unwrap();
        let receiver_config = OTActorReceiverConfigBuilder::default()
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

        let send = async { sender_control.send("", data).await.unwrap() };

        let receive = async { receiver_control.receive("", choices).await.unwrap() };

        let (_, received) = futures::join!(send, receive);

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_ot_actor_many_splits() {
        let sender_config = OTActorSenderConfigBuilder::default()
            .initial_count(100)
            .build()
            .unwrap();
        let receiver_config = OTActorReceiverConfigBuilder::default()
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
            let send = async {
                sender_control
                    .send(&id.to_string(), data.clone())
                    .await
                    .unwrap()
            };

            let receive = async {
                receiver_control
                    .receive(&id.to_string(), choices.clone())
                    .await
                    .unwrap()
            };

            let (_, _received) = futures::join!(send, receive);
        }
    }

    #[tokio::test]
    async fn test_ot_actor_committed_ot() {
        let sender_config = OTActorSenderConfigBuilder::default()
            .initial_count(100)
            .committed()
            .build()
            .unwrap();
        let receiver_config = OTActorReceiverConfigBuilder::default()
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
        let send = async { sender_control.send("", data.clone()).await.unwrap() };

        let receive = async { receiver_control.receive("", choices).await.unwrap() };

        let reveal = async {
            sender_control.mark_for_reveal("").await.unwrap();
            sender_control.reveal().await.unwrap()
        };

        let verify = async { receiver_control.verify("", data.clone()).await };

        let (_, _) = futures::join!(send, receive);
        let (_, verify) = futures::join!(reveal, verify);

        assert!(matches!(verify, Ok(())));
    }
}
