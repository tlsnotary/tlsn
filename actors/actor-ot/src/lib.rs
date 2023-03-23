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
//! Both the Sender and Receiver factories provide an async API, however, both must synchronize the order in which they
//! partition the pre-allocated OTs. To do this, the Sender factory dictates the order of this process.

mod config;
mod receiver;
mod sender;

pub use config::{
    ReceiverFactoryConfig, ReceiverFactoryConfigBuilder, SenderFactoryConfig,
    SenderFactoryConfigBuilder,
};
pub use receiver::{KOSReceiverFactory, ReceiverFactoryControl};
pub use sender::{KOSSenderFactory, SenderFactoryControl};

pub struct Setup;

pub struct GetSender {
    id: String,
    count: usize,
}

pub struct GetReceiver {
    id: String,
    count: usize,
}

pub struct Verify;

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    use actor_mux::{
        MockClientChannelMuxer, MockClientControl, MockServerChannelMuxer, MockServerControl,
    };
    use mpc_core::Block;
    use mpc_ot::{
        config::{
            OTReceiverConfig, OTReceiverConfigBuilder, OTSenderConfig, OTSenderConfigBuilder,
        },
        OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify,
    };
    use mpc_ot_core::msgs::OTFactoryMessage;
    use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl, Channel};
    use xtra::prelude::*;

    type OTFactoryChannel = Box<dyn Channel<OTFactoryMessage, Error = std::io::Error>>;

    async fn create_pair(
        sender_config: SenderFactoryConfig,
        receiver_config: ReceiverFactoryConfig,
    ) -> (
        Address<KOSSenderFactory<OTFactoryChannel, MockClientControl>>,
        Address<KOSReceiverFactory<OTFactoryChannel, MockServerControl>>,
    ) {
        let receiver_mux_addr =
            xtra::spawn_tokio(MockServerChannelMuxer::default(), Mailbox::unbounded());
        let mut receiver_mux = MockServerControl::new(receiver_mux_addr.clone());

        let mut sender_mux = MockClientControl::new(xtra::spawn_tokio(
            MockClientChannelMuxer::new(receiver_mux_addr),
            Mailbox::unbounded(),
        ));

        let sender_channel = sender_mux
            .get_channel("KOSFactory".to_string())
            .await
            .unwrap();
        let (sender_addr, sender_mailbox) = Mailbox::unbounded();
        let (sender_factory, sender_fut) = KOSSenderFactory::new(
            sender_config,
            sender_addr.clone(),
            sender_channel,
            sender_mux,
        );

        let receiver_channel = receiver_mux
            .get_channel("KOSFactory".to_string())
            .await
            .unwrap();
        let (receiver_addr, receiver_mailbox) = Mailbox::unbounded();
        let (receiver_factory, receiver_fut) = KOSReceiverFactory::new(
            receiver_config,
            receiver_addr.clone(),
            receiver_channel,
            receiver_mux,
        );

        tokio::spawn(sender_fut);
        tokio::spawn(receiver_fut);
        let sender_addr = xtra::spawn_tokio(sender_factory, (sender_addr, sender_mailbox));
        let receiver_addr = xtra::spawn_tokio(receiver_factory, (receiver_addr, receiver_mailbox));

        (sender_addr, receiver_addr)
    }

    async fn create_pair_controls(
        sender_config: SenderFactoryConfig,
        receiver_config: ReceiverFactoryConfig,
    ) -> (
        SenderFactoryControl<KOSSenderFactory<OTFactoryChannel, MockClientControl>>,
        ReceiverFactoryControl<KOSReceiverFactory<OTFactoryChannel, MockServerControl>>,
    ) {
        let (sender_addr, receiver_addr) = create_pair(sender_config, receiver_config).await;
        (
            SenderFactoryControl::new(sender_addr),
            ReceiverFactoryControl::new(receiver_addr),
        )
    }

    async fn create_setup_pair(
        sender_config: SenderFactoryConfig,
        receiver_config: ReceiverFactoryConfig,
    ) -> (
        SenderFactoryControl<KOSSenderFactory<OTFactoryChannel, MockClientControl>>,
        ReceiverFactoryControl<KOSReceiverFactory<OTFactoryChannel, MockServerControl>>,
    ) {
        let (mut sender_control, mut receiver_control) =
            create_pair_controls(sender_config, receiver_config).await;

        let (sender_setup_result, receiver_setup_result) =
            futures::join!(sender_control.setup(), receiver_control.setup());
        sender_setup_result.unwrap();
        receiver_setup_result.unwrap();

        (sender_control, receiver_control)
    }

    fn sender_config(count: usize) -> OTSenderConfig {
        OTSenderConfigBuilder::default()
            .count(count)
            .build()
            .unwrap()
    }

    fn receiver_config(count: usize) -> OTReceiverConfig {
        OTReceiverConfigBuilder::default()
            .count(count)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_ot_factory() {
        let initial_count = 10;

        let sender_factory_config = SenderFactoryConfigBuilder::default()
            .initial_count(initial_count)
            .build()
            .unwrap();
        let receiver_factory_config = ReceiverFactoryConfigBuilder::default()
            .initial_count(initial_count)
            .build()
            .unwrap();

        let (mut sender_control, mut receiver_control) =
            create_setup_pair(sender_factory_config, receiver_factory_config).await;

        let instance_id = "test".to_string();
        let data: Vec<[Block; 2]> = (0..10).map(|_| [Block::new(0), Block::new(1)]).collect();
        let choices = vec![
            false, false, true, true, false, true, true, false, true, false,
        ];

        let expected: Vec<Block> = data
            .iter()
            .zip(&choices)
            .map(|(data, choice)| data[*choice as usize])
            .collect();

        let mut sender = sender_control
            .create(instance_id.clone(), sender_config(choices.len()))
            .await
            .unwrap();

        let mut receiver = receiver_control
            .create(instance_id.clone(), receiver_config(choices.len()))
            .await
            .unwrap();

        let send = async { sender.send(data).await.unwrap() };

        let receive = async {
            ObliviousReceive::<bool, Block>::receive(&mut receiver, choices)
                .await
                .unwrap()
        };

        let (_, received) = futures::join!(send, receive);

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_ot_factory_mismatch() {
        let initial_count = 10;

        let sender_factory_config = SenderFactoryConfigBuilder::default()
            .initial_count(initial_count)
            .build()
            .unwrap();
        let receiver_factory_config = ReceiverFactoryConfigBuilder::default()
            .initial_count(initial_count)
            .build()
            .unwrap();

        let (mut sender_control, mut receiver_control) =
            create_setup_pair(sender_factory_config, receiver_factory_config).await;

        let instance_id = "test".to_string();

        let _ = sender_control
            .create(instance_id.clone(), sender_config(10))
            .await
            .unwrap();

        let err = receiver_control
            .create(instance_id.clone(), receiver_config(9))
            .await;

        assert!(matches!(
            err,
            Err(OTFactoryError::SplitMismatch(
                id,
                10,
                9
            )) if id == instance_id
        ));
    }

    #[tokio::test]
    async fn test_ot_factory_many_splits() {
        let initial_count = 100;

        let sender_factory_config = SenderFactoryConfigBuilder::default()
            .initial_count(initial_count)
            .build()
            .unwrap();
        let receiver_factory_config = ReceiverFactoryConfigBuilder::default()
            .initial_count(initial_count)
            .build()
            .unwrap();

        let (mut sender_control, mut receiver_control) =
            create_setup_pair(sender_factory_config, receiver_factory_config).await;

        for id in 0..10 {
            let _ = sender_control
                .create(id.to_string(), sender_config(10))
                .await
                .unwrap();

            let _ = receiver_control
                .create(id.to_string(), receiver_config(10))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_ot_factory_committed_ot() {
        let split_count = 3;
        let split_size = 10;

        let sender_factory_config = SenderFactoryConfigBuilder::default()
            .initial_count(split_count * split_size)
            .committed()
            .build()
            .unwrap();
        let receiver_factory_config = ReceiverFactoryConfigBuilder::default()
            .initial_count(split_count * split_size)
            .committed()
            .build()
            .unwrap();

        let (mut sender_control, receiver_control) =
            create_setup_pair(sender_factory_config, receiver_factory_config).await;

        let mut handles = Vec::with_capacity(split_count);

        for id in 0..split_count {
            {
                let mut sender_control = sender_control.clone();
                let mut receiver_control = receiver_control.clone();

                handles.push(tokio::spawn(async move {
                    let mut sender = sender_control
                        .create(id.to_string(), sender_config(split_size))
                        .await
                        .unwrap();

                    let mut receiver = receiver_control
                        .create(id.to_string(), receiver_config(split_size))
                        .await
                        .unwrap();

                    let messages = vec![[Block::new(420), Block::new(69)]; split_size];
                    let choices = vec![false; split_size];

                    let (send, receive) = tokio::join!(
                        sender.send(messages.clone()),
                        ObliviousReceive::<bool, Block>::receive(&mut receiver, choices)
                    );
                    send.unwrap();
                    _ = receive.unwrap();

                    sender.reveal().await.unwrap();
                    receiver.verify(messages).await.unwrap();
                }))
            }
        }

        // sleep to make sure all tasks hit the barrier
        tokio::time::sleep(Duration::from_millis(100)).await;

        // assert that the tasks haven't finished yet (they should be blocked on the barrier)
        assert!(handles.iter().any(|handle| !handle.is_finished()));

        sender_control
            .address()
            .send(Verify)
            .await
            .unwrap()
            .unwrap();

        // sleep to make sure all tasks finish
        tokio::time::sleep(Duration::from_millis(100)).await;

        for handle in handles {
            handle.await.unwrap();
        }
    }
}
