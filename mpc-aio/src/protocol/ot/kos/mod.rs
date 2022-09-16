pub mod receiver;
pub mod sender;

use super::{OTChannel, ObliviousReceive, ObliviousSend};

#[cfg(test)]
mod tests {
    use super::{
        receiver::Kos15IOReceiver, sender::Kos15IOSender, ObliviousReceive, ObliviousSend,
    };
    use crate::protocol::duplex::DuplexChannel;
    use mpc_core::{msgs::ot::OTMessage, Block};

    const ITERATIONS: usize = 1024;

    #[tokio::test]
    async fn test_mpc_aio_kos_random() {
        let choices = [vec![false; ITERATIONS / 2], vec![true; ITERATIONS / 2]].concat();
        let choices_clone = choices.clone();

        let blocks = vec![[Block::new(0), Block::new(1)]; ITERATIONS];

        let (channel, channel_2) = DuplexChannel::<OTMessage>::new();
        let (sender, receiver) = (
            Kos15IOSender::new(Box::pin(channel)),
            Kos15IOReceiver::new(Box::pin(channel_2)),
        );
        let send = tokio::spawn(async {
            let mut sender = sender.rand_setup().await.unwrap();
            sender.send(blocks).await.unwrap();
        });
        let receive = tokio::spawn(async move {
            let mut receiver = receiver.rand_setup(ITERATIONS).await.unwrap();
            receiver.receive(&choices).await.unwrap()
        });

        let (_, output) = tokio::join!(send, receive);
        assert_eq!(
            output.unwrap(),
            choices_clone
                .iter()
                .map(|c| Block::new(*c as u128))
                .collect::<Vec<Block>>()
        )
    }
}
