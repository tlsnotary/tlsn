pub mod receiver;
pub mod sender;

use super::{OTChannel, ObliviousReceive, ObliviousSend};

#[cfg(test)]
mod tests {
    use crate::protocol::ot::{
        ObliviousAcceptCommit, ObliviousCommit, ObliviousReveal, ObliviousVerify,
    };

    use super::{
        receiver::Kos15IOReceiver, sender::Kos15IOSender, ObliviousReceive, ObliviousSend,
    };
    use mpc_core::{msgs::ot::OTMessage, Block};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use utils_aio::duplex::DuplexChannel;

    const ITERATIONS: usize = 1024;

    #[tokio::test]
    async fn test_kos_random() {
        let choices = [vec![false; ITERATIONS / 2], vec![true; ITERATIONS / 2]].concat();
        let choices_clone = choices.clone();

        let blocks = vec![[Block::new(0), Block::new(1)]; ITERATIONS];

        let (channel, channel_2) = DuplexChannel::<OTMessage>::new();
        let (sender, receiver) = (
            Kos15IOSender::new(Box::new(channel)),
            Kos15IOReceiver::new(Box::new(channel_2)),
        );
        let send = tokio::spawn(async {
            let mut sender = sender.rand_setup(ITERATIONS).await.unwrap();
            sender.send(blocks).await.unwrap();
        });
        let receive: tokio::task::JoinHandle<Vec<Block>> = tokio::spawn(async move {
            let mut receiver = receiver.rand_setup(ITERATIONS).await.unwrap();
            receiver.receive(choices).await.unwrap()
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

    #[tokio::test]
    async fn test_kos_random_multi_block() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let choices = vec![false, true, true, false];
        let msgs: Vec<[[Block; 2]; 2]> = (0..choices.len())
            .map(|_| {
                let msg_0 = [Block::random(&mut rng), Block::random(&mut rng)];
                let msg_1 = [Block::random(&mut rng), Block::random(&mut rng)];
                [msg_0, msg_1]
            })
            .collect();

        let (channel, channel_2) = DuplexChannel::<OTMessage>::new();
        let (sender, receiver) = (
            Kos15IOSender::new(Box::new(channel)),
            Kos15IOReceiver::new(Box::new(channel_2)),
        );

        let sender_fut = {
            let len = choices.len();
            let msgs = msgs.clone();
            async move {
                let mut sender = sender.rand_setup(len).await.unwrap();
                sender.send(msgs).await.unwrap();
            }
        };

        let receiver_fut = {
            let choices = choices.clone();
            async move {
                let mut receiver = receiver.rand_setup(choices.len()).await.unwrap();
                let msgs: Vec<[Block; 2]> = receiver.receive(choices).await.unwrap();
                msgs
            }
        };

        let (_, received) = tokio::join!(sender_fut, receiver_fut);

        let expected: Vec<[Block; 2]> = choices
            .into_iter()
            .zip(msgs.iter())
            .map(|(c, m)| m[c as usize])
            .collect();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_kos_verify() {
        let choices = [vec![false; ITERATIONS / 2], vec![true; ITERATIONS / 2]].concat();
        let choices_clone = choices.clone();

        let blocks = vec![[Block::new(0), Block::new(1)]; ITERATIONS];
        let blocks_clone = blocks.clone();

        let (channel, channel_2) = DuplexChannel::<OTMessage>::new();
        let (mut sender, mut receiver) = (
            Kos15IOSender::new(Box::new(channel)),
            Kos15IOReceiver::new(Box::new(channel_2)),
        );
        let send = tokio::spawn(async {
            sender.commit().await.unwrap();
            let mut sender = sender.rand_setup(ITERATIONS).await.unwrap();
            sender.send(blocks_clone).await.unwrap();
            sender.reveal().await.unwrap();
        });
        let receive = tokio::spawn(async move {
            receiver.accept_commit().await.unwrap();
            let mut receiver = receiver.rand_setup(ITERATIONS).await.unwrap();
            let ot_output: Vec<Block> = receiver.receive(choices).await.unwrap();
            let verification = receiver.verify(blocks).await;
            (ot_output, verification)
        });

        let (_, output) = tokio::join!(send, receive);
        let (ot_output, verification) = output.unwrap();
        assert!(verification.is_ok());
        assert_eq!(
            ot_output,
            choices_clone
                .iter()
                .map(|c| Block::new(*c as u128))
                .collect::<Vec<Block>>()
        )
    }
}
