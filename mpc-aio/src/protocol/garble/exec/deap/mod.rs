mod follower;
mod leader;

pub use follower::{state as follower_state, DEAPFollower};
pub use leader::{state as leader_state, DEAPLeader};

#[cfg(feature = "mock")]
mod mock {
    use super::*;
    use crate::protocol::{
        garble::backend::RayonBackend,
        ot::mock::{mock_ot_pair, MockOTReceiver, MockOTSender},
    };
    use mpc_core::{msgs::garble::GarbleMessage, Block};
    use utils_aio::duplex::DuplexChannel;

    pub fn mock_deap_pair() -> (
        DEAPLeader<
            leader_state::Initialized,
            RayonBackend,
            MockOTSender<Block>,
            MockOTReceiver<Block>,
        >,
        DEAPFollower<
            follower_state::Initialized,
            RayonBackend,
            MockOTSender<Block>,
            MockOTReceiver<Block>,
        >,
    ) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();

        let leader = DEAPLeader::new(
            Box::new(leader_channel),
            RayonBackend,
            leader_sender,
            leader_receiver,
        );
        let follower = DEAPFollower::new(
            Box::new(follower_channel),
            RayonBackend,
            follower_sender,
            follower_receiver,
        );
        (leader, follower)
    }
}

#[cfg(feature = "mock")]
pub use mock::mock_deap_pair;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use mpc_core::garble::config::GarbleConfigBuilder;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_deap() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (leader, follower) = mock_deap_pair();

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();
        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_circ = circ.clone();
        let leader_task = tokio::spawn(async move {
            let config = GarbleConfigBuilder::default_dual_with_rng(
                &mut ChaCha12Rng::seed_from_u64(0),
                leader_circ,
            )
            .build()
            .unwrap();

            let (leader_output, leader) = leader.execute(config, vec![leader_input]).await.unwrap();
            leader.verify().await.unwrap();
            leader_output
        });

        let follower_circ = circ.clone();
        let follower_task = tokio::spawn(async move {
            let config = GarbleConfigBuilder::default_dual_with_rng(
                &mut ChaCha12Rng::seed_from_u64(0),
                follower_circ,
            )
            .build()
            .unwrap();

            let (follower_output, follower) = follower
                .execute(config, vec![follower_input])
                .await
                .unwrap();
            follower.verify().await.unwrap();
            follower_output
        });

        let (leader_gc_evaluated, follower_gc_evaluated) = tokio::join!(leader_task, follower_task);

        let leader_out = leader_gc_evaluated.unwrap();
        let follower_out = follower_gc_evaluated.unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
