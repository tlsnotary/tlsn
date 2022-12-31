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
    use mpc_core::garble::FullInputLabels;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_deap() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (leader, follower) = mock_deap_pair();

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_circ = circ.clone();
        let leader_task = tokio::spawn(async move {
            let (input_labels, delta) = FullInputLabels::generate_set(
                &mut ChaCha12Rng::seed_from_u64(0),
                &leader_circ,
                None,
            );
            let (leader_output, leader) = leader
                .execute(leader_circ, &[leader_input], &input_labels, delta)
                .await
                .unwrap();
            leader.verify().await.unwrap();
            leader_output
        });

        let follower_circ = circ.clone();
        let follower_task = tokio::spawn(async move {
            let (input_labels, delta) = FullInputLabels::generate_set(
                &mut ChaCha12Rng::seed_from_u64(1),
                &follower_circ,
                None,
            );
            let (follower_output, follower) = follower
                .execute(follower_circ, &[follower_input], &input_labels, delta)
                .await
                .unwrap();
            follower.verify().await.unwrap();
            follower_output
        });

        let (leader_gc_evaluated, follower_gc_evaluated) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_out = leader_gc_evaluated.unwrap();
        let follower_out = follower_gc_evaluated.unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
