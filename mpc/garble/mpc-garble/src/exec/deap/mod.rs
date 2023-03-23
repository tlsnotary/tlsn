mod deferred;
mod follower;
mod leader;

pub use deferred::{DeferredDEAPFollower, DeferredDEAPLeader};
pub use follower::{state as follower_state, DEAPFollower};
pub use leader::{state as leader_state, DEAPLeader};

// Use same setup procedure as standard dualex
pub(crate) use super::dual::setup_inputs_with;

#[cfg(feature = "mock")]
pub mod mock {
    use super::*;
    use crate::backend::GarbleBackend;
    use mpc_core::Block;
    use mpc_garble_core::{exec::dual::DualExConfig, msgs::GarbleMessage};
    use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
    use utils_aio::duplex::DuplexChannel;

    pub type MockDEAPLeader = DEAPLeader<
        leader_state::Initialized,
        GarbleBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;
    pub type MockDEAPFollower = DEAPFollower<
        follower_state::Initialized,
        GarbleBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;

    pub fn mock_deap_pair(config: DualExConfig) -> (MockDEAPLeader, MockDEAPFollower) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let ot_factory = MockOTFactory::new();

        let leader = DEAPLeader::new(
            config.clone(),
            Box::new(leader_channel),
            GarbleBackend,
            ot_factory.clone(),
            ot_factory.clone(),
        );

        let follower = DEAPFollower::new(
            config,
            Box::new(follower_channel),
            GarbleBackend,
            ot_factory.clone(),
            ot_factory,
        );

        (leader, follower)
    }
}

#[cfg(test)]
mod tests {
    use crate::exec::dual::DEExecute;

    use super::*;
    use mock::*;
    use mpc_circuits::{WireGroup, ADDER_64};
    use mpc_garble_core::{exec::dual::DualExConfigBuilder, FullInputSet};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_deap() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = ADDER_64.clone();

        let config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();
        let (leader, follower) = mock_deap_pair(config);

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &circ, None);
        let follower_labels = FullInputSet::generate(&mut rng, &circ, None);

        let leader_task = {
            let leader_input = leader_input.clone();
            let follower_input = follower_input.clone();
            tokio::spawn(async move {
                leader
                    .execute(
                        leader_labels,
                        vec![leader_input.clone()],
                        vec![follower_input.group().clone()],
                        vec![leader_input.clone()],
                        vec![],
                    )
                    .await
                    .unwrap()
            })
        };

        let follower_task = tokio::spawn(async move {
            follower
                .execute(
                    follower_labels,
                    vec![follower_input.clone()],
                    vec![leader_input.group().clone()],
                    vec![follower_input],
                    vec![],
                )
                .await
                .unwrap()
        });

        let (leader_out, follower_out) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_out = leader_out.unwrap();
        let follower_out = follower_out.unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
