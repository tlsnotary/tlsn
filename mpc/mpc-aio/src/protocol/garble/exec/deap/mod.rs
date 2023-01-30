mod follower;
mod leader;

pub use follower::{state as follower_state, DEAPFollower};
pub use leader::{state as leader_state, DEAPLeader};

// Use same setup procedure as standard dualex
pub(crate) use super::dual::setup_inputs_with;

#[cfg(feature = "mock")]
mod mock {
    use std::sync::Arc;

    use super::*;
    use crate::protocol::{
        garble::backend::RayonBackend,
        ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender},
    };
    use mpc_circuits::Circuit;
    use mpc_core::{garble::exec::deap::DEAPConfig, msgs::garble::GarbleMessage, Block};
    use utils_aio::duplex::DuplexChannel;

    pub type MockDEAPLeader<S> = DEAPLeader<
        S,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;
    pub type MockDEAPFollower<S> = DEAPFollower<
        S,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;

    pub fn mock_deap_pair(
        config: DEAPConfig,
        circ: Arc<Circuit>,
    ) -> (
        MockDEAPLeader<leader_state::Initialized>,
        MockDEAPFollower<follower_state::Initialized>,
    ) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let ot_factory = MockOTFactory::new();

        let leader = DEAPLeader::new(
            config.clone(),
            circ.clone(),
            Box::new(leader_channel),
            RayonBackend,
            ot_factory.clone(),
            ot_factory.clone(),
        );

        let follower = DEAPFollower::new(
            config,
            circ,
            Box::new(follower_channel),
            RayonBackend,
            ot_factory.clone(),
            ot_factory,
        );

        (leader, follower)
    }
}

#[cfg(feature = "mock")]
pub use mock::mock_deap_pair;

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use mpc_core::garble::{exec::deap::DEAPConfigBuilder, FullInputSet};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_deap() {
        let config = DEAPConfigBuilder::default()
            .id("test".to_string())
            .build()
            .unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (leader, follower) = mock_deap_pair(config, circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &circ, None);
        let follower_labels = FullInputSet::generate(&mut rng, &circ, None);

        let leader_task = {
            let leader_input = leader_input.clone();
            let follower_input = follower_input.clone();
            tokio::spawn(async move {
                let (output, leader) = leader
                    .setup_inputs(
                        leader_labels,
                        vec![leader_input.clone()],
                        vec![follower_input.group().clone()],
                        vec![leader_input.clone()],
                        vec![],
                    )
                    .await
                    .unwrap()
                    .execute()
                    .await
                    .unwrap();
                leader.verify().await.unwrap();
                output
            })
        };

        let follower_task = tokio::spawn(async move {
            let (output, follower) = follower
                .setup_inputs(
                    follower_labels,
                    vec![follower_input.clone()],
                    vec![leader_input.group().clone()],
                    vec![follower_input],
                    vec![],
                )
                .await
                .unwrap()
                .execute()
                .await
                .unwrap();
            follower.verify().await.unwrap();
            output
        });

        let (leader_out, follower_out) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_out = leader_out.unwrap();
        let follower_out = follower_out.unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
