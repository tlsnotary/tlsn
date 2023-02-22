//! This module implements the key exchange logic

use super::{
    circuit::{build_double_combine_pms_circuit, build_nbit_xor_bytes_32},
    msg::{NotaryPublicKey, ServerPublicKey},
    state::{KeyExchangeSetup, PMSComputationSetup, State},
    ComputePMS, KeyExchangeChannel, KeyExchangeError, KeyExchangeFollow, KeyExchangeLead,
    KeyExchangeMessage, PMSLabels, PublicKey,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_aio::protocol::{
    garble::{
        exec::dual::{state::Initialized, DEExecute, DualExFollower, DualExLeader},
        factory::GCFactoryError,
        Evaluator, Generator,
    },
    ot::{OTFactoryError, ObliviousReceive, ObliviousSend},
};
use mpc_circuits::{Input, InputValue, Value, WireGroup};
use mpc_core::{
    garble::{
        exec::dual::{DualExConfig, DualExConfigBuilder},
        label_state::{Active, Full},
        ActiveEncodedInput, Encoded, EncodedSet, EncodingError, FullEncodedInput, FullInputSet,
        Labels,
    },
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use p256::{EncodedPoint, SecretKey};
use point_addition::PointAddition;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use share_conversion_core::fields::{p256::P256, Field};
use std::{borrow::Borrow, sync::Arc};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

/// The instance for performing the key exchange protocol
///
/// Can be either a leader or a follower depending on the role
pub struct KeyExchangeCore<S: State + Send> {
    channel: KeyExchangeChannel,
    state: S,
}

impl<PS, PR, A, D> KeyExchangeCore<KeyExchangeSetup<PS, PR, A, D>>
where
    PS: PointAddition + Send,
    PR: PointAddition + Send,
    A: AsyncFactory<D, Config = DualExConfig, Error = GCFactoryError> + Send,
    D: DEExecute + Send,
{
    /// Creates a new [KeyExchangeCore]
    ///
    /// * `channel`                 - The channel for sending messages between leader and follower
    /// * `point_addition_sender`   - The point addition sender instance used during key exchange
    /// * `point_addition_receiver` - The point addition receiver instance used during key exchange
    /// * `dual_ex_factory`         - The garbled circuit dual execution factory for creating dual execution instances
    /// * `role`                    - The role of this instance during key exchange, either leader or follower
    pub fn new(
        channel: KeyExchangeChannel,
        point_addition_sender: PS,
        point_addition_receiver: PR,
        dual_ex_factory: A,
        role: Role,
    ) -> Self {
        Self {
            channel,
            state: KeyExchangeSetup {
                point_addition_sender,
                point_addition_receiver,
                dual_ex_factory,
                private_key: None,
                server_key: None,
                _phantom_data: std::marker::PhantomData,
                role,
            },
        }
    }

    /// Set up [KeyExchangeCore] for computation of PMS shares and labels
    ///
    /// This method will do the necessary preparation to allow leader and follower to compute the
    /// PMS shares and labels. It is necessary that the key exchange has taken place before.
    ///
    /// * `id` - The id used for the dual execution instances
    pub async fn setup_pms_computation(
        mut self,
        id: String,
    ) -> Result<KeyExchangeCore<PMSComputationSetup<PS, PR, D>>, KeyExchangeError> {
        // Set up dual execution instances and circuits
        let mut config_builder_pms = DualExConfigBuilder::default();
        let mut config_builder_xor = DualExConfigBuilder::default();

        let circuit_pms = build_double_combine_pms_circuit();
        let circuit_xor = build_nbit_xor_bytes_32();

        config_builder_pms.circ(Arc::clone(&circuit_pms));
        config_builder_pms.id(format!("{}/pms", id));

        config_builder_xor.circ(Arc::clone(&circuit_xor));
        config_builder_xor.id(format!("{}/xor", id));

        let config_pms = config_builder_pms.build()?;
        let config_xor = config_builder_xor.build()?;

        let dual_ex_pms = self
            .state
            .dual_ex_factory
            .create(format!("{}/pms", id), config_pms)
            .await?;
        let dual_ex_xor = self
            .state
            .dual_ex_factory
            .create(format!("{}/xor", id), config_xor)
            .await?;

        // Check that the key exchange has taken place
        let private_key = self
            .state
            .private_key
            .ok_or(KeyExchangeError::NoPrivateKey)?;
        let server_key = self.state.server_key.ok_or(KeyExchangeError::NoServerKey)?;

        // Return the new instance prepared for PMS computation
        Ok(KeyExchangeCore {
            channel: self.channel,
            state: PMSComputationSetup {
                point_addition_sender: self.state.point_addition_sender,
                point_addition_receiver: self.state.point_addition_receiver,
                private_key,
                server_key,
                pms_shares: None,
                dual_ex_pms,
                dual_ex_xor,
                circuit_pms,
                circuit_xor,
                role: self.state.role,
            },
        })
    }
}

#[async_trait]
impl<PS, PR, A, B, LSF, LRF, LS, LR> KeyExchangeLead
    for KeyExchangeCore<KeyExchangeSetup<PS, PR, A, DualExLeader<Initialized, B, LSF, LRF, LS, LR>>>
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    A: AsyncFactory<
            DualExLeader<Initialized, B, LSF, LRF, LS, LR>,
            Config = DualExConfig,
            Error = GCFactoryError,
        > + Send,
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    async fn compute_client_key(
        &mut self,
        leader_private_key: SecretKey,
    ) -> Result<PublicKey, KeyExchangeError> {
        // Receive public key from follower
        let message = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::NotaryPublicKey,
            KeyExchangeError::Unexpected
        )?;

        // Combine public keys
        let public_key = leader_private_key.public_key();
        let client_public_key = PublicKey::from_affine(
            (public_key.to_projective() + message.notary_key.to_projective()).to_affine(),
        )?;

        self.state.private_key = Some(leader_private_key);
        Ok(client_public_key)
    }

    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError> {
        // Send server's public key to follower
        let message = KeyExchangeMessage::ServerPublicKey(ServerPublicKey { server_key });
        self.channel.send(message).await?;

        self.state.server_key = Some(server_key);
        Ok(())
    }
}

#[async_trait]
impl<PS, PR, A, B, LSF, LRF, LS, LR> KeyExchangeFollow
    for KeyExchangeCore<
        KeyExchangeSetup<PS, PR, A, DualExFollower<Initialized, B, LSF, LRF, LS, LR>>,
    >
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    A: AsyncFactory<
            DualExFollower<Initialized, B, LSF, LRF, LS, LR>,
            Config = DualExConfig,
            Error = GCFactoryError,
        > + Send,
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    async fn send_public_key(
        &mut self,
        follower_private_key: SecretKey,
    ) -> Result<(), KeyExchangeError> {
        // Send public key to leader
        let public_key = follower_private_key.public_key();
        let message = KeyExchangeMessage::NotaryPublicKey(NotaryPublicKey {
            notary_key: public_key,
        });
        self.channel.send(message).await?;

        self.state.private_key = Some(follower_private_key);
        Ok(())
    }

    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError> {
        // Receive server's public key from leader
        let message = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::ServerPublicKey,
            KeyExchangeError::Unexpected
        )?;

        self.state.server_key = Some(message.server_key);
        Ok(())
    }
}

#[async_trait]
impl<PS, PR, D> ComputePMS for KeyExchangeCore<PMSComputationSetup<PS, PR, D>>
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    D: DEExecute + Send,
{
    async fn compute_pms_shares(&mut self) -> Result<(), KeyExchangeError> {
        let server_key = &self.state.server_key;
        let private_key = &self.state.private_key;

        // Compute the leader's/follower's share of the pre-master secret
        //
        // We need to mimic the [ecdh::p256::diffie-hellman] function without the `SharedSecret`
        // wrapper, because this makes it harder to get the result as an EC curve point.
        let shared_secret = {
            let public_projective = server_key.to_projective();
            (public_projective * private_key.to_nonzero_scalar().borrow().as_ref()).to_affine()
        };

        let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);
        let (pms1, pms2) = futures::try_join!(
            self.state
                .point_addition_sender
                .compute_x_coordinate_share(encoded_point),
            self.state
                .point_addition_receiver
                .compute_x_coordinate_share(encoded_point)
        )?;

        self.state.pms_shares = Some([pms1, pms2]);
        Ok(())
    }

    async fn compute_pms_labels(mut self) -> Result<PMSLabels, KeyExchangeError> {
        // PMS shares have to be already computed in order to continue
        let [pms_share1, pms_share2] =
            self.state.pms_shares.ok_or(KeyExchangeError::NoPMSShares)?;

        // Get the input gates in the correct order according to the role
        let input_gates = self.state.role.input_gates();

        let mut rng = ChaCha20Rng::from_entropy();

        // Prepare circuit inputs
        let input0 = self
            .state
            .circuit_pms
            .input(input_gates[0])?
            .to_value(pms_share1.to_le_bytes())?;

        let input1 = self
            .state
            .circuit_pms
            .input(input_gates[1])?
            .to_value(pms_share2.to_le_bytes())?;
        let input2 = self.state.circuit_pms.input(input_gates[2])?;
        let input3 = self.state.circuit_pms.input(input_gates[3])?;

        let const_input0 = self
            .state
            .circuit_pms
            .input(4)?
            .to_value(Value::ConstZero)?;
        let const_input1 = self.state.circuit_pms.input(5)?.to_value(Value::ConstOne)?;
        let const_input2 = self
            .state
            .circuit_pms
            .input(6)?
            .to_value(Value::ConstZero)?;
        let const_input3 = self.state.circuit_pms.input(7)?.to_value(Value::ConstOne)?;

        // Generate the full labels for the circuit
        let full_labels = FullInputSet::generate(&mut rng, &self.state.circuit_pms, None);

        // Execute the pms circuit in dual execution, but without performing the equality check
        //
        // This will give us the labels without output decoding information, which we want to
        // return in the end, so that they can be reused for the computation of the master secret.
        //
        // The output of this circuit is (A + B, C + D) = (PMS1, PMS2), but we only receive the
        // labels for this.
        let summary = self
            .state
            .dual_ex_pms
            .execute_skip_equality_check(
                full_labels,
                vec![
                    input0.clone(),
                    input1.clone(),
                    const_input0,
                    const_input1,
                    const_input2,
                    const_input3,
                ],
                vec![input2, input3],
                vec![input0, input1],
                vec![],
            )
            .await?;

        // The active and full output from the circuit execution
        let active_output = summary
            .get_evaluator_summary()
            .output_labels()
            .clone()
            .to_inner();
        let full_output = summary
            .get_generator_summary()
            .output_labels()
            .clone()
            .to_inner();

        // We need to apply some transformations, so that this can be used as input for the XOR circuit
        let active_encoded_input = active_output
            .clone()
            .into_iter()
            .enumerate()
            .map(|(k, x)| x.to_input(self.state.circuit_xor.input(k).unwrap()))
            .collect::<Result<Vec<Encoded<Input, Active>>, EncodingError>>()?;

        let full_encoded_input = full_output
            .clone()
            .into_iter()
            .enumerate()
            .map(|(k, x)| x.to_input(self.state.circuit_xor.input(k).unwrap()))
            .collect::<Result<Vec<Encoded<Input, Full>>, EncodingError>>()?;

        let full_encoded_input = EncodedSet::<Input, Full>::new(full_encoded_input)?;

        // Now we use the output of the first circuit (PMS1, PMS2) as cached inputs for the XOR
        // circuit and execute it in full dual execution.
        //
        // This circuit returns PMS1 ^ PMS2, which we expect to be equal to 0, if both parties have
        // been honest.
        let output = self
            .state
            .dual_ex_xor
            .execute(
                full_encoded_input,
                vec![],
                vec![],
                vec![],
                active_encoded_input,
            )
            .await?;

        let Value::Bytes(xor_output) = output[0].value() else {
            return Err(KeyExchangeError::UnexpectedOutputValue);
        };

        // Check that the output of the XOR circuit is equal to 0, i.e. PMS1 == PMS2
        if *xor_output != vec![0_u8; 32] {
            return Err(KeyExchangeError::CheckFailed);
        }

        // Turn output into labels and return them
        let active_labels = active_output
            .into_iter()
            .map(|x| x.into_labels())
            .collect::<Vec<Labels<Active>>>();

        let full_labels = full_output
            .into_iter()
            .map(|x| x.into_labels())
            .collect::<Vec<Labels<Full>>>();

        Ok(PMSLabels {
            active_labels,
            full_labels,
        })
    }
}

/// This struct determines the role during the key exchange protocol
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Leader,
    Follower,
}

impl Role {
    fn input_gates(&self) -> [usize; 4] {
        match self {
            Role::Leader => [0, 2, 1, 3],
            Role::Follower => [1, 3, 0, 2],
        }
    }
}

#[cfg(test)]
mod tests {
    use p256::{NonZeroScalar, PublicKey, SecretKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use share_conversion_core::fields::{p256::P256, Field};

    use super::{KeyExchangeFollow, KeyExchangeLead};
    use crate::{
        mock::{
            create_mock_key_exchange_pair, MockKeyExchangeFollower,
            MockKeyExchangeFollowerPMSSetup, MockKeyExchangeLeader, MockKeyExchangeLeaderPMSSetup,
        },
        ComputePMS, KeyExchangeError,
    };

    #[tokio::test]
    async fn test_key_exchange() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

        let (leader, follower, client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        let expected_client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        assert_eq!(leader.state.private_key.unwrap(), leader_private_key);
        assert_eq!(follower.state.private_key.unwrap(), follower_private_key);

        assert_eq!(leader.state.server_key.unwrap(), server_public_key);
        assert_eq!(follower.state.server_key.unwrap(), server_public_key);

        assert_eq!(client_public_key, expected_client_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms_share() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (leader, follower, client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        let (leader, follower) = setup_and_compute_pms_share(leader, follower).await;

        let [l_pms1, l_pms2] = leader.state.pms_shares.unwrap();
        let [f_pms1, f_pms2] = follower.state.pms_shares.unwrap();

        let expected_ecdh_x =
            p256::ecdh::diffie_hellman(server_private_key, client_public_key.as_affine());

        assert_eq!(
            expected_ecdh_x.raw_secret_bytes().to_vec(),
            (l_pms1 + f_pms1).to_be_bytes()
        );
        assert_eq!(
            expected_ecdh_x.raw_secret_bytes().to_vec(),
            (l_pms2 + f_pms2).to_be_bytes()
        );
        assert_eq!(l_pms1 + f_pms1, l_pms2 + f_pms2);
        assert_ne!(l_pms1, f_pms1);
        assert_ne!(l_pms2, f_pms2);
        assert_ne!(l_pms1, l_pms2);
        assert_ne!(f_pms1, f_pms2);
    }

    #[tokio::test]
    async fn test_compute_pms_labels() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (leader, follower, _client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        let (leader, follower) = setup_and_compute_pms_share(leader, follower).await;
        let (_pms_labels1, _pms_labels2) =
            tokio::try_join!(leader.compute_pms_labels(), follower.compute_pms_labels()).unwrap();
    }

    #[tokio::test]
    async fn test_compute_pms_labels_fail() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (leader, follower, _client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        let (mut leader, follower) = setup_and_compute_pms_share(leader, follower).await;

        // Mutate one share so that check should fail
        if let Some(ref mut shares) = leader.state.pms_shares {
            shares[0] = shares[0] + P256::one();
        }
        let err = tokio::try_join!(leader.compute_pms_labels(), follower.compute_pms_labels())
            .unwrap_err();

        assert!(matches!(err, KeyExchangeError::CheckFailed));
    }

    async fn perform_key_exchange(
        leader_private_key: SecretKey,
        follower_private_key: SecretKey,
        server_public_key: PublicKey,
    ) -> (MockKeyExchangeLeader, MockKeyExchangeFollower, PublicKey) {
        let (mut leader, mut follower) = create_mock_key_exchange_pair();

        let leader_fut = leader.compute_client_key(leader_private_key.clone());
        let follower_fut = follower.send_public_key(follower_private_key.clone());

        let (client_public_key, _) = tokio::try_join!(leader_fut, follower_fut).unwrap();

        let leader_fut = leader.set_server_key(server_public_key);
        let follower_fut = follower.receive_server_key();

        let (_, _) = tokio::try_join!(leader_fut, follower_fut).unwrap();

        (leader, follower, client_public_key)
    }

    async fn setup_and_compute_pms_share(
        leader: MockKeyExchangeLeader,
        follower: MockKeyExchangeFollower,
    ) -> (
        MockKeyExchangeLeaderPMSSetup,
        MockKeyExchangeFollowerPMSSetup,
    ) {
        let mut leader = leader
            .setup_pms_computation(String::from(""))
            .await
            .unwrap();
        let mut follower = follower
            .setup_pms_computation(String::from(""))
            .await
            .unwrap();

        let _ =
            tokio::try_join!(leader.compute_pms_shares(), follower.compute_pms_shares()).unwrap();

        (leader, follower)
    }
}
