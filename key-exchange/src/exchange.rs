//! This module implements the key exchange logic

use super::{
    circuit::{COMBINE_PMS, XOR_BYTES_32},
    KeyExchangeChannel, KeyExchangeError, KeyExchangeFollow, KeyExchangeLead, KeyExchangeMessage,
    PMSLabels, PublicKey,
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
/// Can be either a leader or a follower depending on the instance of `D`, which is the return type
/// of `A`
pub struct KeyExchangeCore<PS, PR, A, D> {
    /// A channel for exchanging messages between leader and follower
    channel: KeyExchangeChannel,
    /// The sender instance for performing point addition
    point_addition_sender: PS,
    /// The receiver instance for performing point addition
    point_addition_receiver: PR,
    /// A factory used to instantiate a leader or follower of the garbled circuit dual execution
    /// protocol
    dual_ex_factory: A,
    /// The private key of the party behind this instance, either follower or leader
    private_key: Option<SecretKey>,
    /// The public key of the server
    server_key: Option<PublicKey>,
    /// Two different additive shares of the pre-master secret
    pms_shares: Option<[P256; 2]>,
    /// The config used for the key exchange protocol
    config: KeyExchangeConfig,
    /// PhantomData needed for return type of `dual_ex_factory`
    _phantom_data: std::marker::PhantomData<D>,
}

impl<PS, PR, A, D> KeyExchangeCore<PS, PR, A, D>
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
    /// * `config`                  - The config used for the key exchange protocol
    pub fn new(
        channel: KeyExchangeChannel,
        point_addition_sender: PS,
        point_addition_receiver: PR,
        dual_ex_factory: A,
        config: KeyExchangeConfig,
    ) -> Self {
        Self {
            channel,
            point_addition_sender,
            point_addition_receiver,
            dual_ex_factory,
            private_key: None,
            server_key: None,
            pms_shares: None,
            config,
            _phantom_data: std::marker::PhantomData,
        }
    }
}

impl<PS, PR, A, D> KeyExchangeCore<PS, PR, A, D>
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    A: AsyncFactory<D, Config = DualExConfig, Error = GCFactoryError> + Send,
    D: DEExecute + Send,
{
    /// Compute the additive shares of the pre-master secret, twice
    async fn compute_pms_shares_for(&mut self) -> Result<(), KeyExchangeError> {
        let server_key = &self.server_key.ok_or(KeyExchangeError::NoServerKey)?;
        let private_key = self
            .private_key
            .as_ref()
            .ok_or(KeyExchangeError::NoPrivateKey)?;

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
            self.point_addition_sender
                .compute_x_coordinate_share(encoded_point),
            self.point_addition_receiver
                .compute_x_coordinate_share(encoded_point)
        )?;

        self.pms_shares = Some([pms1, pms2]);
        Ok(())
    }

    /// Compute the PMS labels needed to compute the master secret
    ///
    /// * `role` - The role of this party in the protocol
    async fn compute_pms_labels_for(&mut self, role: Role) -> Result<PMSLabels, KeyExchangeError> {
        let mut rng = ChaCha20Rng::from_entropy();

        // PMS shares have to be already computed in order to continue
        let [pms_share1, pms_share2] = self.pms_shares.ok_or(KeyExchangeError::NoPMSShares)?;

        // Get the correct order for the input gates, depending on the role
        let input_gates_order = role.input_gates_order();

        // Set up dual execution instance and circuit for the PMS circuit
        let dual_ex_pms = {
            let mut config_builder_pms = DualExConfigBuilder::default();

            config_builder_pms.circ(Arc::clone(&COMBINE_PMS));
            config_builder_pms.id(format!("{}/pms", self.config.id));
            let config_pms = config_builder_pms.build()?;

            self.dual_ex_factory
                .create(format!("{}/pms", self.config.id), config_pms)
                .await?
        };

        // Prepare circuit inputs
        let input0 = COMBINE_PMS
            .input(input_gates_order[0])?
            .to_value(pms_share1.to_le_bytes())?;

        let input1 = COMBINE_PMS
            .input(input_gates_order[1])?
            .to_value(pms_share2.to_le_bytes())?;
        let input2 = COMBINE_PMS.input(input_gates_order[2])?;
        let input3 = COMBINE_PMS.input(input_gates_order[3])?;

        let const_input0 = COMBINE_PMS.input(4)?.to_value(Value::ConstZero)?;
        let const_input1 = COMBINE_PMS.input(5)?.to_value(Value::ConstOne)?;

        // Generate the full labels for the circuit
        let full_labels = FullInputSet::generate(&mut rng, &COMBINE_PMS, None);

        // Execute the pms circuit in dual execution, but without performing the equality check
        //
        // This will give us the labels without output decoding information, which we want to
        // return in the end, so that they can be reused for the computation of the master secret.
        //
        // The output of this circuit is (A + B, C + D) = (PMS1, PMS2), but we only receive the
        // labels for this.
        let summary = dual_ex_pms
            .execute_skip_equality_check(
                full_labels,
                vec![input0.clone(), input1.clone(), const_input0, const_input1],
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

        // We need to apply some transformations, so that this can be used as input for the XOR circuit later
        let active_encoded_input = active_output
            .clone()
            .into_iter()
            .enumerate()
            .map(|(k, x)| x.to_input(XOR_BYTES_32.input(k).unwrap()))
            .collect::<Result<Vec<Encoded<Input, Active>>, EncodingError>>()?;

        let full_encoded_input = full_output
            .clone()
            .into_iter()
            .enumerate()
            .map(|(k, x)| x.to_input(XOR_BYTES_32.input(k).unwrap()))
            .collect::<Result<Vec<Encoded<Input, Full>>, EncodingError>>()?;

        let full_encoded_input = EncodedSet::<Input, Full>::new(full_encoded_input)?;

        // Now we use the output of the first circuit (PMS1, PMS2) as cached inputs for the XOR
        // circuit and execute it in full dual execution.
        //
        // This circuit returns PMS1 ^ PMS2, which we expect to be equal to 0, if both parties have
        // been honest.

        // Set up dual execution instance and circuit for the XOR circuit
        let dual_ex_xor = {
            let mut config_builder_xor = DualExConfigBuilder::default();

            config_builder_xor.circ(Arc::clone(&XOR_BYTES_32));
            config_builder_xor.id(format!("{}/xor", self.config.id));
            let config_xor = config_builder_xor.build()?;

            self.dual_ex_factory
                .create(format!("{}/xor", self.config.id), config_xor)
                .await?
        };

        // Perform full dual execution of XOR circuit
        let output = dual_ex_xor
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
        // We only need half the labels because we only need one of the two PMS values (which we
        // know are equal to each other)
        // Since, there are only 2 output labels, we can just take the first one
        let active_labels = active_output
            .into_iter()
            .next()
            .expect("Should be able to return first group of output labels for this circuit")
            .into_labels();

        let full_labels = full_output
            .into_iter()
            .next()
            .expect("Should be able to return first group of output labels for this circuit")
            .into_labels();

        Ok(PMSLabels {
            active_labels,
            full_labels,
        })
    }
}

#[async_trait]
impl<PS, PR, A, B, LSF, LRF, LS, LR> KeyExchangeLead
    for KeyExchangeCore<PS, PR, A, DualExLeader<Initialized, B, LSF, LRF, LS, LR>>
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
            KeyExchangeMessage::FollowerPublicKey,
            KeyExchangeError::Unexpected
        )?;
        let follower_public_key: PublicKey = message.try_into()?;

        // Combine public keys
        let leader_public_key = leader_private_key.public_key();
        let client_public_key = PublicKey::from_affine(
            (leader_public_key.to_projective() + follower_public_key.to_projective()).to_affine(),
        )?;

        self.private_key = Some(leader_private_key);
        Ok(client_public_key)
    }

    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError> {
        // Send server's public key to follower
        let message = KeyExchangeMessage::ServerPublicKey(server_key.into());
        self.channel.send(message).await?;

        self.server_key = Some(server_key);
        Ok(())
    }

    async fn compute_pms_shares(&mut self) -> Result<(), KeyExchangeError> {
        self.compute_pms_shares_for().await
    }

    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError> {
        self.compute_pms_labels_for(Role::Leader).await
    }
}

#[async_trait]
impl<PS, PR, A, B, LSF, LRF, LS, LR> KeyExchangeFollow
    for KeyExchangeCore<PS, PR, A, DualExFollower<Initialized, B, LSF, LRF, LS, LR>>
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
        let message = KeyExchangeMessage::FollowerPublicKey(public_key.into());
        self.channel.send(message).await?;

        self.private_key = Some(follower_private_key);
        Ok(())
    }

    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError> {
        // Receive server's public key from leader
        let message = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::ServerPublicKey,
            KeyExchangeError::Unexpected
        )?;
        let server_key = message.try_into()?;

        self.server_key = Some(server_key);
        Ok(())
    }

    async fn compute_pms_shares(&mut self) -> Result<(), KeyExchangeError> {
        self.compute_pms_shares_for().await
    }

    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError> {
        self.compute_pms_labels_for(Role::Follower).await
    }
}

/// A config used in the key exchange protocol
#[derive(Debug, Clone)]
pub struct KeyExchangeConfig {
    id: String,
}

impl KeyExchangeConfig {
    /// Create a new config
    pub fn new(id: String) -> Self {
        Self { id }
    }

    /// Get the id of this instance
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// The role of the instance, either `Leader` or `Follower`
#[derive(Clone, Copy, Debug)]
pub enum Role {
    Leader,
    Follower,
}

impl Role {
    /// Get the correct order of input gate for this role
    const fn input_gates_order(&self) -> [usize; 4] {
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
        mock::{create_mock_key_exchange_pair, MockKeyExchangeFollower, MockKeyExchangeLeader},
        KeyExchangeError,
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

        assert_eq!(leader.private_key.unwrap(), leader_private_key);
        assert_eq!(follower.private_key.unwrap(), follower_private_key);

        assert_eq!(leader.server_key.unwrap(), server_public_key);
        assert_eq!(follower.server_key.unwrap(), server_public_key);

        assert_eq!(client_public_key, expected_client_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms_share() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower, client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        tokio::try_join!(leader.compute_pms_shares(), follower.compute_pms_shares()).unwrap();

        let [l_pms1, l_pms2] = leader.pms_shares.unwrap();
        let [f_pms1, f_pms2] = follower.pms_shares.unwrap();

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

        let (mut leader, mut follower, _client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        tokio::try_join!(leader.compute_pms_shares(), follower.compute_pms_shares()).unwrap();

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

        let (mut leader, mut follower, _client_public_key) = perform_key_exchange(
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        tokio::try_join!(leader.compute_pms_shares(), follower.compute_pms_shares()).unwrap();

        // Mutate one share so that check should fail
        if let Some(ref mut shares) = leader.pms_shares {
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
}
