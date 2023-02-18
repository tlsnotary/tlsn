use super::state::KeyExchangeSetup;
use crate::{
    circuit::{build_double_combine_pms_circuit, build_nbit_xor_bytes_32},
    msg::{NotaryPublicKey, ServerPublicKey},
    state::{PMSComputationSetup, State},
    ComputePMS, KeyExchangeChannel, KeyExchangeError, KeyExchangeFollow, KeyExchangeLead,
    KeyExchangeMessage, PMSLabels, PublicKey,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_aio::protocol::{
    garble::{
        exec::dual::{state::Initialized, DEExecute, DualExFollower, DualExLeader},
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

pub struct KeyExchangeCore<S: State + Send> {
    channel: KeyExchangeChannel,
    state: S,
}

impl<P, A, D> KeyExchangeCore<KeyExchangeSetup<P, A, D>>
where
    P: PointAddition + Send,
    A: AsyncFactory<D, Config = DualExConfig, Error = OTFactoryError> + Send,
    D: DEExecute + Send,
{
    /// Creates a new KeyExchangeCore
    pub fn new(
        channel: KeyExchangeChannel,
        point_addition_sender: P,
        point_addition_receiver: P,
        dual_ex_factory: A,
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
            },
        }
    }

    /// Setup KeyExchangeCore for PMS computation
    pub async fn setup_pms_computation(
        mut self,
        id: String,
    ) -> Result<KeyExchangeCore<PMSComputationSetup<P, D>>, KeyExchangeError> {
        let mut config_builder_pms = DualExConfigBuilder::default();
        let mut config_builder_xor = DualExConfigBuilder::default();

        let circuit_pms = build_double_combine_pms_circuit();
        let circuit_xor = build_nbit_xor_bytes_32();

        config_builder_pms.circ(Arc::clone(&circuit_pms));
        config_builder_pms.id(id.clone());

        config_builder_xor.circ(Arc::clone(&circuit_xor));
        config_builder_xor.id(id.clone());

        let config_pms = config_builder_pms.build().unwrap();
        let config_xor = config_builder_pms.build().unwrap();

        let dual_ex_pms = self
            .state
            .dual_ex_factory
            .create(format!("{}/pms", id), config_pms)
            .await?;
        let dual_ex_xor = self
            .state
            .dual_ex_factory
            .create(format!("{}/pms", id), config_xor)
            .await?;

        let private_key = self
            .state
            .private_key
            .ok_or(KeyExchangeError::NoPrivateKey)?;
        let server_key = self.state.server_key.ok_or(KeyExchangeError::NoServerKey)?;

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
            },
        })
    }
}

#[async_trait]
impl<P, A, B, LSF, LRF, LS, LR> KeyExchangeLead
    for KeyExchangeCore<KeyExchangeSetup<P, A, DualExLeader<Initialized, B, LSF, LRF, LS, LR>>>
where
    P: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    A: AsyncFactory<
            DualExLeader<Initialized, B, LSF, LRF, LS, LR>,
            Config = DualExConfig,
            Error = OTFactoryError,
        > + Send,
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    async fn send_client_key(
        &mut self,
        leader_private_key: SecretKey,
    ) -> Result<PublicKey, KeyExchangeError> {
        let message = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::NotaryPublicKey,
            KeyExchangeError::Unexpected
        )?;

        let public_key = leader_private_key.public_key();
        let client_public_key = PublicKey::from_affine(
            (public_key.to_projective() + message.notary_key.to_projective()).to_affine(),
        )?;

        self.state.private_key = Some(leader_private_key);
        Ok(client_public_key)
    }

    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError> {
        let message = KeyExchangeMessage::ServerPublicKey(ServerPublicKey { server_key });
        self.channel.send(message).await?;

        self.state.server_key = Some(server_key);
        Ok(())
    }
}

#[async_trait]
impl<P, A, B, LSF, LRF, LS, LR> KeyExchangeFollow
    for KeyExchangeCore<KeyExchangeSetup<P, A, DualExFollower<Initialized, B, LSF, LRF, LS, LR>>>
where
    P: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    A: AsyncFactory<
            DualExFollower<Initialized, B, LSF, LRF, LS, LR>,
            Config = DualExConfig,
            Error = OTFactoryError,
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
        let public_key = follower_private_key.public_key();
        let message = KeyExchangeMessage::NotaryPublicKey(NotaryPublicKey {
            notary_key: public_key,
        });

        self.channel.send(message).await?;
        self.state.private_key = Some(follower_private_key);
        Ok(())
    }

    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError> {
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
impl<P, D> ComputePMS for KeyExchangeCore<PMSComputationSetup<P, D>>
where
    P: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send,
    D: DEExecute + Send,
{
    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError> {
        let server_key = &self.state.server_key;
        let private_key = &self.state.private_key;

        // We need to mimic the ecdh::p256::diffie-hellman function without the `SharedSecret`
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
        // Compute circuit input
        let [pms_share1, pms_share2] =
            self.state.pms_shares.ok_or(KeyExchangeError::NoPMSShares)?;

        let mut rng = ChaCha20Rng::from_entropy();

        let leader_input1 = self
            .state
            .circuit_pms
            .input(0)
            .unwrap()
            .to_value(pms_share1.to_le_bytes())
            .unwrap();
        let follower_input1 = self.state.circuit_pms.input(1).unwrap();

        let leader_input2 = self
            .state
            .circuit_pms
            .input(2)
            .unwrap()
            .to_value(pms_share2.to_le_bytes())
            .unwrap();
        let follower_input2 = self.state.circuit_pms.input(3).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &self.state.circuit_pms, None);

        let summary = self
            .state
            .dual_ex_pms
            .execute_skip_equality_check(
                leader_labels,
                vec![leader_input1.clone(), leader_input2.clone()],
                vec![follower_input1.clone(), follower_input2.clone()],
                vec![leader_input1.clone(), leader_input2.clone()],
                vec![],
            )
            .await?;

        let active_output_labels = summary.get_evaluator_summary().output_labels();
        let full_output_labels = summary.get_generator_summary().output_labels();

        let active_encoded_input = active_output_labels
            .clone()
            .to_inner()
            .into_iter()
            .enumerate()
            .map(|(k, x)| x.to_input(self.state.circuit_xor.input(k).unwrap()))
            .collect::<Result<Vec<Encoded<Input, Active>>, EncodingError>>()
            .unwrap();

        let full_encoded_input = full_output_labels
            .clone()
            .to_inner()
            .into_iter()
            .enumerate()
            .map(|(k, x)| x.to_input(self.state.circuit_xor.input(k).unwrap()))
            .collect::<Result<Vec<Encoded<Input, Full>>, EncodingError>>()
            .unwrap();
        let full_encoded_input = EncodedSet::<Input, Full>::new(full_encoded_input).unwrap();

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

        let (Value::Bytes(sub_output), Value::Bool(carry)) = (output[0].value(), output[1].value()) else {
            panic!("Unexpected output type");
        };

        if *sub_output != vec![0_u8; 32] || *carry {
            return Err(KeyExchangeError::CheckFailed);
        }

        let active_labels = active_output_labels
            .clone()
            .to_inner()
            .into_iter()
            .map(|x| x.into_labels())
            .collect::<Vec<Labels<Active>>>();

        let full_labels = full_output_labels
            .clone()
            .to_inner()
            .into_iter()
            .map(|x| x.into_labels())
            .collect::<Vec<Labels<Full>>>();

        Ok(PMSLabels {
            active_labels,
            full_labels,
        })
    }
}
