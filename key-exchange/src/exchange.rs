use super::{state::KeyExchangeSetup, PMSLabels};
use crate::{
    msg::{NotaryPublicKey, ServerPublicKey},
    state::{PMSComputationSetup, State},
    ComputePMS, KeyExchangeChannel, KeyExchangeError, KeyExchangeFollow, KeyExchangeLead,
    KeyExchangeMessage, PublicKey,
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
use mpc_circuits::{builder::CircuitBuilder, Circuit, InputValue, ValueType, WireGroup};
use mpc_core::{
    garble::{
        exec::dual::{DualExConfig, DualExConfigBuilder},
        ActiveEncodedInput, FullEncodedInput, FullInputSet,
    },
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use p256::{EncodedPoint, SecretKey};
use point_addition::PointAddition;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use share_conversion_core::fields::{p256::P256, Field};
use std::{borrow::Borrow, sync::Arc};
use tls_circuits::combine_pms_shares;
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
        let mut config_builder = DualExConfigBuilder::default();

        let circuit = build_double_combine_pms_circuit();
        config_builder.circ(circuit);
        config_builder.id(id.clone());

        let config = config_builder.build().unwrap();
        let circuit = Arc::clone(&config.circ());

        let dual_ex = self.state.dual_ex_factory.create(id, config).await?;
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
                dual_ex,
                circuit,
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
            .circuit
            .input(0)
            .unwrap()
            .to_value(pms_share1.to_le_bytes())
            .unwrap();

        let leader_input2 = self
            .state
            .circuit
            .input(0)
            .unwrap()
            .to_value(pms_share2.to_le_bytes())
            .unwrap();

        let follower_input1 = self.state.circuit.input(1).unwrap();
        let follower_input2 = self.state.circuit.input(1).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &self.state.circuit, None);

        let summary = self
            .state
            .dual_ex
            .execute_skip_equality_check(
                leader_labels,
                vec![leader_input1.clone(), leader_input2.clone()],
                vec![follower_input1.clone(), follower_input2.clone()],
                vec![leader_input1.clone(), leader_input2.clone()],
                vec![],
            )
            .await?;

        let output_labels = summary.get_evaluator_summary().output_labels();
    }
}

fn build_double_combine_pms_circuit() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("pms_shares_double", "", "0.1.0");

    let a = builder.add_input(
        "PMS_SHARE_A",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let b = builder.add_input(
        "PMS_SHARE_B",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let c = builder.add_input(
        "PMS_SHARE_C",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );
    let d = builder.add_input(
        "PMS_SHARE_C",
        "256-bit PMS Additive Share",
        ValueType::Bytes,
        256,
    );

    let mut builder = builder.build_inputs();
    let handle1 = builder.add_circ(&combine_pms_shares());
    let handle2 = builder.add_circ(&combine_pms_shares());

    let a_input = handle1.input(0).unwrap();
    let b_input = handle1.input(1).unwrap();

    let c_input = handle2.input(0).unwrap();
    let d_input = handle2.input(1).unwrap();

    builder.connect(&a[..], &a_input[..]);
    builder.connect(&b[..], &b_input[..]);
    builder.connect(&c[..], &c_input[..]);
    builder.connect(&d[..], &d_input[..]);

    let pms1_out = handle1.output(0).expect("add mod is missing output 0");
    let pms2_out = handle2.output(0).expect("add mod is missing output 0");

    let mut builder = builder.build_gates();

    let pms1 = builder.add_output("PMS1", "Pre-master Secret", ValueType::Bytes, 256);
    let pms2 = builder.add_output("PMS2", "Pre-master Secret", ValueType::Bytes, 256);

    builder.connect(&pms1_out[..], &pms1[..]);
    builder.connect(&pms2_out[..], &pms2[..]);

    builder.build_circuit().unwrap()
}

//        // Garble input
//        let leader_input = self
//            .state
//            .circuit
//            .input(0)
//            .unwrap()
//            .to_value(circ_input)
//            .unwrap();
//        let follower_input = self.state.circuit.input(1).unwrap();
//        let leader_labels = FullInputSet::generate(&mut rng, &self.state.circuit, None);
//
//        let summary = self
//            .state
//            .dual_ex
//            .setup_inputs(
//                leader_labels,
//                vec![leader_input.clone()],
//                vec![follower_input],
//                vec![leader_input.clone()],
//                vec![],
//            )
//            .await?
//            .execute_skip_equality_check()
//            .await?;
//
//        let decoded = summary.get_evaluator_summary().decode()?;
//        let (Value::Bits(sub_output), Value::Bool(carry)) = (decoded[0].value(), decoded[1].value()) else {
//            panic!("Unexpected output type");
//        };
//        if *sub_output != vec![false; 256] || *carry {
//            return Err(KeyExchangeError::CheckFailed);
//        }
//        todo!()
//    }
//}
