use std::marker::PhantomData;

use async_trait::async_trait;
use mpc_circuits::InputValue;
use mpc_garble_core::{
    exec::zk::{ProverConfig, VerifierConfig},
    msgs::GarbleMessage,
    ActiveEncodedInput, FullEncodedInput,
};
use mpc_ot::{
    config::{OTReceiverConfig, OTSenderConfig},
    OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify,
};
use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl};

use crate::{
    exec::zk::{prover_state, verifier_state, Prover, Verifier},
    Compressor, Evaluator, Generator, Validator,
};

use super::GCFactoryError;

pub struct ProverFactory<M, B, LRF, LR> {
    mux_control: M,
    backend: B,
    label_receiver_factory: LRF,
    _label_receiver: PhantomData<LR>,
}

impl<M, B, LRF, LR> Clone for ProverFactory<M, B, LRF, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Evaluator + Compressor + Validator + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
{
    fn clone(&self) -> Self {
        ProverFactory {
            mux_control: self.mux_control.clone(),
            backend: self.backend.clone(),
            label_receiver_factory: self.label_receiver_factory.clone(),
            _label_receiver: PhantomData,
        }
    }
}

impl<M, B, LRF, LR> ProverFactory<M, B, LRF, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Evaluator + Compressor + Validator + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Create a new ProverFactory.
    pub fn new(mux_control: M, backend: B, label_receiver_factory: LRF) -> Self {
        ProverFactory {
            mux_control,
            backend,
            label_receiver_factory,
            _label_receiver: PhantomData,
        }
    }
}

#[async_trait]
impl<M, B, LRF, LR> AsyncFactory<Prover<prover_state::Initialized, B, LRF, LR>>
    for ProverFactory<M, B, LRF, LR>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Evaluator + Compressor + Validator + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    type Config = ProverConfig;
    type Error = GCFactoryError;

    async fn create(
        &mut self,
        _id: String,
        config: Self::Config,
    ) -> Result<Prover<prover_state::Initialized, B, LRF, LR>, Self::Error> {
        let channel = self
            .mux_control
            .get_channel(config.id().to_string())
            .await?;

        let prover = Prover::new(
            config,
            channel,
            self.backend.clone(),
            self.label_receiver_factory.clone(),
        );

        Ok(prover)
    }
}

pub struct VerifierFactory<M, B, LSF, LS> {
    mux_control: M,
    backend: B,
    label_sender_factory: LSF,
    _label_sender: PhantomData<LS>,
}

impl<M, B, LSF, LS> Clone for VerifierFactory<M, B, LSF, LS>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Generator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
{
    fn clone(&self) -> Self {
        VerifierFactory {
            mux_control: self.mux_control.clone(),
            backend: self.backend.clone(),
            label_sender_factory: self.label_sender_factory.clone(),
            _label_sender: PhantomData,
        }
    }
}

impl<M, B, LSF, LS> VerifierFactory<M, B, LSF, LS>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    /// Create a new VerifierFactory.
    pub fn new(mux_control: M, backend: B, label_sender_factory: LSF) -> Self {
        VerifierFactory {
            mux_control,
            backend,
            label_sender_factory,
            _label_sender: PhantomData,
        }
    }
}

#[async_trait]
impl<M, B, LSF, LS> AsyncFactory<Verifier<verifier_state::Initialized, B, LSF, LS>>
    for VerifierFactory<M, B, LSF, LS>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Evaluator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    type Config = VerifierConfig;
    type Error = GCFactoryError;

    async fn create(
        &mut self,
        _id: String,
        config: Self::Config,
    ) -> Result<Verifier<verifier_state::Initialized, B, LSF, LS>, Self::Error> {
        let channel = self
            .mux_control
            .get_channel(config.id().to_string())
            .await?;

        let follower = Verifier::new(
            config,
            channel,
            self.backend.clone(),
            self.label_sender_factory.clone(),
        );

        Ok(follower)
    }
}

#[cfg(feature = "mock")]
pub mod mock {
    use mpc_core::Block;
    use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
    use utils_aio::mux::mock::MockMuxChannelFactory;

    use crate::backend::RayonBackend;

    use super::*;

    pub type MockProverFactory = ProverFactory<
        MockMuxChannelFactory<GarbleMessage>,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTReceiver<Block>,
    >;

    pub type MockVerifierFactory = VerifierFactory<
        MockMuxChannelFactory<GarbleMessage>,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTSender<Block>,
    >;

    pub fn create_mock_zk_factory_pair() -> (MockProverFactory, MockVerifierFactory) {
        let mux_factory = MockMuxChannelFactory::new();
        let ot_factory = MockOTFactory::new();

        (
            ProverFactory::new(mux_factory.clone(), RayonBackend, ot_factory.clone()),
            VerifierFactory::new(mux_factory, RayonBackend, ot_factory),
        )
    }
}
