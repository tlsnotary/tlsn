use std::marker::PhantomData;

use async_trait::async_trait;
use mpc_circuits::InputValue;
use mpc_garble_core::{
    exec::dual::DualExConfig, msgs::GarbleMessage, ActiveEncodedInput, FullEncodedInput,
};
use mpc_ot::{
    config::{OTReceiverConfig, OTSenderConfig},
    OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify,
};
use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl};

use crate::{
    exec::deap::{follower_state, leader_state, DEAPFollower, DEAPLeader},
    Compressor, Evaluator, Generator, Validator,
};

use super::GCFactoryError;

pub struct DEAPLeaderFactory<M, B, LSF, LRF, LS, LR> {
    mux_control: M,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,
    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<M, B, LSF, LRF, LS, LR> Clone for DEAPLeaderFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
{
    fn clone(&self) -> Self {
        DEAPLeaderFactory {
            mux_control: self.mux_control.clone(),
            backend: self.backend.clone(),
            label_sender_factory: self.label_sender_factory.clone(),
            label_receiver_factory: self.label_receiver_factory.clone(),
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        }
    }
}

impl<M, B, LSF, LRF, LS, LR> DEAPLeaderFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Create a new DEAPFactory.
    pub fn new(
        mux_control: M,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> Self {
        DEAPLeaderFactory {
            mux_control,
            backend,
            label_sender_factory,
            label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        }
    }
}

#[async_trait]
impl<M, B, LSF, LRF, LS, LR>
    AsyncFactory<DEAPLeader<leader_state::Initialized, B, LSF, LRF, LS, LR>>
    for DEAPLeaderFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    type Config = DualExConfig;
    type Error = GCFactoryError;

    async fn create(
        &mut self,
        _id: String,
        config: Self::Config,
    ) -> Result<DEAPLeader<leader_state::Initialized, B, LSF, LRF, LS, LR>, Self::Error> {
        let channel = self
            .mux_control
            .get_channel(config.id().to_string())
            .await?;

        let leader = DEAPLeader::new(
            config,
            channel,
            self.backend.clone(),
            self.label_sender_factory.clone(),
            self.label_receiver_factory.clone(),
        );

        Ok(leader)
    }
}

pub struct DEAPFollowerFactory<M, B, LSF, LRF, LS, LR> {
    mux_control: M,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,
    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<M, B, LSF, LRF, LS, LR> Clone for DEAPFollowerFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
{
    fn clone(&self) -> Self {
        DEAPFollowerFactory {
            mux_control: self.mux_control.clone(),
            backend: self.backend.clone(),
            label_sender_factory: self.label_sender_factory.clone(),
            label_receiver_factory: self.label_receiver_factory.clone(),
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        }
    }
}

impl<M, B, LSF, LRF, LS, LR> DEAPFollowerFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Create a new DEAPFactory.
    pub fn new(
        mux_control: M,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> Self {
        DEAPFollowerFactory {
            mux_control,
            backend,
            label_sender_factory,
            label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        }
    }
}

#[async_trait]
impl<M, B, LSF, LRF, LS, LR>
    AsyncFactory<DEAPFollower<follower_state::Initialized, B, LSF, LRF, LS, LR>>
    for DEAPFollowerFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Evaluator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    type Config = DualExConfig;
    type Error = GCFactoryError;

    async fn create(
        &mut self,
        _id: String,
        config: Self::Config,
    ) -> Result<DEAPFollower<follower_state::Initialized, B, LSF, LRF, LS, LR>, Self::Error> {
        let channel = self
            .mux_control
            .get_channel(config.id().to_string())
            .await?;

        let follower = DEAPFollower::new(
            config,
            channel,
            self.backend.clone(),
            self.label_sender_factory.clone(),
            self.label_receiver_factory.clone(),
        );

        Ok(follower)
    }
}

#[cfg(feature = "mock")]
pub mod mock {
    use mpc_core::Block;
    use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
    use utils_aio::mux::mock::MockMuxChannelFactory;

    use super::*;
    use crate::backend::GarbleBackend;

    pub type MockDEAPLeaderFactory = DEAPLeaderFactory<
        MockMuxChannelFactory<GarbleMessage>,
        GarbleBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;

    pub type MockDEAPFollowerFactory = DEAPFollowerFactory<
        MockMuxChannelFactory<GarbleMessage>,
        GarbleBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;

    pub fn create_mock_deap_factory_pair() -> (MockDEAPLeaderFactory, MockDEAPFollowerFactory) {
        let mux_factory = MockMuxChannelFactory::new();
        let ot_factory = MockOTFactory::new();

        (
            DEAPLeaderFactory::new(
                mux_factory.clone(),
                GarbleBackend,
                ot_factory.clone(),
                ot_factory.clone(),
            ),
            DEAPFollowerFactory::new(mux_factory, GarbleBackend, ot_factory.clone(), ot_factory),
        )
    }
}
