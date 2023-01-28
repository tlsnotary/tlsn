use std::marker::PhantomData;

use async_trait::async_trait;
use mpc_circuits::InputValue;
use mpc_core::{
    garble::{exec::dual::DualExConfig, ActiveEncodedInput, FullEncodedInput},
    msgs::garble::GarbleMessage,
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl};

use crate::protocol::{
    garble::{
        exec::dual::{state::Initialized, DualExFollower, DualExLeader},
        Evaluator, Generator,
    },
    ot::{OTFactoryError, ObliviousReceive, ObliviousSend},
};

use super::GCFactoryError;

pub struct DualExFactory<M, B, LSF, LRF, LS, LR> {
    mux_control: M,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,
    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<M, B, LSF, LRF, LS, LR> Clone for DualExFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Generator + Evaluator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
{
    fn clone(&self) -> Self {
        DualExFactory {
            mux_control: self.mux_control.clone(),
            backend: self.backend.clone(),
            label_sender_factory: self.label_sender_factory.clone(),
            label_receiver_factory: self.label_receiver_factory.clone(),
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        }
    }
}

impl<M, B, LSF, LRF, LS, LR> DualExFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Clone + Send,
    B: Generator + Evaluator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Create a new DualExFactory.
    pub fn new(
        mux_control: M,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> Self {
        DualExFactory {
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
impl<M, B, LSF, LRF, LS, LR> AsyncFactory<DualExLeader<Initialized, B, LSF, LRF, LS, LR>>
    for DualExFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Evaluator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    type Config = DualExConfig;
    type Error = GCFactoryError;

    async fn create(
        &mut self,
        _id: String,
        config: Self::Config,
    ) -> Result<DualExLeader<Initialized, B, LSF, LRF, LS, LR>, Self::Error> {
        let channel = self
            .mux_control
            .get_channel(config.id().to_string())
            .await?;

        Ok(DualExLeader::new(
            config,
            channel,
            self.backend.clone(),
            self.label_sender_factory.clone(),
            self.label_receiver_factory.clone(),
        ))
    }
}

#[async_trait]
impl<M, B, LSF, LRF, LS, LR> AsyncFactory<DualExFollower<Initialized, B, LSF, LRF, LS, LR>>
    for DualExFactory<M, B, LSF, LRF, LS, LR>
where
    M: MuxChannelControl<GarbleMessage> + Send,
    B: Generator + Evaluator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    type Config = DualExConfig;
    type Error = GCFactoryError;

    async fn create(
        &mut self,
        _id: String,
        config: Self::Config,
    ) -> Result<DualExFollower<Initialized, B, LSF, LRF, LS, LR>, Self::Error> {
        let channel = self
            .mux_control
            .get_channel(config.id().to_string())
            .await?;

        Ok(DualExFollower::new(
            config,
            channel,
            self.backend.clone(),
            self.label_sender_factory.clone(),
            self.label_receiver_factory.clone(),
        ))
    }
}

#[cfg(feature = "mock")]
pub mod mock {
    use mpc_core::Block;
    use utils_aio::mux::mock::MockMuxChannelFactory;

    use crate::protocol::{
        garble::backend::RayonBackend,
        ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender},
    };

    use super::*;

    pub type MockDualExFactory = DualExFactory<
        MockMuxChannelFactory<GarbleMessage>,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;

    pub fn create_mock_dualex_factory() -> MockDualExFactory {
        let mux_factory = MockMuxChannelFactory::new();
        let ot_factory = MockOTFactory::new();

        DualExFactory::new(mux_factory, RayonBackend, ot_factory.clone(), ot_factory)
    }
}
