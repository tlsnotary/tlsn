use super::{A2MMessage, M2AMessage, SendTapeMessage, Setup};
use mpc_aio::protocol::ot::{OTFactoryError, ObliviousSend};
use mpc_core::{ot::config::OTSenderConfig, Block};
use share_conversion_aio::{
    gf2_128::{
        recorder::{Recorder, Tape, Void},
        Gf2ConversionMessage, SendTape, Sender as IOSender,
    },
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError,
};
use share_conversion_core::gf2_128::Gf2_128ShareConvert;
use utils_aio::{adaptive_barrier::AdaptiveBarrier, factory::AsyncFactory, mux::MuxChannelControl};
use xtra::prelude::*;

enum State<
    T: AsyncFactory<OT>,
    OT: ObliviousSend<[Block; 2]>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
> {
    Initialized {
        id: String,
        /// see `barrier` in [share_conversion_aio::gf2_128::Sender]
        barrier: Option<AdaptiveBarrier>,
        /// a local muxer which provides a channel to the remote conversion receiver
        muxer: V,
        /// see `sender_factory` in [share_conversion_aio::gf2_128::Sender]
        sender_factory: T,
    },
    Setup(IOSender<T, OT, U, W>),
    Complete,
    Error,
}

#[derive(xtra::Actor)]
pub struct Sender<T, OT, U, V, W = Void>
where
    T: AsyncFactory<OT>,
    OT: ObliviousSend<[Block; 2]>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
{
    state: State<T, OT, U, V, W>,
}

impl<T, OT, U, V, W> Sender<T, OT, U, V, W>
where
    T: AsyncFactory<OT>,
    OT: ObliviousSend<[Block; 2]>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
{
    pub fn new(id: String, barrier: Option<AdaptiveBarrier>, muxer: V, sender_factory: T) -> Self {
        Self {
            state: State::Initialized {
                id,
                barrier,
                muxer,
                sender_factory,
            },
        }
    }
}

/// The controller to talk to the local conversion sender actor. This is the only way to talk
/// to the actor.
pub struct SenderControl<T>(Address<T>);

impl<T> SenderControl<T> {
    pub fn new(address: Address<T>) -> Self {
        Self(address)
    }
}

impl<T> Clone for SenderControl<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> SenderControl<T>
where
    T: Handler<Setup, Return = Result<(), ShareConversionError>>,
{
    pub async fn setup(&mut self) -> Result<(), ShareConversionError> {
        self.0
            .send(Setup)
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T> MultiplicativeToAdditive for SenderControl<T>
where
    T: Handler<M2AMessage<Vec<u128>>, Return = Result<Vec<u128>, ShareConversionError>>,
{
    type FieldElement = u128;

    /// Sends M2AMessage to the actor
    async fn m_to_a(
        &mut self,
        input: Vec<Self::FieldElement>,
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.0
            .send(M2AMessage(input))
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T> AdditiveToMultiplicative for SenderControl<T>
where
    T: Handler<A2MMessage<Vec<u128>>, Return = Result<Vec<u128>, ShareConversionError>>,
{
    type FieldElement = u128;

    /// Sends A2MMessage to the actor
    async fn a_to_m(
        &mut self,
        input: Vec<Self::FieldElement>,
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.0
            .send(A2MMessage(input))
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T> SendTape for SenderControl<T>
where
    T: Handler<SendTapeMessage, Return = Result<(), ShareConversionError>>,
{
    /// Sends SendTapeMessage to the actor
    async fn send_tape(self) -> Result<(), ShareConversionError> {
        self.0
            .send(SendTapeMessage)
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T, OT, U, V, W> Handler<Setup> for Sender<T, OT, U, V, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    W: Recorder<U> + Send + 'static,
{
    type Return = Result<(), ShareConversionError>;

    async fn handle(&mut self, _message: Setup, ctx: &mut Context<Self>) -> Self::Return {
        // We need to own the state, so we use this only as a temporary modification
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Initialized {id, barrier, mut muxer, sender_factory} = state else {
            ctx.stop_self();
            return Err(ShareConversionError::Other(String::from("Actor has to be in the Initialized state")));
        };

        let channel = muxer
            .get_channel(id.clone())
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?;
        let sender = IOSender::new(sender_factory, id, channel, barrier);
        self.state = State::Setup(sender);

        Ok(())
    }
}

#[async_trait]
impl<T, OT, U, V, W> Handler<M2AMessage<Vec<u128>>> for Sender<T, OT, U, V, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    W: Recorder<U> + Send + 'static,
    IOSender<T, OT, U, W>: MultiplicativeToAdditive<FieldElement = u128>,
{
    type Return = Result<Vec<u128>, ShareConversionError>;

    /// This handler is called when the actor receives M2AMessage
    async fn handle(
        &mut self,
        message: M2AMessage<Vec<u128>>,
        ctx: &mut Context<Self>,
    ) -> Self::Return {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup(mut state) = state else {
            ctx.stop_self();
            return Err(ShareConversionError::Other(String::from(
                "Actor is not in the Setup state",
            )));
        };
        let out = state.m_to_a(message.0).await;
        self.state = State::Setup(state);
        out
    }
}

#[async_trait]
impl<T, OT, U, V, W> Handler<A2MMessage<Vec<u128>>> for Sender<T, OT, U, V, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    W: Recorder<U> + Send + 'static,
    IOSender<T, OT, U, W>: AdditiveToMultiplicative<FieldElement = u128>,
{
    type Return = Result<Vec<u128>, ShareConversionError>;

    /// This handler is called when the actor receives A2MMessage
    async fn handle(
        &mut self,
        message: A2MMessage<Vec<u128>>,
        ctx: &mut Context<Self>,
    ) -> Self::Return {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup(mut state) = state else {
            ctx.stop_self();
            return Err(ShareConversionError::Other(String::from(
                "Actor is not in the Setup state",
            )));
        };
        let out = state.a_to_m(message.0).await;
        self.state = State::Setup(state);
        out
    }
}

#[async_trait]
impl<T, OT, U, V> Handler<SendTapeMessage> for Sender<T, OT, U, V, Tape>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    IOSender<T, OT, U, Tape>: SendTape,
{
    type Return = Result<(), ShareConversionError>;

    /// This handler is called when the actor receives SendTapeMessage
    async fn handle(&mut self, _message: SendTapeMessage, ctx: &mut Context<Self>) -> Self::Return {
        let state = std::mem::replace(&mut self.state, State::Error);
        ctx.stop_self();

        let State::Setup(state) = state else {
            return Err(ShareConversionError::Other(String::from(
                "Actor is not in the Setup state",
            )));
        };

        self.state = State::Complete;
        state.send_tape().await
    }
}
