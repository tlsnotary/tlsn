use super::{A2MMessage, M2AMessage, SendTapeMessage, SetupMessage};
use mpc_aio::protocol::ot::{OTFactoryError, ObliviousSend};
use mpc_core::ot::config::OTSenderConfig;
use share_conversion_aio::{
    conversion::{
        recorder::{Recorder, Tape, Void},
        Sender as IOSender, ShareConversionMessage,
    },
    AdditiveToMultiplicative, MultiplicativeToAdditive, SendTape, ShareConversionError,
};
use share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::{adaptive_barrier::AdaptiveBarrier, factory::AsyncFactory, mux::MuxChannelControl};
use xtra::prelude::*;

enum State<
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError>,
    OT: ObliviousSend<[X; 2]>,
    U: ShareConvert<Inner = Y>,
    V: MuxChannelControl<ShareConversionMessage<Y>>,
    W: Recorder<U, Y>,
    Y: Field<BlockEncoding = X>,
    X,
> {
    Initialized {
        id: String,
        /// see `barrier` in [share_conversion_aio::conversion::Sender]
        barrier: Option<AdaptiveBarrier>,
        /// a local muxer which provides a channel to the remote conversion receiver
        muxer: V,
        /// see `sender_factory` in [share_conversion_aio::conversion::Sender]
        sender_factory: T,
    },
    Setup(IOSender<T, OT, U, Y, X, W>),
    Complete,
    Error,
}

#[derive(xtra::Actor)]
pub struct Sender<T, OT, U, V, X, Y, W = Void>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError>,
    OT: ObliviousSend<[X; 2]>,
    U: ShareConvert<Inner = Y>,
    V: MuxChannelControl<ShareConversionMessage<Y>>,
    W: Recorder<U, Y>,
    Y: Field<BlockEncoding = X>,
{
    state: State<T, OT, U, V, W, Y, X>,
}

impl<T, OT, U, V, X, Y, W> Sender<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError>,
    OT: ObliviousSend<[X; 2]>,
    U: ShareConvert<Inner = Y>,
    V: MuxChannelControl<ShareConversionMessage<Y>>,
    W: Recorder<U, Y>,
    Y: Field<BlockEncoding = X>,
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
    T: Handler<SetupMessage, Return = Result<(), ShareConversionError>>,
{
    pub async fn setup(&mut self) -> Result<(), ShareConversionError> {
        self.0
            .send(SetupMessage)
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T, U: Field> MultiplicativeToAdditive<U> for SenderControl<T>
where
    T: Handler<M2AMessage<Vec<U>>, Return = Result<Vec<U>, ShareConversionError>>,
{
    /// Sends M2AMessage to the actor
    async fn m_to_a(&mut self, input: Vec<U>) -> Result<Vec<U>, ShareConversionError> {
        self.0
            .send(M2AMessage(input))
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T, U: Field> AdditiveToMultiplicative<U> for SenderControl<T>
where
    T: Handler<A2MMessage<Vec<U>>, Return = Result<Vec<U>, ShareConversionError>>,
{
    /// Sends A2MMessage to the actor
    async fn a_to_m(&mut self, input: Vec<U>) -> Result<Vec<U>, ShareConversionError> {
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
impl<T, OT, U, V, X, Y, W> Handler<SetupMessage> for Sender<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[X; 2]> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    W: Recorder<U, Y> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
{
    type Return = Result<(), ShareConversionError>;

    async fn handle(&mut self, _message: SetupMessage, ctx: &mut Context<Self>) -> Self::Return {
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
impl<T, OT, U, V, X, Y, W> Handler<M2AMessage<Vec<Y>>> for Sender<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[X; 2]> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    W: Recorder<U, Y> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
    IOSender<T, OT, U, Y, X, W>: MultiplicativeToAdditive<Y>,
{
    type Return = Result<Vec<Y>, ShareConversionError>;

    /// This handler is called when the actor receives M2AMessage
    async fn handle(
        &mut self,
        message: M2AMessage<Vec<Y>>,
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
impl<T, OT, U, V, X, Y, W> Handler<A2MMessage<Vec<Y>>> for Sender<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[X; 2]> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    W: Recorder<U, Y> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
    IOSender<T, OT, U, Y, X, W>: AdditiveToMultiplicative<Y>,
{
    type Return = Result<Vec<Y>, ShareConversionError>;

    /// This handler is called when the actor receives A2MMessage
    async fn handle(
        &mut self,
        message: A2MMessage<Vec<Y>>,
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
impl<T, OT, U, V, X, Y> Handler<SendTapeMessage> for Sender<T, OT, U, V, X, Y, Tape<Y>>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[X; 2]> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
    IOSender<T, OT, U, Y, X, Tape<Y>>: SendTape,
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
