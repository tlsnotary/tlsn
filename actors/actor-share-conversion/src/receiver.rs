use super::{A2MMessage, M2AMessage, SetupMessage, VerifyTapeMessage};
use mpc_ot::{config::OTReceiverConfig, OTFactoryError, ObliviousReceive};
use mpc_share_conversion::{
    conversion::{
        recorder::{Recorder, Tape, Void},
        Receiver as IOReceiver, ShareConversionMessage,
    },
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError, VerifyTape,
};
use mpc_share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl};
use xtra::prelude::*;

enum State<
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError>,
    OT: ObliviousReceive<bool, X>,
    U: ShareConvert<Inner = Y>,
    V: MuxChannelControl<ShareConversionMessage<Y>>,
    W: Recorder<U, Y>,
    Y: Field<BlockEncoding = X>,
    X,
> {
    Initialized {
        id: String,
        /// a local muxer which provides a channel to the remote conversion sender
        muxer: V,
        /// see `receiver_factory` in [mpc_share_conversion::conversion::Receiver]
        receiver_factory: T,
    },
    Setup(IOReceiver<T, OT, U, Y, X, W>),
    Complete,
    Error,
}

#[derive(xtra::Actor)]
pub struct Receiver<T, OT, U, V, X, Y, W = Void>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError>,
    OT: ObliviousReceive<bool, X>,
    U: ShareConvert<Inner = Y>,
    V: MuxChannelControl<ShareConversionMessage<Y>>,
    W: Recorder<U, Y>,
    Y: Field<BlockEncoding = X>,
{
    state: State<T, OT, U, V, W, Y, X>,
}

impl<T, OT, U, V, X, Y, W> Receiver<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError>,
    OT: ObliviousReceive<bool, X>,
    U: ShareConvert<Inner = Y>,
    V: MuxChannelControl<ShareConversionMessage<Y>>,
    W: Recorder<U, Y>,
    Y: Field<BlockEncoding = X>,
{
    pub fn new(id: String, muxer: V, receiver_factory: T) -> Self {
        Self {
            state: State::Initialized {
                id,
                muxer,
                receiver_factory,
            },
        }
    }
}

/// The controller to talk to the local conversion receiver actor. This is the only way to talk
/// to the actor.
pub struct ReceiverControl<T>(Address<T>);

impl<T> ReceiverControl<T> {
    pub fn new(address: Address<T>) -> Self {
        Self(address)
    }
}

impl<T> Clone for ReceiverControl<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ReceiverControl<T>
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
impl<T, U: Field> MultiplicativeToAdditive<U> for ReceiverControl<T>
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
impl<T, U: Field> AdditiveToMultiplicative<U> for ReceiverControl<T>
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
impl<T> VerifyTape for ReceiverControl<T>
where
    T: Handler<VerifyTapeMessage, Return = Result<(), ShareConversionError>>,
{
    /// Sends VerifyTapeMessage to the actor
    async fn verify_tape(self) -> Result<(), ShareConversionError> {
        self.0
            .send(VerifyTapeMessage)
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?
    }
}

#[async_trait]
impl<T, OT, U, V, X, Y, W> Handler<SetupMessage> for Receiver<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousReceive<bool, X> + Send + 'static,
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

        let State::Initialized {id, mut muxer, receiver_factory} = state else {
            ctx.stop_self();
            return Err(ShareConversionError::Other(String::from("Actor has to be in the Initialized state")));
        };

        let channel = muxer
            .get_channel(id.clone())
            .await
            .map_err(|err| ShareConversionError::Other(err.to_string()))?;
        let receiver = IOReceiver::new(receiver_factory, id, channel);
        self.state = State::Setup(receiver);

        Ok(())
    }
}

#[async_trait]
impl<T, OT, U, V, X, Y, W> Handler<M2AMessage<Vec<Y>>> for Receiver<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousReceive<bool, X> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    W: Recorder<U, Y> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
    IOReceiver<T, OT, U, Y, X, W>: MultiplicativeToAdditive<Y>,
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
impl<T, OT, U, V, X, Y, W> Handler<A2MMessage<Vec<Y>>> for Receiver<T, OT, U, V, X, Y, W>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousReceive<bool, X> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    W: Recorder<U, Y> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
    IOReceiver<T, OT, U, Y, X, W>: AdditiveToMultiplicative<Y>,
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
impl<T, OT, U, V, X, Y> Handler<VerifyTapeMessage> for Receiver<T, OT, U, V, X, Y, Tape<Y>>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousReceive<bool, X> + Send + 'static,
    U: ShareConvert<Inner = Y> + Send + 'static,
    V: MuxChannelControl<ShareConversionMessage<Y>> + Send + 'static,
    X: Send + 'static,
    Y: Field<BlockEncoding = X> + Send + 'static,
    IOReceiver<T, OT, U, Y, X, Tape<Y>>: VerifyTape,
{
    type Return = Result<(), ShareConversionError>;

    /// This handler is called when the actor receives VerifyTapeMessage
    async fn handle(
        &mut self,
        _message: VerifyTapeMessage,
        ctx: &mut Context<Self>,
    ) -> Self::Return {
        let state = std::mem::replace(&mut self.state, State::Error);
        ctx.stop_self();

        let State::Setup(state) = state else {
            return Err(ShareConversionError::Other(String::from(
                "Actor is not in the Setup state",
            )));
        };

        self.state = State::Complete;
        state.verify_tape().await
    }
}
