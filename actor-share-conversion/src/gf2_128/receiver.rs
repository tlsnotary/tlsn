use super::{A2MMessage, M2AMessage, VerifyTapeMessage};
use crate::ActorConversionError;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};
use mpc_core::Block;
use share_conversion_aio::{
    gf2_128::{
        recorder::{Recorder, Void},
        Gf2ConversionMessage, Receiver as IOReceiver, VerifyTape,
    },
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError,
};
use share_conversion_core::gf2_128::Gf2_128ShareConvert;
use utils_aio::mux::MuxChannelControl;
use xtra::prelude::*;

enum State<T: OTReceiverFactory, U: Gf2_128ShareConvert, V: Recorder<U>> {
    Setup(IOReceiver<T, U, V>),
    Complete,
}

#[derive(xtra::Actor)]
pub struct Receiver<T, U, V = Void>
where
    T: OTReceiverFactory,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    inner: State<T, U, V>,
}

impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
        V: Gf2_128ShareConvert + Send,
        W: Recorder<V>,
    > Receiver<T, V, W>
{
    pub async fn new<X: MuxChannelControl<Gf2ConversionMessage>>(
        mut muxer: X,
        receiver_factory: T,
        id: String,
    ) -> Result<Self, ActorConversionError> {
        let channel = muxer.get_channel(id.clone()).await?;
        let receiver = IOReceiver::new(receiver_factory, id, channel);
        Ok(Self {
            inner: State::Setup(receiver),
        })
    }
}

#[derive(Clone)]
pub struct ReceiverControl<T>(Address<T>);

impl<T> ReceiverControl<T> {
    pub fn new(address: Address<T>) -> Self {
        Self(address)
    }
}

#[async_trait]
impl<T> MultiplicativeToAdditive for ReceiverControl<T>
where
    T: Handler<M2AMessage<Vec<u128>>, Return = Result<Vec<u128>, ActorConversionError>>,
{
    type FieldElement = u128;
    type Error = ActorConversionError;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, Self::Error> {
        self.0.send(M2AMessage(input.to_vec())).await?
    }
}

#[async_trait]
impl<T> AdditiveToMultiplicative for ReceiverControl<T>
where
    T: Handler<A2MMessage<Vec<u128>>, Return = Result<Vec<u128>, ActorConversionError>>,
{
    type FieldElement = u128;
    type Error = ActorConversionError;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, Self::Error> {
        self.0.send(A2MMessage(input.to_vec())).await?
    }
}

#[async_trait]
impl<T> VerifyTape for ReceiverControl<T>
where
    T: Handler<VerifyTapeMessage, Return = Result<(), ActorConversionError>>,
{
    type Error = ActorConversionError;

    async fn verify_tape(self) -> Result<(), ActorConversionError> {
        self.0.send(VerifyTapeMessage).await?
    }
}

#[async_trait]
impl<T, U, V, W> Handler<M2AMessage<Vec<u128>>> for Receiver<T, V, W>
where
    T: OTReceiverFactory<Protocol = U> + Send + 'static,
    U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
    V: Gf2_128ShareConvert + Send + 'static,
    W: Recorder<V> + Send + 'static,
    IOReceiver<T, V, W>:
        MultiplicativeToAdditive<FieldElement = u128, Error = ShareConversionError>,
{
    type Return = Result<Vec<u128>, ActorConversionError>;

    async fn handle(
        &mut self,
        message: M2AMessage<Vec<u128>>,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        match self.inner {
            State::Setup(ref mut inner) => inner
                .m_to_a(message.0.as_slice())
                .await
                .map_err(ActorConversionError::from),
            State::Complete => Err(ActorConversionError::Shutdown),
        }
    }
}

#[async_trait]
impl<T, U, V, W> Handler<A2MMessage<Vec<u128>>> for Receiver<T, V, W>
where
    T: OTReceiverFactory<Protocol = U> + Send + 'static,
    U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
    V: Gf2_128ShareConvert + Send + 'static,
    W: Recorder<V> + Send + 'static,
    IOReceiver<T, V, W>:
        AdditiveToMultiplicative<FieldElement = u128, Error = ShareConversionError>,
{
    type Return = Result<Vec<u128>, ActorConversionError>;

    async fn handle(
        &mut self,
        message: A2MMessage<Vec<u128>>,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        match self.inner {
            State::Setup(ref mut inner) => inner
                .a_to_m(message.0.as_slice())
                .await
                .map_err(ActorConversionError::from),
            State::Complete => Err(ActorConversionError::Shutdown),
        }
    }
}

#[async_trait]
impl<T, U, V, W> Handler<VerifyTapeMessage> for Receiver<T, V, W>
where
    T: OTReceiverFactory<Protocol = U> + Send + 'static,
    U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
    V: Gf2_128ShareConvert + Send + 'static,
    W: Recorder<V> + Send + 'static,
    IOReceiver<T, V, W>: VerifyTape<Error = ShareConversionError>,
{
    type Return = Result<(), ActorConversionError>;

    async fn handle(
        &mut self,
        _message: VerifyTapeMessage,
        ctx: &mut Context<Self>,
    ) -> Self::Return {
        let inner = std::mem::replace(&mut self.inner, State::Complete);

        if let State::Setup(inner) = inner {
            inner
                .verify_tape()
                .await
                .map_err(ActorConversionError::from)?
        } else {
            return Err(ActorConversionError::Shutdown);
        };

        ctx.stop_self();
        Ok(())
    }
}
