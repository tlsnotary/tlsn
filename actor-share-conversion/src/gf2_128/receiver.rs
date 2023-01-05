use super::{A2MMessage, M2AMessage, VerifyTapeMessage};
use crate::ActorConversionError;
use mpc_aio::protocol::ot::{OTFactoryError, ObliviousReceive};
use mpc_core::{ot::config::OTReceiverConfig, Block};
use share_conversion_aio::{
    gf2_128::{
        recorder::{Recorder, Tape, Void},
        Gf2ConversionMessage, Receiver as IOReceiver, VerifyTape,
    },
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError,
};
use share_conversion_core::gf2_128::Gf2_128ShareConvert;
use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl};
use xtra::prelude::*;

enum State<T, OT, U, V>
where
    T: AsyncFactory<OT>,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    Initialized,
    Setup(IOReceiver<T, OT, U, V>),
    Complete,
}

#[derive(xtra::Actor)]
pub struct Receiver<T, OT, U, V = Void>
where
    T: AsyncFactory<OT>,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    state: State<T, OT, U, V>,
}

impl<T, OT, U, V> Receiver<T, OT, U, V>
where
    T: AsyncFactory<OT>,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    pub fn new() -> Self {
        Self {
            state: State::Initialized,
        }
    }
}

impl<T, OT, U, V> Receiver<T, OT, U, V>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    pub async fn setup<X: MuxChannelControl<Gf2ConversionMessage>>(
        &mut self,
        mut muxer: X,
        receiver_factory: T,
        id: String,
    ) -> Result<(), ActorConversionError> {
        let channel = muxer.get_channel(id.clone()).await?;
        let receiver = IOReceiver::new(receiver_factory, id, channel);
        self.state = State::Setup(receiver);
        Ok(())
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
        input: Vec<Self::FieldElement>,
    ) -> Result<Vec<Self::FieldElement>, Self::Error> {
        self.0.send(M2AMessage(input)).await?
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
        input: Vec<Self::FieldElement>,
    ) -> Result<Vec<Self::FieldElement>, Self::Error> {
        self.0.send(A2MMessage(input)).await?
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
impl<T, OT, U, V> Handler<M2AMessage<Vec<u128>>> for Receiver<T, OT, U, V>
where
    T: AsyncFactory<OT> + Send + 'static,
    OT: ObliviousReceive<bool, Block> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOReceiver<T, OT, U, V>:
        MultiplicativeToAdditive<FieldElement = u128, Error = ShareConversionError>,
{
    type Return = Result<Vec<u128>, ActorConversionError>;

    async fn handle(
        &mut self,
        message: M2AMessage<Vec<u128>>,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        match self.state {
            State::Setup(ref mut inner) => inner
                .m_to_a(message.0)
                .await
                .map_err(ActorConversionError::from),
            State::Complete => Err(ActorConversionError::Shutdown),
            State::Initialized => Err(ActorConversionError::NotSetup),
        }
    }
}

#[async_trait]
impl<T, OT, U, V> Handler<A2MMessage<Vec<u128>>> for Receiver<T, OT, U, V>
where
    T: AsyncFactory<OT> + Send + 'static,
    OT: ObliviousReceive<bool, Block> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOReceiver<T, OT, U, V>:
        AdditiveToMultiplicative<FieldElement = u128, Error = ShareConversionError>,
{
    type Return = Result<Vec<u128>, ActorConversionError>;

    async fn handle(
        &mut self,
        message: A2MMessage<Vec<u128>>,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        match self.state {
            State::Setup(ref mut inner) => inner
                .a_to_m(message.0)
                .await
                .map_err(ActorConversionError::from),
            State::Complete => Err(ActorConversionError::Shutdown),
            State::Initialized => Err(ActorConversionError::NotSetup),
        }
    }
}

#[async_trait]
impl<T, OT, U> Handler<VerifyTapeMessage> for Receiver<T, OT, U, Tape>
where
    T: AsyncFactory<OT> + Send + 'static,
    OT: ObliviousReceive<bool, Block> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    IOReceiver<T, OT, U, Tape>: VerifyTape<Error = ShareConversionError>,
{
    type Return = Result<(), ActorConversionError>;

    async fn handle(
        &mut self,
        _message: VerifyTapeMessage,
        ctx: &mut Context<Self>,
    ) -> Self::Return {
        let inner = std::mem::replace(&mut self.state, State::Complete);
        let _ = match inner {
            State::Setup(inner) => inner
                .verify_tape()
                .await
                .map_err(ActorConversionError::from),
            State::Complete => Err(ActorConversionError::Shutdown),
            State::Initialized => Err(ActorConversionError::NotSetup),
        }?;

        ctx.stop_self();
        Ok(())
    }
}
