use super::{A2MMessage, M2AMessage, SendTapeMessage};
use crate::ActorConversionError;
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
    V: Recorder<U>,
> {
    Setup(IOSender<T, OT, U, V>),
    Complete,
}

#[derive(xtra::Actor)]
pub struct Sender<T, OT, U, V = Void>
where
    T: AsyncFactory<OT>,
    OT: ObliviousSend<[Block; 2]>,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    inner: State<T, OT, U, V>,
}

impl<T, OT, U, V> Sender<T, OT, U, V>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    OT: ObliviousSend<[Block; 2]> + Send,
    U: Gf2_128ShareConvert + Send,
    V: Recorder<U>,
{
    pub async fn new<W: MuxChannelControl<Gf2ConversionMessage>>(
        mut muxer: W,
        sender_factory: T,
        id: String,
        barrier: Option<AdaptiveBarrier>,
    ) -> Result<Self, ActorConversionError> {
        let channel = muxer.get_channel(id.clone()).await?;
        let sender = IOSender::new(sender_factory, id, channel, barrier);
        Ok(Self {
            inner: State::Setup(sender),
        })
    }
}

#[derive(Clone)]
pub struct SenderControl<T>(Address<T>);

impl<T> SenderControl<T> {
    pub fn new(address: Address<T>) -> Self {
        Self(address)
    }
}

#[async_trait]
impl<T> MultiplicativeToAdditive for SenderControl<T>
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
impl<T> AdditiveToMultiplicative for SenderControl<T>
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
impl<T> SendTape for SenderControl<T>
where
    T: Handler<SendTapeMessage, Return = Result<(), ActorConversionError>>,
{
    type Error = ActorConversionError;

    async fn send_tape(self) -> Result<(), ActorConversionError> {
        self.0.send(SendTapeMessage).await?
    }
}

#[async_trait]
impl<T, OT, U, V> Handler<M2AMessage<Vec<u128>>> for Sender<T, OT, U, V>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOSender<T, OT, U, V>:
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
impl<T, OT, U, V> Handler<A2MMessage<Vec<u128>>> for Sender<T, OT, U, V>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOSender<T, OT, U, V>:
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
impl<T, OT, U> Handler<SendTapeMessage> for Sender<T, OT, U, Tape>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    OT: ObliviousSend<[Block; 2]> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    IOSender<T, OT, U, Tape>: SendTape<Error = ShareConversionError>,
{
    type Return = Result<(), ActorConversionError>;

    async fn handle(&mut self, _message: SendTapeMessage, ctx: &mut Context<Self>) -> Self::Return {
        let inner = std::mem::replace(&mut self.inner, State::Complete);

        if let State::Setup(inner) = inner {
            inner
                .send_tape()
                .await
                .map_err(ActorConversionError::from)?
        } else {
            return Err(ActorConversionError::Shutdown);
        };

        ctx.stop_self();
        Ok(())
    }
}
