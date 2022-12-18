use crate::ActorConversionError;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};
use share_conversion_aio::{
    gf2_128::{
        recorder::{Recorder, Void},
        Gf2ConversionMessage, SendTape, Sender as IOSender,
    },
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError,
};
use share_conversion_core::gf2_128::{Gf2_128ShareConvert, OTEnvelope};
use utils_aio::{adaptive_barrier::AdaptiveBarrier, mux::MuxChannelControl};
use xtra::prelude::*;

#[derive(xtra::Actor)]
pub struct Sender<T, U, V = Void>
where
    T: OTSenderFactory,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    inner: IOSender<T, U, V>,
}

pub struct M2AMessage<T>(T);
pub struct A2MMessage<T>(T);
pub struct SendTapeMessage;

impl<T, U, V> Sender<T, U, V>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert,
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
        Ok(Self { inner: sender })
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
impl<T, U, V> Handler<M2AMessage<Vec<u128>>> for Sender<T, U, V>
where
    T: OTSenderFactory + Send + 'static,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOSender<T, U, V>: MultiplicativeToAdditive<FieldElement = u128, Error = ShareConversionError>,
{
    type Return = Result<Vec<u128>, ActorConversionError>;

    async fn handle(
        &mut self,
        message: M2AMessage<Vec<u128>>,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        self.inner
            .m_to_a(message.0.as_slice())
            .await
            .map_err(ActorConversionError::from)
    }
}

#[async_trait]
impl<T, U, V> Handler<A2MMessage<Vec<u128>>> for Sender<T, U, V>
where
    T: OTSenderFactory + Send + 'static,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOSender<T, U, V>: AdditiveToMultiplicative<FieldElement = u128, Error = ShareConversionError>,
{
    type Return = Result<Vec<u128>, ActorConversionError>;

    async fn handle(
        &mut self,
        message: A2MMessage<Vec<u128>>,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        self.inner
            .a_to_m(message.0.as_slice())
            .await
            .map_err(ActorConversionError::from)
    }
}

#[async_trait]
impl<T, U, V> Handler<SendTapeMessage> for Sender<T, U, V>
where
    T: OTSenderFactory + Send + 'static,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert + Send + 'static,
    V: Recorder<U> + Send + 'static,
    IOSender<T, U, V>: SendTape<Error = ShareConversionError>,
{
    type Return = Result<(), ActorConversionError>;

    async fn handle(
        &mut self,
        _message: SendTapeMessage,
        _ctx: &mut Context<Self>,
    ) -> Self::Return {
        // TODO: Solve &mut self vs self
        self.inner
            .send_tape()
            .await
            .map_err(ActorConversionError::from)
    }
}
