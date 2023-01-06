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

enum State<T, OT, U, V, W>
where
    T: AsyncFactory<OT>,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
{
    Initialized {
        id: String,
        muxer: V,
        receiver_factory: T,
    },
    Setup(IOReceiver<T, OT, U, W>),
    Complete,
}

#[derive(xtra::Actor)]
pub struct Receiver<T, OT, U, V, W = Void>
where
    T: AsyncFactory<OT>,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
{
    state: State<T, OT, U, V, W>,
}

impl<T, OT, U, V, W> Receiver<T, OT, U, V, W>
where
    T: AsyncFactory<OT>,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
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

impl<T, OT, U, V, W> Receiver<T, OT, U, V, W>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    OT: ObliviousReceive<bool, Block>,
    U: Gf2_128ShareConvert,
    V: MuxChannelControl<Gf2ConversionMessage>,
    W: Recorder<U>,
{
    pub async fn setup(&mut self) -> Result<(), ActorConversionError> {
        // We need to own the state, so we use this only as a temporary modification
        let state = std::mem::replace(&mut self.state, State::Complete);

        match state {
            State::Initialized {
                id,
                mut muxer,
                receiver_factory,
            } => {
                let channel = muxer.get_channel(id.clone()).await?;
                let receiver = IOReceiver::new(receiver_factory, id, channel);
                self.state = State::Setup(receiver);
            }
            State::Setup(_) => {
                self.state = state;
                return Err(ActorConversionError::AlreadySetup);
            }
            State::Complete => {
                self.state = state;
                return Err(ActorConversionError::Shutdown);
            }
        }

        Ok(())
    }
}

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
impl<T, OT, U, V, W> Handler<M2AMessage<Vec<u128>>> for Receiver<T, OT, U, V, W>
where
    T: AsyncFactory<OT> + Send + 'static,
    OT: ObliviousReceive<bool, Block> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    W: Recorder<U> + Send + 'static,
    IOReceiver<T, OT, U, W>:
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
            State::Initialized { .. } => Err(ActorConversionError::NotSetup),
        }
    }
}

#[async_trait]
impl<T, OT, U, V, W> Handler<A2MMessage<Vec<u128>>> for Receiver<T, OT, U, V, W>
where
    T: AsyncFactory<OT> + Send + 'static,
    OT: ObliviousReceive<bool, Block> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    W: Recorder<U> + Send + 'static,
    IOReceiver<T, OT, U, W>:
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
            State::Initialized { .. } => Err(ActorConversionError::NotSetup),
        }
    }
}

#[async_trait]
impl<T, OT, U, V> Handler<VerifyTapeMessage> for Receiver<T, OT, U, V, Tape>
where
    T: AsyncFactory<OT> + Send + 'static,
    OT: ObliviousReceive<bool, Block> + Send + 'static,
    U: Gf2_128ShareConvert + Send + 'static,
    V: MuxChannelControl<Gf2ConversionMessage> + Send + 'static,
    IOReceiver<T, OT, U, Tape>: VerifyTape<Error = ShareConversionError>,
{
    type Return = Result<(), ActorConversionError>;

    async fn handle(
        &mut self,
        _message: VerifyTapeMessage,
        ctx: &mut Context<Self>,
    ) -> Self::Return {
        let state = std::mem::replace(&mut self.state, State::Complete);
        let _ = match state {
            State::Setup(state) => state
                .verify_tape()
                .await
                .map_err(ActorConversionError::from),
            State::Complete => Err(ActorConversionError::Shutdown),
            State::Initialized { .. } => Err(ActorConversionError::NotSetup),
        }?;

        ctx.stop_self();
        Ok(())
    }
}
