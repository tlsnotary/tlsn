use async_trait::async_trait;

use futures::{stream::SplitSink, Future, SinkExt, StreamExt};
use mpc_aio::protocol::ot::{
    kos::sender::Kos15IOSender, OTFactoryError, OTSenderFactory, ObliviousSend,
};
use xtra::prelude::*;

use crate::{config::SenderFactoryConfig, GetSender, Setup};
use mpc_core::{
    msgs::ot::{OTFactoryMessage, OTMessage, Split},
    ot::s_state::RandSetup,
};
use utils_aio::{mux::MuxChannelControl, Channel};

pub enum State {
    Initialized,
    Setup(Kos15IOSender<RandSetup>),
    Error,
}

#[derive(xtra::Actor)]
pub struct KOSSenderFactory<T, U> {
    config: SenderFactoryConfig,
    sink: SplitSink<T, OTFactoryMessage>,
    mux_control: U,
    state: State,
}

#[derive(Clone)]
pub struct SenderFactoryControl<T>(Address<T>);

impl<T, S> SenderFactoryControl<T>
where
    T: Handler<Setup, Return = Result<(), OTFactoryError>>
        + Handler<GetSender, Return = Result<S, OTFactoryError>>,
    S: ObliviousSend,
{
    pub fn new(addr: Address<T>) -> Self {
        Self(addr)
    }

    pub async fn setup(&mut self) -> Result<(), OTFactoryError> {
        self.0
            .send(Setup)
            .await
            .map_err(|e| OTFactoryError::Other(e.to_string()))?
    }

    pub async fn get_sender(&mut self, id: String, count: usize) -> Result<S, OTFactoryError> {
        self.0
            .send(GetSender { id, count })
            .await
            .map_err(|e| OTFactoryError::Other(e.to_string()))?
    }
}

#[async_trait]
impl<T, U> OTSenderFactory for SenderFactoryControl<KOSSenderFactory<T, U>>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Protocol = Kos15IOSender<RandSetup>;

    async fn new_sender(
        &mut self,
        id: String,
        count: usize,
    ) -> Result<Self::Protocol, OTFactoryError> {
        self.get_sender(id, count).await
    }
}

impl<T, U> KOSSenderFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    pub fn new(
        config: SenderFactoryConfig,
        _addr: Address<Self>,
        channel: T,
        mux_control_child: U,
    ) -> (Self, impl Future<Output = Result<(), OTFactoryError>>) {
        let (sink, mut stream) = channel.split();

        let fut = async move {
            while let Some(_) = stream.next().await {
                // The receiver factory shouldn't send messages
                unimplemented!();
            }
            Ok(())
        };

        (
            Self {
                config,
                sink,
                mux_control: mux_control_child,
                state: State::Initialized,
            },
            fut,
        )
    }
}

#[async_trait]
impl<T, U> Handler<Setup> for KOSSenderFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<(), OTFactoryError>;

    async fn handle(
        &mut self,
        _msg: Setup,
        _ctx: &mut Context<Self>,
    ) -> Result<(), OTFactoryError> {
        // If we're already setup return an error
        if !matches!(&self.state, &State::Initialized) {
            return Err(OTFactoryError::Other(
                "KOSSenderFactory is already setup".to_string(),
            ));
        };

        let parent_ot_channel = self
            .mux_control
            .get_channel(self.config.ot_id.clone())
            .await?;
        let parent_ot = Kos15IOSender::new(parent_ot_channel)
            .rand_setup(self.config.initial_count)
            .await?;

        self.state = State::Setup(parent_ot);

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<GetSender> for KOSSenderFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<Kos15IOSender<RandSetup>, OTFactoryError>;

    async fn handle(
        &mut self,
        msg: GetSender,
        _ctx: &mut Context<Self>,
    ) -> Result<Kos15IOSender<RandSetup>, OTFactoryError> {
        let GetSender { id, count } = msg;

        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup(parent_ot) = state else {
            return Err(OTFactoryError::Other("KOSSenderFactory is not setup".to_string()));
        };

        // Open channel to receiver
        let child_channel_fut = self.mux_control.get_channel(id.clone());

        // Send split information to receiver factory
        let msg = Split { id, count };
        let send_msg_fut = self.sink.send(OTFactoryMessage::Split(msg));

        // Get channel and send message concurrently
        let (child_channel, send_msg) = futures::join!(child_channel_fut, send_msg_fut);
        let child_channel = child_channel?;
        _ = send_msg?;

        let (parent_ot, child_ot) = parent_ot.split(child_channel, count)?;

        self.state = State::Setup(parent_ot);

        Ok(child_ot)
    }
}
