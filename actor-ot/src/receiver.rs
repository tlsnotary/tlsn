use std::collections::HashMap;

use async_trait::async_trait;

use futures::{channel::oneshot, stream::SplitSink, Future, StreamExt};
use mpc_aio::protocol::ot::{
    kos::receiver::Kos15IOReceiver, OTFactoryError, OTReceiverFactory, ObliviousReceive,
};
use xtra::prelude::*;

use crate::{config::ReceiverFactoryConfig, GetReceiver, Setup};
use mpc_core::{
    msgs::ot::{OTFactoryMessage, OTMessage, Split},
    ot::r_state::RandSetup,
};
use utils_aio::{mux::MuxChannelControl, Channel};

pub enum State {
    Initialized(oneshot::Sender<()>),
    Setup(Kos15IOReceiver<RandSetup>),
    Error,
}

#[derive(xtra::Actor)]
pub struct KOSReceiverFactory<T, U> {
    config: ReceiverFactoryConfig,
    _sink: SplitSink<T, OTFactoryMessage>,
    mux_control: U,
    state: State,
    child_buffer: HashMap<String, Result<Kos15IOReceiver<RandSetup>, OTFactoryError>>,
    pending_buffer:
        HashMap<String, oneshot::Sender<Result<Kos15IOReceiver<RandSetup>, OTFactoryError>>>,
}

#[derive(Clone)]
pub struct ReceiverFactoryControl<T>(Address<T>);

impl<T, S> ReceiverFactoryControl<T>
where
    T: Handler<Setup, Return = Result<(), OTFactoryError>>
        + Handler<GetReceiver, Return = oneshot::Receiver<Result<S, OTFactoryError>>>,
    S: ObliviousReceive,
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

    pub async fn get_receiver(&mut self, id: String, count: usize) -> Result<S, OTFactoryError> {
        self.0
            .send(GetReceiver { id, count })
            .await
            .map_err(|e| OTFactoryError::Other(e.to_string()))?
            .await
            .map_err(|_| OTFactoryError::Other("oneshot channel was dropped".to_string()))?
    }
}

#[async_trait]
impl<T, U> OTReceiverFactory for ReceiverFactoryControl<KOSReceiverFactory<T, U>>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Protocol = Kos15IOReceiver<RandSetup>;

    async fn new_receiver(
        &mut self,
        id: String,
        count: usize,
    ) -> Result<Self::Protocol, OTFactoryError> {
        self.get_receiver(id, count).await
    }
}

impl<T, U> KOSReceiverFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    pub fn new(
        config: ReceiverFactoryConfig,
        addr: Address<Self>,
        channel: T,
        mux_control_child: U,
    ) -> (Self, impl Future<Output = Result<(), OTFactoryError>>) {
        let (sink, mut stream) = channel.split();
        let (sender, receiver) = oneshot::channel();

        let fut = async move {
            // wait for actor to signal that it is setup before we start
            // processing these messages
            _ = receiver.await;
            while let Some(msg) = stream.next().await {
                match msg {
                    OTFactoryMessage::Split(msg) => addr
                        .send(msg)
                        .await
                        .map_err(|e| OTFactoryError::Other(e.to_string()))??,
                    _ => return Err(OTFactoryError::UnexpectedMessage(msg)),
                };
            }
            Ok(())
        };

        (
            Self {
                config,
                _sink: sink,
                mux_control: mux_control_child,
                state: State::Initialized(sender),
                child_buffer: HashMap::default(),
                pending_buffer: HashMap::default(),
            },
            fut,
        )
    }
}

#[async_trait]
impl<T, U> Handler<Setup> for KOSReceiverFactory<T, U>
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
        if !matches!(&self.state, &State::Initialized(_)) {
            return Err(OTFactoryError::Other(
                "KOSReceiverFactory is already setup".to_string(),
            ));
        };

        // Open channel to sender factory
        let parent_ot_channel = self
            .mux_control
            .get_channel(self.config.ot_id.clone())
            .await?;
        let parent_ot = Kos15IOReceiver::new(parent_ot_channel)
            .rand_setup(self.config.initial_count)
            .await?;

        self.state = State::Setup(parent_ot);

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<Split> for KOSReceiverFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<(), OTFactoryError>;

    async fn handle(&mut self, msg: Split, _ctx: &mut Context<Self>) -> Result<(), OTFactoryError> {
        let Split { id, count } = msg;

        // We need this scope to own the parent OT for splitting, so we swap
        // out the internal state
        let state = std::mem::replace(&mut self.state, State::Error);

        // These messages should not start being processed until after setup
        // so this is a fatal error
        let State::Setup(parent_ot) = state else {
            return Err(OTFactoryError::Other("KOSReceiverFactory is not setup".to_string()));
        };

        // Open channel to sender
        let child_channel = self.mux_control.get_channel(id.clone()).await?;
        // Split off OTs
        let (parent_ot, child_ot) = parent_ot.split(child_channel, count)?;

        // If a caller is already waiting, send it right away
        if let Some(sender) = self.pending_buffer.remove(&id) {
            _ = sender.send(Ok(child_ot));
        } else {
            // Otherwise insert child OT into buffer
            self.child_buffer.insert(id, Ok(child_ot));
        }

        self.state = State::Setup(parent_ot);

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<GetReceiver> for KOSReceiverFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTFactoryError>>;

    async fn handle(
        &mut self,
        msg: GetReceiver,
        _ctx: &mut Context<Self>,
    ) -> oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTFactoryError>> {
        let GetReceiver { id, count } = msg;

        let (sender, receiver) = oneshot::channel();

        // If we're not setup return an error
        if !matches!(&self.state, &State::Setup(_)) {
            _ = sender.send(Err(OTFactoryError::Other(
                "KOSReceiverFactory is not setup".to_string(),
            )));
            return receiver;
        }

        // Check if we've already processed the split message for this instance
        if let Some(child_ot) = self.child_buffer.remove(&id) {
            // If we have, make sure that the number of OTs allocated is expected
            if let Ok(child_ot) = &child_ot {
                if child_ot.remaining() != count {
                    _ = sender.send(Err(OTFactoryError::SplitMismatch(
                        id,
                        child_ot.remaining(),
                        count,
                    )));
                    return receiver;
                }
            }
            // Send child instance immediately
            _ = sender.send(child_ot);
        } else {
            // Otherwise insert this instance ID and oneshot receiver into a buffer
            self.pending_buffer.insert(id, sender);
        }

        receiver
    }
}
