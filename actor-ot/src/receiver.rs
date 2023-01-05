use std::collections::HashMap;

use async_trait::async_trait;

use futures::{channel::oneshot, stream::SplitSink, Future, StreamExt};
use mpc_aio::protocol::ot::{
    config::OTReceiverConfig, kos::receiver::Kos15IOReceiver, OTFactoryError,
    ObliviousAcceptCommit, ObliviousReceive,
};
use xtra::{prelude::*, scoped};

use crate::{config::ReceiverFactoryConfig, GetReceiver, Setup};
use mpc_core::{
    msgs::ot::{OTFactoryMessage, OTMessage, Split},
    ot::r_state::RandSetup,
    Block,
};
use utils_aio::{factory::AsyncFactory, mux::MuxChannelControl, Channel};

pub enum State {
    Initialized(oneshot::Sender<()>),
    Setup(Kos15IOReceiver<RandSetup>),
    Error,
}

#[derive(xtra::Actor)]
pub struct KOSReceiverFactory<T, U> {
    config: ReceiverFactoryConfig,
    /// This sink is not used at the moment. Future features may
    /// require the ReceiverFactory to send messages to the SenderFactory, so
    /// we keep this around.
    _sink: SplitSink<T, OTFactoryMessage>,
    /// Local muxer which sets up channels with the remote KOSSenderFactory
    mux_control: U,
    state: State,
    /// A buffer of ready-to-use OTs which have not yet been requested by a local caller
    child_buffer: HashMap<String, Result<Kos15IOReceiver<RandSetup>, OTFactoryError>>,
    /// A buffer of local callers which have requested OTs. As soon as we synchronize OT
    /// splitting with the remote KOSSenderFactory, we will send OTs to the callers.
    pending_buffer:
        HashMap<String, oneshot::Sender<Result<Kos15IOReceiver<RandSetup>, OTFactoryError>>>,
}

impl<T, U> KOSReceiverFactory<T, U>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    pub fn new(
        config: ReceiverFactoryConfig,
        addr: Address<Self>,
        // the channel over which OT splits are synchronized with the remote
        // KOSSenderFactory
        channel: T,
        mux_control: U,
    ) -> (
        Self,
        impl Future<Output = Option<Result<(), OTFactoryError>>>,
    ) {
        let (sink, mut stream) = channel.split();
        let (sender, receiver) = oneshot::channel();

        let fut = scoped(&addr.clone(), async move {
            // wait for actor to signal that it is set up before we start
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
        });

        (
            Self {
                config,
                _sink: sink,
                mux_control,
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

    /// Handles the Setup message
    async fn handle(
        &mut self,
        _msg: Setup,
        _ctx: &mut Context<Self>,
    ) -> Result<(), OTFactoryError> {
        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Initialized(setup_signal) = state else {
            return Err(OTFactoryError::Other(
                "KOSSenderFactory is already setup".to_string(),
            ));
        };

        // Open channel to the remote KOSSenderFactory
        let parent_ot_channel = self
            .mux_control
            .get_channel(self.config.ot_id.clone())
            .await?;

        let mut parent_ot = Kos15IOReceiver::new(parent_ot_channel);

        if self.config.committed {
            parent_ot.accept_commit().await?;
        }

        let parent_ot = parent_ot.rand_setup(self.config.initial_count).await?;

        self.state = State::Setup(parent_ot);

        // Signal to OTFactoryMessage stream that we're ready to process messages
        _ = setup_signal.send(());

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

    /// Handles the Split message. This message is sent by the remote KOSSenderFactory.
    async fn handle(&mut self, msg: Split, _ctx: &mut Context<Self>) -> Result<(), OTFactoryError> {
        let Split { id, count } = msg;

        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        // These messages should not start being processed until after setup
        // so this is a fatal error
        let State::Setup(parent_ot) = state else {
            return Err(OTFactoryError::Other("KOSReceiverFactory is not setup".to_string()));
        };

        // Open channel to the OT sender
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

    /// Handles the GetReceiver message
    async fn handle(
        &mut self,
        msg: GetReceiver,
        _ctx: &mut Context<Self>,
    ) -> oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTFactoryError>> {
        let GetReceiver { id, count } = msg;

        // since we may be called before we are ready to return the OTs, we use a oneshot
        // for all our return values and errors.
        let (sender, receiver) = oneshot::channel();

        // If we're not set up, return an error
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
            // Otherwise insert this instance ID and oneshot sender into a buffer
            self.pending_buffer.insert(id, sender);
        }

        receiver
    }
}

pub struct ReceiverFactoryControl<T>(Address<T>);

impl<T> Clone for ReceiverFactoryControl<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, S> ReceiverFactoryControl<T>
where
    T: Handler<Setup, Return = Result<(), OTFactoryError>>
        + Handler<GetReceiver, Return = oneshot::Receiver<Result<S, OTFactoryError>>>,
    S: ObliviousReceive<bool, Block>,
{
    pub fn new(addr: Address<T>) -> Self {
        Self(addr)
    }

    /// Returns mutable reference to address
    pub fn address_mut(&mut self) -> &mut Address<T> {
        &mut self.0
    }

    /// Sends setup message to actor
    pub async fn setup(&mut self) -> Result<(), OTFactoryError> {
        self.0
            .send(Setup)
            .await
            .map_err(|e| OTFactoryError::Other(e.to_string()))?
    }

    /// Requests receiver from actor
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
impl<T, U> AsyncFactory<Kos15IOReceiver<RandSetup>>
    for ReceiverFactoryControl<KOSReceiverFactory<T, U>>
where
    T: Channel<OTFactoryMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Config = OTReceiverConfig;
    type Error = OTFactoryError;

    async fn create(
        &mut self,
        id: String,
        config: OTReceiverConfig,
    ) -> Result<Kos15IOReceiver<RandSetup>, OTFactoryError> {
        self.get_receiver(id, config.count).await
    }
}
