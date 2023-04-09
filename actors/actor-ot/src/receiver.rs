use std::collections::HashMap;

use async_trait::async_trait;

use futures::{channel::oneshot, stream::SplitSink, Future, StreamExt};
use mpc_ot::{
    kos::receiver::Kos15IOReceiver, OTError, ObliviousAcceptCommit, ObliviousReceive,
    ObliviousVerify,
};
use xtra::{prelude::*, scoped};

use crate::{config::OTActorReceiverConfig, GetReceiver, Setup};
use mpc_core::Block;
use mpc_ot_core::{
    msgs::{OTMessage, Split},
    r_state::RandSetup,
};
use utils_aio::{mux::MuxChannelControl, Channel};

pub enum State {
    Initialized(oneshot::Sender<()>),
    Setup(Kos15IOReceiver<RandSetup>),
    Error,
}

#[derive(xtra::Actor)]
pub struct KOSReceiverActor<T, U> {
    config: OTActorReceiverConfig,
    /// This sink is not used at the moment. Future features may require the KOSReceiverActor to
    /// send messages to the KOSSenderActor, so we keep this around.
    _sink: SplitSink<T, OTMessage>,
    /// Local muxer which sets up channels with the remote KOSSenderActor
    mux_control: U,
    state: State,
    /// A buffer of ready-to-use OTs which have not yet been requested by a local caller
    child_buffer: HashMap<String, Result<Kos15IOReceiver<RandSetup>, OTError>>,
    /// A buffer of local callers which have requested OTs. As soon as we synchronize OT
    /// splitting with the remote KOSSenderActor, we will send OTs to the callers.
    pending_buffer: HashMap<String, oneshot::Sender<Result<Kos15IOReceiver<RandSetup>, OTError>>>,
}

impl<T, U> KOSReceiverActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    pub fn new(
        config: OTActorReceiverConfig,
        addr: Address<Self>,
        // the channel over which OT splits are synchronized with the remote
        // KOSSenderActor
        channel: T,
        mux_control: U,
    ) -> (Self, impl Future<Output = Option<Result<(), OTError>>>) {
        let (sink, mut stream) = channel.split();
        let (sender, receiver) = oneshot::channel();

        let fut = scoped(&addr.clone(), async move {
            // wait for actor to signal that it is set up before we start
            // processing these messages
            _ = receiver.await;
            while let Some(msg) = stream.next().await {
                match msg {
                    OTMessage::Split(msg) => addr
                        .send(msg)
                        .await
                        .map_err(|e| OTError::Other(e.to_string()))??,
                    _ => return Err(OTError::Unexpected(msg)),
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
impl<T, U> Handler<Setup> for KOSReceiverActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<(), OTError>;

    /// Handles the Setup message
    async fn handle(&mut self, _msg: Setup, _ctx: &mut Context<Self>) -> Result<(), OTError> {
        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Initialized(setup_signal) = state else {
            return Err(OTError::Other(
                "KOSReceiverActor is already setup".to_string(),
            ));
        };

        // Open channel to the remote KOSSenderActor
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

        // Signal to OTMessage stream that we're ready to process messages
        _ = setup_signal.send(());

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<Split> for KOSReceiverActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<(), OTError>;

    /// Handles the Split message. This message is sent by the remote KOSSenderActor.
    async fn handle(&mut self, msg: Split, _ctx: &mut Context<Self>) -> Result<(), OTError> {
        let Split { id, count } = msg;

        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        // These messages should not start being processed until after setup
        // so this is a fatal error
        let State::Setup(receiver) = state else {
            return Err(OTError::Other("KOSReceiverActor is not setup".to_string()));
        };

        // Open channel to the OT sender
        let child_channel = self.mux_control.get_channel(id.clone()).await?;
        // Split off OTs
        let (receiver, child_ot) = receiver.split(child_channel, count)?;

        // If a caller is already waiting, send it right away
        if let Some(sender) = self.pending_buffer.remove(&id) {
            _ = sender.send(Ok(child_ot));
        } else {
            // Otherwise insert child OT into buffer
            self.child_buffer.insert(id, Ok(child_ot));
        }

        self.state = State::Setup(receiver);

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<GetReceiver> for KOSReceiverActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTError>>;

    /// Handles the GetReceiver message
    async fn handle(
        &mut self,
        msg: GetReceiver,
        _ctx: &mut Context<Self>,
    ) -> oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTError>> {
        let GetReceiver { id, count } = msg;

        // since we may be called before we are ready to return the OTs, we use a oneshot
        // for all our return values and errors.
        let (sender, receiver) = oneshot::channel();

        // If we're not set up, return an error
        if !matches!(&self.state, &State::Setup { .. }) {
            _ = sender.send(Err(OTError::Other(
                "KOSReceiverActor is not setup".to_string(),
            )));
            return receiver;
        }

        // Check if we've already processed the split message for this instance
        if let Some(child_ot) = self.child_buffer.remove(&id) {
            // If we have, make sure that the number of OTs allocated is expected
            if let Ok(child_ot) = &child_ot {
                if child_ot.remaining() != count {
                    _ = sender.send(Err(OTError::SplitMismatch(id, child_ot.remaining(), count)));
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

pub struct ReceiverActorControl<T> {
    address: Address<T>,
    child_receiver: Option<Kos15IOReceiver<RandSetup>>,
}

impl<T> Clone for ReceiverActorControl<T> {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            child_receiver: None,
        }
    }
}

impl<T, S> ReceiverActorControl<T>
where
    T: Handler<Setup, Return = Result<(), OTError>>
        + Handler<GetReceiver, Return = oneshot::Receiver<Result<S, OTError>>>,
{
    pub fn new(address: Address<T>) -> Self {
        Self {
            address,
            child_receiver: None,
        }
    }

    /// Returns mutable reference to address
    pub fn address_mut(&mut self) -> &mut Address<T> {
        &mut self.address
    }

    /// Sends setup message to actor
    pub async fn setup(&mut self) -> Result<(), OTError> {
        self.address
            .send(Setup)
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}

#[async_trait]
impl<T> ObliviousReceive<bool, Block> for ReceiverActorControl<T>
where
    T: Handler<
        GetReceiver,
        Return = oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTError>>,
    >,
{
    async fn receive(&mut self, id: String, choices: Vec<bool>) -> Result<Vec<Block>, OTError> {
        let receiver = self
            .address
            .send(GetReceiver {
                id: id.clone(),
                count: choices.len(),
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
            .await??;

        self.child_receiver = Some(receiver);
        self.child_receiver
            .as_mut()
            .unwrap()
            .receive(id, choices)
            .await
    }
}

#[async_trait]
impl<T> ObliviousVerify<[Block; 2]> for ReceiverActorControl<T> {
    async fn verify(mut self, input: Vec<[Block; 2]>) -> Result<(), OTError> {
        let child_receiver = self.child_receiver.take().ok_or(OTError::Other(
            "No KOSReceiver instance available to reveal".to_string(),
        ))?;
        child_receiver.verify(input).await
    }
}
