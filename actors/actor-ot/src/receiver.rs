use crate::{config::OTActorReceiverConfig, GetReceiver, SendBackReceiver, Setup, Verify};
use async_trait::async_trait;
use futures::{channel::oneshot, stream::SplitSink, Future, FutureExt, StreamExt};
use mpz_core::Block;
use mpz_ot::{
    kos::receiver::Kos15IOReceiver, OTChannel, OTError, ObliviousAcceptCommitOwned,
    ObliviousReceive, ObliviousReceiveOwned, ObliviousVerify, ObliviousVerifyOwned,
};
use mpz_ot_core::{
    msgs::{OTMessage, Split},
    r_state::RandSetup,
};
use std::{collections::HashMap, pin::Pin};
use utils_aio::mux::MuxChannel;
use xtra::{prelude::*, scoped};

#[allow(clippy::large_enum_variant)]
enum State {
    Initialized(oneshot::Sender<()>),
    Setup {
        receiver: Kos15IOReceiver<RandSetup>,
        child_receivers: HashMap<String, Kos15IOReceiver<RandSetup>>,
    },
    Error,
}

/// KOS OT Receiver Actor
#[derive(xtra::Actor)]
pub struct KOSReceiverActor {
    config: OTActorReceiverConfig,
    /// This sink is not used at the moment. Future features may require the KOSReceiverActor to
    /// send messages to the KOSSenderActor, so we keep this around.
    _sink: SplitSink<OTChannel, OTMessage>,
    /// Local muxer which sets up channels with the remote KOSSenderActor
    mux_control: Box<dyn MuxChannel<OTMessage> + Send>,
    state: State,
    /// A buffer of ready-to-use OTs which have not yet been requested by a local caller
    child_buffer: HashMap<String, Result<Kos15IOReceiver<RandSetup>, OTError>>,
    /// A buffer of local callers which have requested OTs. As soon as we synchronize OT
    /// splitting with the remote KOSSenderActor, we will send OTs to the callers.
    pending_buffer: HashMap<String, oneshot::Sender<Result<Kos15IOReceiver<RandSetup>, OTError>>>,
}

impl KOSReceiverActor {
    /// Creates a new KOSReceiverActor
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the receiver
    /// * `addr` - The address of the receiver
    /// * `channel` - The channel over which OT splits are synchronized with the remote
    ///               KOSSenderActor
    /// * `mux_control` - The muxer which sets up channels with the remote KOSSenderActor
    pub fn new(
        config: OTActorReceiverConfig,
        addr: Address<Self>,
        channel: OTChannel,
        mux_control: Box<dyn MuxChannel<OTMessage> + Send>,
    ) -> (Self, impl Future<Output = ()>) {
        let (sink, mut stream) = channel.split();
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                config,
                _sink: sink,
                mux_control,
                state: State::Initialized(sender),
                child_buffer: HashMap::default(),
                pending_buffer: HashMap::default(),
            },
            scoped(&addr.clone(), async move {
                // wait for actor to signal that it is set up before we start
                // processing these messages
                _ = receiver.await;
                while let Some(msg) = stream.next().await {
                    match msg {
                        Ok(OTMessage::Split(msg)) => {
                            // Forward message to actor, ignore result.
                            _ = addr.send(msg).await
                        }
                        _ => {
                            // Shutdown if we receive any unexpected message
                            break;
                        }
                    };
                }
            })
            .map(|_| ()),
        )
    }
}

#[async_trait]
impl Handler<Setup> for KOSReceiverActor {
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
            .get_channel(&format!("{}/parent", self.config.id))
            .await?;

        let mut parent_ot = Kos15IOReceiver::new(parent_ot_channel);

        if self.config.committed {
            parent_ot.accept_commit().await?;
        }

        let parent_ot = parent_ot.rand_setup(self.config.initial_count).await?;

        self.state = State::Setup {
            receiver: parent_ot,
            child_receivers: HashMap::new(),
        };

        // Signal to OTMessage stream that we're ready to process messages
        _ = setup_signal.send(());

        Ok(())
    }
}

#[async_trait]
impl Handler<Split> for KOSReceiverActor {
    type Return = Result<(), OTError>;

    /// Handles the Split message. This message is sent by the remote KOSSenderActor.
    async fn handle(&mut self, msg: Split, _ctx: &mut Context<Self>) -> Result<(), OTError> {
        let Split { id, count } = msg;

        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        // These messages should not start being processed until after setup
        // so this is a fatal error
        let State::Setup{ receiver, child_receivers } = state else {
            return Err(OTError::Other("KOSReceiverActor is not setup".to_string()));
        };

        // Open channel to the OT sender
        let child_channel = self.mux_control.get_channel(&id).await?;
        // Split off OTs
        let (receiver, child_ot) = receiver.split(child_channel, count)?;

        // If a caller is already waiting, send it right away
        if let Some(sender) = self.pending_buffer.remove(&id) {
            _ = sender.send(Ok(child_ot));
        } else {
            // Otherwise insert child OT into buffer
            self.child_buffer.insert(id, Ok(child_ot));
        }

        self.state = State::Setup {
            receiver,
            child_receivers,
        };

        Ok(())
    }
}

#[async_trait]
impl Handler<GetReceiver> for KOSReceiverActor {
    type Return = oneshot::Receiver<Result<Kos15IOReceiver<RandSetup>, OTError>>;

    /// Handles the GetReceiver message
    #[allow(clippy::async_yields_async)]
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

#[async_trait]
impl Handler<SendBackReceiver> for KOSReceiverActor {
    type Return = Result<(), OTError>;

    /// Handles the SendBackReceiver message
    async fn handle(
        &mut self,
        msg: SendBackReceiver,
        _ctx: &mut Context<Self>,
    ) -> Result<(), OTError> {
        let SendBackReceiver { id, child_receiver } = msg;

        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        // These messages should not start being processed until after setup
        // so this is a fatal error
        let State::Setup{ receiver, mut child_receivers } = state else {
            return Err(OTError::Other("KOSReceiverActor is not setup".to_string()));
        };

        // Insert child receiver into map
        child_receivers.insert(id, child_receiver);

        self.state = State::Setup {
            receiver,
            child_receivers,
        };

        Ok(())
    }
}

#[async_trait]
impl Handler<Verify> for KOSReceiverActor {
    type Return =
        Result<Pin<Box<dyn Future<Output = Result<(), OTError>> + Send + 'static>>, OTError>;

    /// Handles the Verify message
    async fn handle(&mut self, msg: Verify, _ctx: &mut Context<Self>) -> Self::Return {
        let Verify { id, input } = msg;

        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        // These messages should not start being processed until after setup
        // so this is a fatal error
        let State::Setup{ receiver, mut child_receivers } = state else {
            return Err(OTError::Other("KOSReceiverActor is not setup".to_string()));
        };

        // Get child receiver
        let child_receiver = child_receivers.remove(&id).ok_or(OTError::Other(format!(
            "KOSReceiverActor does not have child receiver for id {}",
            id
        )))?;

        // Verify child receiver
        let result = child_receiver.verify(input);

        self.state = State::Setup {
            receiver,
            child_receivers,
        };

        Ok(result)
    }
}

/// Control handle for KOSReceiverActor
#[derive(Debug)]
pub struct ReceiverActorControl(Address<KOSReceiverActor>);

impl Clone for ReceiverActorControl {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl ReceiverActorControl {
    /// Creates a new ReceiverActorControl
    pub fn new(address: Address<KOSReceiverActor>) -> Self {
        Self(address)
    }

    /// Returns mutable reference to address
    pub fn address_mut(&mut self) -> &mut Address<KOSReceiverActor> {
        &mut self.0
    }

    /// Sends Setup message to actor
    pub async fn setup(&mut self) -> Result<(), OTError> {
        self.0
            .send(Setup)
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}

#[async_trait]
impl ObliviousReceive<bool, Block> for ReceiverActorControl {
    async fn receive(&self, id: &str, choices: Vec<bool>) -> Result<Vec<Block>, OTError> {
        let mut child_receiver = self
            .0
            .send(GetReceiver {
                id: id.to_owned(),
                count: choices.len(),
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
            .await??;

        let output = child_receiver.receive(choices).await?;
        self.0
            .send(SendBackReceiver {
                id: id.to_owned(),
                child_receiver,
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))??;
        Ok(output)
    }
}

#[async_trait]
impl<const N: usize> ObliviousReceive<bool, [Block; N]> for ReceiverActorControl {
    async fn receive(&self, id: &str, choices: Vec<bool>) -> Result<Vec<[Block; N]>, OTError> {
        let mut child_receiver = self
            .0
            .send(GetReceiver {
                id: id.to_owned(),
                count: choices.len(),
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
            .await??;

        let output = child_receiver.receive(choices).await?;
        self.0
            .send(SendBackReceiver {
                id: id.to_owned(),
                child_receiver,
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))??;
        Ok(output)
    }
}

#[async_trait]
impl ObliviousVerify<[Block; 2]> for ReceiverActorControl {
    async fn verify(&self, id: &str, input: Vec<[Block; 2]>) -> Result<(), OTError> {
        let verify_future = self
            .0
            .send(Verify {
                id: id.to_owned(),
                input,
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))??;

        verify_future.await
    }
}
