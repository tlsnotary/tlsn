use crate::{config::OTActorSenderConfig, GetSender, Reveal, SendBackSender, Setup};
use async_trait::async_trait;
use futures::{
    stream::{FuturesUnordered, SplitSink},
    Future, FutureExt, SinkExt, StreamExt, TryStreamExt,
};
use mpc_core::Block;
use mpc_ot::{
    kos::sender::Kos15IOSender, OTChannel, OTError, ObliviousCommitOwned, ObliviousReveal,
    ObliviousRevealOwned, ObliviousSend, ObliviousSendOwned,
};
use mpc_ot_core::{
    msgs::{OTMessage, Split},
    s_state::RandSetup,
};
use std::collections::HashMap;
use utils_aio::mux::MuxChannel;
use xtra::{prelude::*, scoped};

#[allow(clippy::large_enum_variant)]
enum State {
    Initialized,
    Setup {
        sender: Kos15IOSender<RandSetup>,
        child_senders: HashMap<String, Kos15IOSender<RandSetup>>,
    },
    Error,
}

/// KOS OT Sender Actor
#[derive(xtra::Actor)]
pub struct KOSSenderActor {
    config: OTActorSenderConfig,
    sink: SplitSink<OTChannel, OTMessage>,
    /// Local muxer which sets up channels with the remote KOSReceiverActor
    mux_control: Box<dyn MuxChannel<OTMessage> + Send>,
    state: State,
}

impl KOSSenderActor {
    /// Creates a new KOSSenderActor
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the sender
    /// * `addr` - The address of the sender
    /// * `channel` - The channel over which OT splits are synchronized with the remote
    ///               KOSReceiverActor
    /// * `mux_control` - The muxer which sets up channels with the remote KOSReceiverActor
    pub fn new(
        config: OTActorSenderConfig,
        addr: Address<Self>,
        channel: OTChannel,
        mux_control: Box<dyn MuxChannel<OTMessage> + Send>,
    ) -> (Self, impl Future<Output = ()>) {
        let (sink, mut stream) = channel.split();

        (
            Self {
                config,
                sink,
                mux_control,
                state: State::Initialized,
            },
            scoped(&addr, async move {
                while stream.next().await.is_some() {
                    // Receiver should not send messages, we just discard.
                    continue;
                }
            })
            .map(|_| ()),
        )
    }
}

#[async_trait]
impl Handler<Setup> for KOSSenderActor {
    type Return = Result<(), OTError>;

    /// Handles the Setup message
    async fn handle(&mut self, _msg: Setup, _ctx: &mut Context<Self>) -> Result<(), OTError> {
        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Initialized = state else {
            return Err(OTError::Other(
                "KOSSenderActor is already setup".to_string(),
            ));
        };

        let parent_ot_channel = self
            .mux_control
            .get_channel(&format!("{}/parent", self.config.id))
            .await?;
        let mut parent_ot = Kos15IOSender::new(parent_ot_channel);

        if self.config.committed {
            parent_ot.commit().await?;
        }

        let parent_ot = parent_ot.rand_setup(self.config.initial_count).await?;

        self.state = State::Setup {
            sender: parent_ot,
            child_senders: HashMap::new(),
        };

        Ok(())
    }
}

#[async_trait]
impl Handler<GetSender> for KOSSenderActor {
    type Return = Result<Kos15IOSender<RandSetup>, OTError>;

    /// Handles the GetSender message
    async fn handle(
        &mut self,
        msg: GetSender,
        _ctx: &mut Context<Self>,
    ) -> Result<Kos15IOSender<RandSetup>, OTError> {
        let GetSender { id, count } = msg;

        // We move the state into scope and replace with error state
        // in case of early returns
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup{sender, child_senders} = state else {
            return Err(OTError::Other("KOSSenderActor is not setup".to_string()));
        };

        // Open channel to receiver
        let child_channel_fut = self.mux_control.get_channel(&id);

        // Send split information to receiver
        let msg = Split {
            id: id.clone(),
            count,
        };
        let send_msg_fut = self.sink.send(OTMessage::Split(msg));

        // Get channel and send message concurrently
        let (child_channel, send_msg) = futures::join!(child_channel_fut, send_msg_fut);
        let child_channel = child_channel?;
        _ = send_msg?;

        let (sender, child_ot) = sender.split(child_channel, count)?;

        self.state = State::Setup {
            sender,
            child_senders,
        };

        Ok(child_ot)
    }
}

#[async_trait]
impl Handler<Reveal> for KOSSenderActor {
    type Return = Result<(), OTError>;

    /// Handles the Reveal message
    async fn handle(&mut self, _msg: Reveal, ctx: &mut Context<Self>) -> Self::Return {
        if !self.config.committed {
            return Err(OTError::Other(
                "KOSSenderActor not configured for committed OT".to_string(),
            ));
        }

        // Leave actor in error state
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup{child_senders, ..} = state else {
            return Err(OTError::Other("KOSSenderActor is not setup".to_string()));
        };
        ctx.stop_self();

        let futures: FuturesUnordered<_> = child_senders
            .into_values()
            .map(|child_sender| child_sender.reveal())
            .collect();
        futures.try_collect::<Vec<_>>().await?;
        Ok(())
    }
}

#[async_trait]
impl Handler<SendBackSender> for KOSSenderActor {
    type Return = Result<(), OTError>;

    /// Handles the SendBackSender message
    async fn handle(&mut self, msg: SendBackSender, _ctx: &mut Context<Self>) -> Self::Return {
        let SendBackSender { id, child_sender } = msg;

        // Leave actor in error state
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup{sender, mut child_senders} = state else {
            return Err(OTError::Other("KOSSenderActor is not setup".to_string()));
        };

        child_senders.insert(id, child_sender);

        self.state = State::Setup {
            sender,
            child_senders,
        };

        Ok(())
    }
}

/// Control handle for the KOSSenderActor
pub struct SenderActorControl(Address<KOSSenderActor>);

impl Clone for SenderActorControl {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl SenderActorControl {
    /// Creates a new SenderActorControl
    pub fn new(address: Address<KOSSenderActor>) -> Self {
        Self(address)
    }

    /// Returns mutable reference to address
    pub fn address(&mut self) -> &mut Address<KOSSenderActor> {
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
impl ObliviousSend<[Block; 2]> for SenderActorControl {
    async fn send(&self, id: &str, inputs: Vec<[Block; 2]>) -> Result<(), OTError> {
        let mut child_sender = self
            .0
            .send(GetSender {
                id: id.to_owned(),
                count: inputs.len(),
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))??;

        child_sender.send(inputs).await?;

        self.0
            .send(SendBackSender {
                id: id.to_owned(),
                child_sender,
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}

#[async_trait]
impl<const N: usize> ObliviousSend<[[Block; N]; 2]> for SenderActorControl {
    async fn send(&self, id: &str, inputs: Vec<[[Block; N]; 2]>) -> Result<(), OTError> {
        let mut child_sender = self
            .0
            .send(GetSender {
                id: id.to_owned(),
                count: inputs.len(),
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))??;

        child_sender.send(inputs).await?;

        self.0
            .send(SendBackSender {
                id: id.to_owned(),
                child_sender,
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}

#[async_trait]
impl ObliviousReveal for SenderActorControl {
    async fn reveal(&self) -> Result<(), OTError> {
        self.0
            .send(Reveal)
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}
