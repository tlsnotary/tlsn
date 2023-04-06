use crate::{config::OTActorSenderConfig, GetSender, MarkForReveal, Reveal, Setup};
use async_trait::async_trait;
use futures::{stream::SplitSink, Future, SinkExt, StreamExt};
use mpc_core::Block;
use mpc_ot::{
    kos::sender::Kos15IOSender, OTError, ObliviousCommit, ObliviousReveal, ObliviousSend,
};
use mpc_ot_core::{
    msgs::{OTMessage, Split},
    s_state::RandSetup,
};
use utils_aio::{mux::MuxChannelControl, Channel};
use xtra::{prelude::*, scoped};

pub enum State {
    Initialized,
    Setup {
        sender: Kos15IOSender<RandSetup>,
        child_senders: Vec<Kos15IOSender<RandSetup>>,
    },
    Error,
}

#[derive(xtra::Actor)]
pub struct KOSSenderActor<T, U> {
    config: OTActorSenderConfig,
    sink: SplitSink<T, OTMessage>,
    /// Local muxer which sets up channels with the remote KOSReceiverActor
    mux_control: U,
    state: State,
}

impl<T, U> KOSSenderActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    pub fn new(
        config: OTActorSenderConfig,
        addr: Address<Self>,
        // the channel over which OT splits are synchronized with the remote
        // KOSReceiverActor
        channel: T,
        mux_control: U,
    ) -> (Self, impl Future<Output = Option<Result<(), OTError>>>) {
        let (sink, mut stream) = channel.split();

        let fut = scoped(&addr, async move {
            while let Some(msg) = stream.next().await {
                // The receiver factory shouldn't send messages
                return Err(OTError::Unexpected(msg));
            }
            Ok(())
        });

        (
            Self {
                config,
                sink,
                mux_control,
                state: State::Initialized,
            },
            fut,
        )
    }
}

#[async_trait]
impl<T, U> Handler<Setup> for KOSSenderActor<T, U>
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

        let State::Initialized = state else {
            return Err(OTError::Other(
                "KOSSenderActor is already setup".to_string(),
            ));
        };

        let parent_ot_channel = self
            .mux_control
            .get_channel(self.config.ot_id.clone())
            .await?;
        let mut parent_ot = Kos15IOSender::new(parent_ot_channel);

        if self.config.committed {
            parent_ot.commit().await?;
        }

        let parent_ot = parent_ot.rand_setup(self.config.initial_count).await?;

        self.state = State::Setup {
            sender: parent_ot,
            child_senders: vec![],
        };

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<GetSender> for KOSSenderActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
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
        let child_channel_fut = self.mux_control.get_channel(id.clone());

        // Send split information to receiver
        let msg = Split { id, count };
        let send_msg_fut = self.sink.send(OTMessage::Split(msg));

        // Get channel and send message concurrently
        let (child_channel, send_msg) = futures::join!(child_channel_fut, send_msg_fut);
        let child_channel = child_channel?;
        _ = send_msg?;

        let (parent_ot, child_ot) = sender.split(child_channel, count)?;

        self.state = State::Setup {
            sender,
            child_senders,
        };

        Ok(child_ot)
    }
}

#[async_trait]
impl<T, U> Handler<MarkForReveal> for KOSSenderActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<(), OTError>;

    /// Handles the Verify message
    async fn handle(&mut self, msg: MarkForReveal, _ctx: &mut Context<Self>) -> Self::Return {
        if !self.config.committed {
            return Err(OTError::Other(
                "KOSSenderActor not configured for committed OT".to_string(),
            ));
        }

        // Leave actor in error state
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup{sender, child_senders} = state else {
            return Err(OTError::Other("KOSSenderActor is not setup".to_string()));
        };

        child_senders.push(msg.0);

        self.state = State::Setup {
            sender,
            child_senders,
        };

        Ok(())
    }
}

#[async_trait]
impl<T, U> Handler<Reveal> for KOSSenderActor<T, U>
where
    T: Channel<OTMessage, Error = std::io::Error> + Send + 'static,
    U: MuxChannelControl<OTMessage> + Send + 'static,
{
    type Return = Result<(), OTError>;

    /// Handles the Reveal message
    async fn handle(&mut self, msg: Reveal, ctx: &mut Context<Self>) -> Self::Return {
        if !self.config.committed {
            return Err(OTError::Other(
                "KOSSenderActor not configured for committed OT".to_string(),
            ));
        }

        // Leave actor in error state
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup{sender, child_senders} = state else {
            return Err(OTError::Other("KOSSenderActor is not setup".to_string()));
        };

        for s in child_senders {
            s.reveal().await?;
        }
        ctx.stop_self();
        Ok(())
    }
}

pub struct SenderActorControl<T> {
    address: Address<T>,
    child_sender: Option<Kos15IOSender<RandSetup>>,
}

impl<T> Clone for SenderActorControl<T> {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            child_sender: None,
        }
    }
}

impl<T> SenderActorControl<T>
where
    T: Handler<Setup, Return = Result<(), OTError>>
        + Handler<MarkForReveal, Return = Result<(), OTError>>,
{
    pub fn new(addr: Address<T>) -> Self {
        Self {
            address: addr,
            child_sender: None,
        }
    }

    /// Returns mutable reference to address
    pub fn address(&mut self) -> &mut Address<T> {
        &mut self.address
    }

    /// Sends setup message to actor
    pub async fn setup(&mut self) -> Result<(), OTError> {
        self.address
            .send(Setup)
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }

    pub async fn mark_for_reveal(&mut self) -> Result<(), OTError> {
        let child_sender = self.child_sender.take().ok_or(OTError::Other(
            "No KOSSender instance available to reveal".to_string(),
        ))?;
        self.address
            .send(MarkForReveal(child_sender))
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}

#[async_trait]
impl<T> ObliviousSend<[Block; 2]> for SenderActorControl<T>
where
    T: Handler<GetSender, Return = Result<Kos15IOSender<RandSetup>, OTError>>,
{
    async fn send(&mut self, id: String, inputs: Vec<[Block; 2]>) -> Result<(), OTError> {
        let sender = self
            .address
            .send(GetSender {
                id,
                count: inputs.len(),
            })
            .await
            .map_err(|e| OTError::Other(e.to_string()))??;

        self.child_sender = Some(sender);
        self.child_sender.unwrap().send(id, inputs).await
    }
}

#[async_trait]
impl<T> ObliviousReveal for SenderActorControl<T>
where
    T: Handler<Reveal, Return = Result<(), OTError>>,
{
    async fn reveal(mut self) -> Result<(), OTError> {
        self.address
            .send(Reveal)
            .await
            .map_err(|e| OTError::Other(e.to_string()))?
    }
}
