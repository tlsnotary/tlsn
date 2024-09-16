use std::future::Future;

use super::{MpcTlsData, MpcTlsLeader};
use crate::{leader::state, msg::MpcTlsLeaderMsg, MpcTlsError};
use ludi::{mailbox, Actor, Address, Context, Dispatch, Handler, Message};
use tracing::{debug, Instrument};

#[derive(Debug, Clone)]
pub struct MpcTlsLeaderCtrl {
    address: Address<MpcTlsLeaderMsg>,
}

impl MpcTlsLeaderCtrl {
    /// Creates a new control for [`MpcTlsLeader`].
    pub fn new(address: Address<MpcTlsLeaderMsg>) -> Self {
        Self { address }
    }
}

impl MpcTlsLeader {
    /// Runs the leader actor.
    ///
    /// Returns a control handle and a future that resolves when the actor is stopped.
    ///
    /// # Note
    ///
    /// The future must be polled continuously to make progress.
    pub fn run(
        mut self,
    ) -> (
        MpcTlsLeaderCtrl,
        impl Future<Output = Result<MpcTlsData, MpcTlsError>>,
    ) {
        let (mut mailbox, address) = mailbox(100);

        let ctrl = MpcTlsLeaderCtrl::new(address);
        let fut = async move { ludi::run(&mut self, &mut mailbox).await };

        (ctrl, fut.in_current_span())
    }
}

impl Actor for MpcTlsLeader {
    type Stop = MpcTlsData;
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("leader actor stopped");

        let state::Closed { data } = self.state.take().try_into_closed()?;

        Ok(data)
    }
}

impl Dispatch<MpcTlsLeader> for MpcTlsLeaderMsg {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut Context<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<MpcTlsLeaderMsg> for MpcTlsLeader {
    fn handle(
        &mut self,
        msg: MpcTlsLeaderMsg,
        ctx: &mut Context<Self>,
    ) -> impl Future<Output = <MpcTlsLeaderMsg as Message>::Return> + Send {
        match msg {
            MpcTlsLeaderMsg::BackendMsgSetProtocolVersion(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetCipherSuite(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgGetSuite(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetEncrypt(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetDecrypt(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgGetClientRandom(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgGetClientKeyShare(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetServerRandom(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetServerKeyShare(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetServerCertDetails(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetServerKxDetails(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetHsHashClientKeyExchange(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgSetHsHashServerHello(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgGetServerFinishedVd(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgGetClientFinishedVd(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgPrepareEncryption(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgEncrypt(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgDecrypt(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgNextIncoming(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgBufferIncoming(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgGetNotify(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgBufferLen(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::BackendMsgServerClosed(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::DeferDecryption(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::CloseConnection(msg) => self.handle(msg, ctx),
            MpcTlsLeaderMsg::Finalize(msg) => self.handle(msg, ctx),
        }
    }
}
