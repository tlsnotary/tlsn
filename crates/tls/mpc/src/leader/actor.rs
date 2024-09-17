use std::future::Future;

use super::{MpcTlsData, MpcTlsLeader};
use crate::{
    leader::state,
    msg::mpc_tls_leader_msg::{CloseConnection, Commit, DeferDecryption, MpcTlsLeaderMsg},
    MpcTlsError,
};
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
        async {
            match self {
                MpcTlsLeaderMsg::BackendMsgSetProtocolVersion(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetProtocolVersion(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetCipherSuite(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetCipherSuite(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgGetSuite(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgGetSuite(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetEncrypt(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetEncrypt(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetDecrypt(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetDecrypt(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgGetClientRandom(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgGetClientRandom(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgGetClientKeyShare(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgGetClientKeyShare(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetServerRandom(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetServerRandom(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetServerKeyShare(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetServerKeyShare(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetServerCertDetails(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetServerCertDetails(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetServerKxDetails(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetServerKxDetails(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetHsHashClientKeyExchange(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetHsHashClientKeyExchange(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgSetHsHashServerHello(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgSetHsHashServerHello(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgGetServerFinishedVd(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgGetServerFinishedVd(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgGetClientFinishedVd(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgGetClientFinishedVd(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgPrepareEncryption(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgPrepareEncryption(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgEncrypt(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgEncrypt(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgDecrypt(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgDecrypt(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgNextIncoming(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgNextIncoming(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgBufferIncoming(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgBufferIncoming(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgGetNotify(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgGetNotify(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgBufferLen(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgBufferLen(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::BackendMsgServerClosed(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::BackendMsgServerClosed(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::DeferDecryption(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::DeferDecryption(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::CloseConnection(msg) => {
                    msg.dispatch(actor, ctx, |value| {
                        ret(Self::Return::CloseConnection(value))
                    })
                    .await;
                }
                MpcTlsLeaderMsg::Finalize(msg) => {
                    msg.dispatch(actor, ctx, |value| ret(Self::Return::Finalize(value)))
                        .await;
                }
            }
        }
    }
}

impl MpcTlsLeaderCtrl {
    /// Commits the leader to the current transcript.
    ///
    /// This reveals the AEAD key to the leader and disables sending or receiving
    /// any further messages.
    pub async fn commit(&self) -> Result<(), MpcTlsError> {
        self.address.send(MpcTlsLeaderMsg::Finalize(Commit)).await?
    }

    /// Closes the connection.
    pub async fn close_connection(&self) -> Result<(), MpcTlsError> {
        self.address
            .send(MpcTlsLeaderMsg::CloseConnection(CloseConnection))
            .await?
    }

    /// Defers decryption of any incoming messages.
    pub async fn defer_decryption(&self) -> Result<(), MpcTlsError> {
        self.address
            .send(MpcTlsLeaderMsg::DeferDecryption(DeferDecryption))
            .await?
    }
}

impl Dispatch<MpcTlsLeader> for Commit {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut Context<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<Commit> for MpcTlsLeader {
    fn handle(
        &mut self,
        _msg: Commit,
        _ctx: &mut Context<Self>,
    ) -> impl Future<Output = <Commit as Message>::Return> + Send {
        async { self.commit().await }
    }
}

impl Dispatch<MpcTlsLeader> for CloseConnection {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut Context<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<CloseConnection> for MpcTlsLeader {
    fn handle(
        &mut self,
        _msg: CloseConnection,
        ctx: &mut Context<Self>,
    ) -> impl Future<Output = <CloseConnection as Message>::Return> + Send {
        async { self.close_connection(ctx).await }
    }
}

impl Dispatch<MpcTlsLeader> for DeferDecryption {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut Context<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<DeferDecryption> for MpcTlsLeader {
    fn handle(
        &mut self,
        _msg: DeferDecryption,
        _ctx: &mut Context<Self>,
    ) -> impl Future<Output = <DeferDecryption as Message>::Return> + Send {
        async { self.defer_decryption().await }
    }
}
