//! Messages for the follower actor.

use ::ludi::{Context, Message};
use ludi::Dispatch;

use crate::error::Kind;
use crate::msg::{
    ClientFinishedVd, CloseConnection, Commit, CommitMessage, ComputeKeyExchange, DecryptAlert,
    DecryptMessage, DecryptServerFinished, EncryptAlert, EncryptClientFinished, EncryptMessage,
    MpcTlsMessage, ServerFinishedVd,
};
use crate::{MpcTlsError, MpcTlsFollower};

#[allow(missing_docs)]
#[derive(Debug)]
pub enum MpcTlsFollowerMsg {
    ComputeKeyExchange(ComputeKeyExchange),
    ClientFinishedVd(ClientFinishedVd),
    EncryptClientFinished(EncryptClientFinished),
    EncryptAlert(EncryptAlert),
    ServerFinishedVd(ServerFinishedVd),
    DecryptServerFinished(DecryptServerFinished),
    DecryptAlert(DecryptAlert),
    CommitMessage(CommitMessage),
    EncryptMessage(EncryptMessage),
    DecryptMessage(DecryptMessage),
    CloseConnection(CloseConnection),
    Finalize(Commit),
}

impl Message for MpcTlsFollowerMsg {
    type Return = MpcTlsFollowerMsgReturn;
}

#[allow(missing_docs)]
pub enum MpcTlsFollowerMsgReturn {
    ComputeKeyExchange(<ComputeKeyExchange as Message>::Return),
    ClientFinishedVd(<ClientFinishedVd as Message>::Return),
    EncryptClientFinished(<EncryptClientFinished as Message>::Return),
    EncryptAlert(<EncryptAlert as Message>::Return),
    ServerFinishedVd(<ServerFinishedVd as Message>::Return),
    DecryptServerFinished(<DecryptServerFinished as Message>::Return),
    DecryptAlert(<DecryptAlert as Message>::Return),
    CommitMessage(<CommitMessage as Message>::Return),
    EncryptMessage(<EncryptMessage as Message>::Return),
    DecryptMessage(<DecryptMessage as Message>::Return),
    CloseConnection(<CloseConnection as Message>::Return),
    Finalize(<Commit as Message>::Return),
}

impl Dispatch<MpcTlsFollower> for MpcTlsFollowerMsg {
    async fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut Context<MpcTlsFollower>,
        ret: R,
    ) {
        match self {
            MpcTlsFollowerMsg::ComputeKeyExchange(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::ComputeKeyExchange(value))
                })
                .await;
            }
            MpcTlsFollowerMsg::ClientFinishedVd(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::ClientFinishedVd(value))
                })
                .await;
            }
            MpcTlsFollowerMsg::EncryptClientFinished(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::EncryptClientFinished(value))
                })
                .await;
            }
            MpcTlsFollowerMsg::EncryptAlert(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::EncryptAlert(value)))
                    .await;
            }
            MpcTlsFollowerMsg::ServerFinishedVd(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::ServerFinishedVd(value))
                })
                .await;
            }
            MpcTlsFollowerMsg::DecryptServerFinished(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::DecryptServerFinished(value))
                })
                .await;
            }
            MpcTlsFollowerMsg::DecryptAlert(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::DecryptAlert(value)))
                    .await;
            }
            MpcTlsFollowerMsg::CommitMessage(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::CommitMessage(value)))
                    .await;
            }
            MpcTlsFollowerMsg::EncryptMessage(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::EncryptMessage(value)))
                    .await;
            }
            MpcTlsFollowerMsg::DecryptMessage(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::DecryptMessage(value)))
                    .await;
            }
            MpcTlsFollowerMsg::CloseConnection(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::CloseConnection(value))
                })
                .await;
            }
            MpcTlsFollowerMsg::Finalize(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::Finalize(value)))
                    .await;
            }
        }
    }
}

impl TryFrom<MpcTlsMessage> for MpcTlsFollowerMsg {
    type Error = MpcTlsError;

    fn try_from(msg: MpcTlsMessage) -> Result<Self, Self::Error> {
        #[allow(unreachable_patterns)]
        match msg {
            MpcTlsMessage::ComputeKeyExchange(msg) => Ok(Self::ComputeKeyExchange(msg)),
            MpcTlsMessage::ClientFinishedVd(msg) => Ok(Self::ClientFinishedVd(msg)),
            MpcTlsMessage::EncryptClientFinished(msg) => Ok(Self::EncryptClientFinished(msg)),
            MpcTlsMessage::EncryptAlert(msg) => Ok(Self::EncryptAlert(msg)),
            MpcTlsMessage::ServerFinishedVd(msg) => Ok(Self::ServerFinishedVd(msg)),
            MpcTlsMessage::DecryptServerFinished(msg) => Ok(Self::DecryptServerFinished(msg)),
            MpcTlsMessage::DecryptAlert(msg) => Ok(Self::DecryptAlert(msg)),
            MpcTlsMessage::CommitMessage(msg) => Ok(Self::CommitMessage(msg)),
            MpcTlsMessage::EncryptMessage(msg) => Ok(Self::EncryptMessage(msg)),
            MpcTlsMessage::DecryptMessage(msg) => Ok(Self::DecryptMessage(msg)),
            MpcTlsMessage::CloseConnection(msg) => Ok(Self::CloseConnection(msg)),
            MpcTlsMessage::Commit(msg) => Ok(Self::Finalize(msg)),
            msg => Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                format!("peer sent unexpected message: {:?}", msg),
            )),
        }
    }
}

impl Message for ComputeKeyExchange {
    type Return = Option<()>;
}

impl Message for ClientFinishedVd {
    type Return = Option<()>;
}

impl Message for EncryptClientFinished {
    type Return = Option<()>;
}

impl Message for EncryptAlert {
    type Return = Option<()>;
}

impl Message for ServerFinishedVd {
    type Return = Option<()>;
}

impl Message for DecryptServerFinished {
    type Return = Option<()>;
}

impl Message for DecryptAlert {
    type Return = Option<()>;
}

impl Message for CommitMessage {
    type Return = ();
}

impl Message for EncryptMessage {
    type Return = Option<()>;
}

impl Message for DecryptMessage {
    type Return = Option<()>;
}

impl Message for CloseConnection {
    type Return = Option<()>;
}

impl Message for Commit {
    type Return = Option<()>;
}
