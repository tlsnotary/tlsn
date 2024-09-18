use ludi::Message;

use crate::error::Kind;
use crate::msg::{
    ClientFinishedVd, CloseConnection, Commit, CommitMessage, ComputeKeyExchange, DecryptAlert,
    DecryptMessage, DecryptServerFinished, EncryptAlert, EncryptClientFinished, EncryptMessage,
    MpcTlsMessage, ServerFinishedVd,
};
use crate::MpcTlsError;

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
    type Return = ();
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
