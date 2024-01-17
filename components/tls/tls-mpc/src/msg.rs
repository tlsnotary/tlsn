//! Contains message types for communication between leader and follower

use serde::{Deserialize, Serialize};

use crate::{
    error::Kind,
    follower::{
        ClientFinishedVd, CommitMessage, ComputeClientKey, ComputeKeyExchange, DecryptAlert,
        DecryptMessage, DecryptServerFinished, EncryptAlert, EncryptClientFinished, EncryptMessage,
        ServerFinishedVd,
    },
    leader::{
        BackendMsgBufferIncoming, BackendMsgDecrypt, BackendMsgEncrypt,
        BackendMsgGetClientFinishedVd, BackendMsgGetClientKeyShare, BackendMsgGetClientRandom,
        BackendMsgGetServerFinishedVd, BackendMsgGetSuite, BackendMsgNextIncoming,
        BackendMsgPrepareEncryption, BackendMsgSetCipherSuite, BackendMsgSetDecrypt,
        BackendMsgSetEncrypt, BackendMsgSetHsHashClientKeyExchange, BackendMsgSetHsHashServerHello,
        BackendMsgSetProtocolVersion, BackendMsgSetServerCertDetails, BackendMsgSetServerKeyShare,
        BackendMsgSetServerKxDetails, BackendMsgSetServerRandom,
    },
    MpcTlsError,
};

/// MPC-TLS protocol message.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub enum MpcTlsMessage {
    ComputeClientKey(ComputeClientKey),
    ComputeKeyExchange(ComputeKeyExchange),
    ClientFinishedVd(ClientFinishedVd),
    EncryptClientFinished(EncryptClientFinished),
    EncryptAlert(EncryptAlert),
    ServerFinishedVd(ServerFinishedVd),
    DecryptServerFinished(DecryptServerFinished),
    DecryptAlert(DecryptAlert),
    /// A leader commitment to a TLS message received from the server.
    CommitMessage(CommitMessage),
    EncryptMessage(EncryptMessage),
    DecryptMessage(DecryptMessage),
    CloseConnection(CloseConnection),
    Finalize(Finalize),
}

impl TryFrom<MpcTlsMessage> for MpcTlsFollowerMsg {
    type Error = MpcTlsError;

    fn try_from(msg: MpcTlsMessage) -> Result<Self, Self::Error> {
        #[allow(unreachable_patterns)]
        match msg {
            MpcTlsMessage::ComputeClientKey(msg) => Ok(Self::ComputeClientKey(msg)),
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
            MpcTlsMessage::Finalize(msg) => Ok(Self::Finalize(msg)),
            msg => Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                format!("peer sent unexpected message: {:?}", msg),
            )),
        }
    }
}

#[derive(ludi::Wrap)]
#[allow(missing_docs)]
#[ludi(return_attrs(allow(missing_docs)))]
pub enum MpcTlsLeaderMsg {
    BackendMsgSetProtocolVersion(BackendMsgSetProtocolVersion),
    BackendMsgSetCipherSuite(BackendMsgSetCipherSuite),
    BackendMsgGetSuite(BackendMsgGetSuite),
    BackendMsgSetEncrypt(BackendMsgSetEncrypt),
    BackendMsgSetDecrypt(BackendMsgSetDecrypt),
    BackendMsgGetClientRandom(BackendMsgGetClientRandom),
    BackendMsgGetClientKeyShare(BackendMsgGetClientKeyShare),
    BackendMsgSetServerRandom(BackendMsgSetServerRandom),
    BackendMsgSetServerKeyShare(BackendMsgSetServerKeyShare),
    BackendMsgSetServerCertDetails(BackendMsgSetServerCertDetails),
    BackendMsgSetServerKxDetails(BackendMsgSetServerKxDetails),
    BackendMsgSetHsHashClientKeyExchange(BackendMsgSetHsHashClientKeyExchange),
    BackendMsgSetHsHashServerHello(BackendMsgSetHsHashServerHello),
    BackendMsgGetServerFinishedVd(BackendMsgGetServerFinishedVd),
    BackendMsgGetClientFinishedVd(BackendMsgGetClientFinishedVd),
    BackendMsgPrepareEncryption(BackendMsgPrepareEncryption),
    BackendMsgEncrypt(BackendMsgEncrypt),
    BackendMsgDecrypt(BackendMsgDecrypt),
    BackendMsgNextIncoming(BackendMsgNextIncoming),
    BackendMsgBufferIncoming(BackendMsgBufferIncoming),
    CloseConnection(CloseConnection),
    Finalize(Finalize),
}

#[derive(ludi::Wrap)]
#[allow(missing_docs)]
#[ludi(return_attrs(allow(missing_docs)))]
pub enum MpcTlsFollowerMsg {
    ComputeClientKey(ComputeClientKey),
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
    Finalize(Finalize),
}

/// Message to close the connection
#[derive(Debug, ludi::Message, Serialize, Deserialize)]
#[ludi(return_ty = "Result<(), MpcTlsError>")]
pub struct CloseConnection;

/// Message to finalize the MPC-TLS protocol
#[derive(Debug, ludi::Message, Serialize, Deserialize)]
#[ludi(return_ty = "Result<(), MpcTlsError>")]
pub struct Finalize;
