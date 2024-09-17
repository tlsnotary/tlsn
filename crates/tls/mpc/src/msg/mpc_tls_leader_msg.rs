use crate::MpcTlsError;
use ludi::Message;

#[derive(Debug, Clone, Copy)]
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
    BackendMsgGetNotify(BackendMsgGetNotify),
    BackendMsgBufferLen(BackendMsgBufferLen),
    BackendMsgServerClosed(BackendMsgServerClosed),
    DeferDecryption(DeferDecryption),
    CloseConnection(CloseConnection),
    Finalize(Commit),
}

impl Message for MpcTlsLeaderMsg {
    type Return = Result<(), MpcTlsError>;
}

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetProtocolVersion;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetCipherSuite;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgGetSuite;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetEncrypt;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetDecrypt;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgGetClientRandom;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgGetClientKeyShare;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetServerRandom;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetServerKeyShare;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetServerCertDetails;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetServerKxDetails;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetHsHashClientKeyExchange;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgSetHsHashServerHello;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgGetServerFinishedVd;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgGetClientFinishedVd;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgPrepareEncryption;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgEncrypt;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgDecrypt;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgNextIncoming;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgBufferIncoming;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgGetNotify;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgBufferLen;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct BackendMsgServerClosed;

/// Message to start deferring the decryption
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub struct DeferDecryption;

impl Message for DeferDecryption {
    type Return = Result<(), MpcTlsError>;
}

/// Message to close the connection
#[derive(Debug, Clone, Copy)]
pub struct CloseConnection;

impl Message for CloseConnection {
    type Return = Result<(), MpcTlsError>;
}

/// Message to finalize the MPC-TLS protocol
#[derive(Debug, Clone, Copy)]
pub struct Commit;

impl Message for Commit {
    type Return = Result<(), MpcTlsError>;
}
