use crate::MpcTlsError;
use ludi::{Error, Message, Wrap};
use tls_backend::BackendError;

#[derive(Debug)]
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
    type Return = MpcTlsLeaderMsgReturn;
}

#[derive(Debug)]
pub enum MpcTlsLeaderMsgReturn {
    BackendMsgSetProtocolVersion(<BackendMsgSetProtocolVersion as Message>::Return),
    BackendMsgSetCipherSuite(<BackendMsgSetCipherSuite as Message>::Return),
    BackendMsgGetSuite(<BackendMsgGetSuite as Message>::Return),
    BackendMsgSetEncrypt(<BackendMsgSetEncrypt as Message>::Return),
    BackendMsgSetDecrypt(<BackendMsgSetDecrypt as Message>::Return),
    BackendMsgGetClientRandom(<BackendMsgGetClientRandom as Message>::Return),
    BackendMsgGetClientKeyShare(<BackendMsgGetClientKeyShare as Message>::Return),
    BackendMsgSetServerRandom(<BackendMsgSetServerRandom as Message>::Return),
    BackendMsgSetServerKeyShare(<BackendMsgSetServerKeyShare as Message>::Return),
    BackendMsgSetServerCertDetails(<BackendMsgSetServerCertDetails as Message>::Return),
    BackendMsgSetServerKxDetails(<BackendMsgSetServerKxDetails as Message>::Return),
    BackendMsgSetHsHashClientKeyExchange(<BackendMsgSetHsHashClientKeyExchange as Message>::Return),
    BackendMsgSetHsHashServerHello(<BackendMsgSetHsHashServerHello as Message>::Return),
    BackendMsgGetServerFinishedVd(<BackendMsgGetServerFinishedVd as Message>::Return),
    BackendMsgGetClientFinishedVd(<BackendMsgGetClientFinishedVd as Message>::Return),
    BackendMsgPrepareEncryption(<BackendMsgPrepareEncryption as Message>::Return),
    BackendMsgEncrypt(<BackendMsgEncrypt as Message>::Return),
    BackendMsgDecrypt(<BackendMsgDecrypt as Message>::Return),
    BackendMsgNextIncoming(<BackendMsgNextIncoming as Message>::Return),
    BackendMsgBufferIncoming(<BackendMsgBufferIncoming as Message>::Return),
    BackendMsgGetNotify(<BackendMsgGetNotify as Message>::Return),
    BackendMsgBufferLen(<BackendMsgBufferLen as Message>::Return),
    BackendMsgServerClosed(<BackendMsgServerClosed as Message>::Return),
    DeferDecryption(<DeferDecryption as Message>::Return),
    CloseConnection(<CloseConnection as Message>::Return),
    Finalize(<Commit as Message>::Return),
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetProtocolVersion;

impl Message for BackendMsgSetProtocolVersion {
    type Return = Result<(), BackendError>;
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetCipherSuite;

impl Message for BackendMsgSetCipherSuite {
    type Return = Result<(), BackendError>;
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetSuite;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetEncrypt;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetDecrypt;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientRandom;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientKeyShare;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerRandom;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerKeyShare;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerCertDetails;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerKxDetails;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetHsHashClientKeyExchange;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetHsHashServerHello;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetServerFinishedVd;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientFinishedVd;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgPrepareEncryption;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgEncrypt;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgDecrypt;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgNextIncoming;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgBufferIncoming;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetNotify;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgBufferLen;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgServerClosed;

/// Message to start deferring the decryption
#[allow(missing_docs)]
#[derive(Debug)]
pub struct DeferDecryption;

impl Message for DeferDecryption {
    type Return = Result<(), MpcTlsError>;
}

impl From<DeferDecryption> for MpcTlsLeaderMsg {
    fn from(value: DeferDecryption) -> Self {
        MpcTlsLeaderMsg::DeferDecryption(value)
    }
}

impl Wrap<DeferDecryption> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<DeferDecryption as Message>::Return, Error> {
        match ret {
            Self::Return::DeferDecryption(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

/// Message to close the connection
#[derive(Debug)]
pub struct CloseConnection;

impl Message for CloseConnection {
    type Return = Result<(), MpcTlsError>;
}

impl From<CloseConnection> for MpcTlsLeaderMsg {
    fn from(value: CloseConnection) -> Self {
        MpcTlsLeaderMsg::CloseConnection(value)
    }
}

impl Wrap<CloseConnection> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<CloseConnection as Message>::Return, Error> {
        match ret {
            Self::Return::CloseConnection(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

/// Message to finalize the MPC-TLS protocol
#[derive(Debug)]
pub struct Commit;

impl Message for Commit {
    type Return = Result<(), MpcTlsError>;
}

impl From<Commit> for MpcTlsLeaderMsg {
    fn from(value: Commit) -> Self {
        MpcTlsLeaderMsg::Finalize(value)
    }
}

impl Wrap<Commit> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<Commit as Message>::Return, Error> {
        match ret {
            Self::Return::Finalize(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}
