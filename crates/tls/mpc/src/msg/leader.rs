//! Messages for the leader actor.

use crate::MpcTlsError;
use ludi::{Error, Message, Wrap};
use tls_backend::{BackendError, BackendNotify, DecryptMode, EncryptMode};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::ProtocolVersion,
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};

#[allow(missing_docs)]
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

#[allow(missing_docs)]
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
pub struct BackendMsgSetProtocolVersion {
    pub version: ProtocolVersion,
}

impl Message for BackendMsgSetProtocolVersion {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetProtocolVersion> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetProtocolVersion) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetProtocolVersion(value)
    }
}

impl Wrap<BackendMsgSetProtocolVersion> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetProtocolVersion as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetProtocolVersion(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetCipherSuite {
    pub suite: SupportedCipherSuite,
}

impl Message for BackendMsgSetCipherSuite {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetCipherSuite> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetCipherSuite) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetCipherSuite(value)
    }
}

impl Wrap<BackendMsgSetCipherSuite> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetCipherSuite as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetCipherSuite(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetSuite;

impl Message for BackendMsgGetSuite {
    type Return = Result<SupportedCipherSuite, BackendError>;
}

impl From<BackendMsgGetSuite> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetSuite) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetSuite(value)
    }
}

impl Wrap<BackendMsgGetSuite> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgGetSuite as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetSuite(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetEncrypt {
    pub mode: EncryptMode,
}

impl Message for BackendMsgSetEncrypt {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetEncrypt> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetEncrypt) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetEncrypt(value)
    }
}

impl Wrap<BackendMsgSetEncrypt> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetEncrypt as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetEncrypt(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetDecrypt {
    pub mode: DecryptMode,
}

impl Message for BackendMsgSetDecrypt {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetDecrypt> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetDecrypt) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetDecrypt(value)
    }
}

impl Wrap<BackendMsgSetDecrypt> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetDecrypt as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetDecrypt(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientRandom;

impl Message for BackendMsgGetClientRandom {
    type Return = Result<Random, BackendError>;
}

impl From<BackendMsgGetClientRandom> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetClientRandom) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetClientRandom(value)
    }
}

impl Wrap<BackendMsgGetClientRandom> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetClientRandom as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetClientRandom(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientKeyShare;

impl Message for BackendMsgGetClientKeyShare {
    type Return = Result<PublicKey, BackendError>;
}

impl From<BackendMsgGetClientKeyShare> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetClientKeyShare) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetClientKeyShare(value)
    }
}

impl Wrap<BackendMsgGetClientKeyShare> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetClientKeyShare as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetClientKeyShare(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerRandom {
    pub random: Random,
}

impl Message for BackendMsgSetServerRandom {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerRandom> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerRandom) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerRandom(value)
    }
}

impl Wrap<BackendMsgSetServerRandom> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerRandom as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerRandom(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerKeyShare {
    pub key: PublicKey,
}

impl Message for BackendMsgSetServerKeyShare {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerKeyShare> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerKeyShare) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerKeyShare(value)
    }
}

impl Wrap<BackendMsgSetServerKeyShare> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerKeyShare as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerKeyShare(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerCertDetails {
    pub cert_details: ServerCertDetails,
}

impl Message for BackendMsgSetServerCertDetails {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerCertDetails> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerCertDetails) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerCertDetails(value)
    }
}

impl Wrap<BackendMsgSetServerCertDetails> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerCertDetails as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerCertDetails(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerKxDetails {
    pub kx_details: ServerKxDetails,
}

impl Message for BackendMsgSetServerKxDetails {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerKxDetails> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerKxDetails) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerKxDetails(value)
    }
}

impl Wrap<BackendMsgSetServerKxDetails> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerKxDetails as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerKxDetails(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetHsHashClientKeyExchange {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgSetHsHashClientKeyExchange {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetHsHashClientKeyExchange> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetHsHashClientKeyExchange) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetHsHashClientKeyExchange(value)
    }
}

impl Wrap<BackendMsgSetHsHashClientKeyExchange> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetHsHashClientKeyExchange as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetHsHashClientKeyExchange(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetHsHashServerHello {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgSetHsHashServerHello {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetHsHashServerHello> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetHsHashServerHello) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetHsHashServerHello(value)
    }
}

impl Wrap<BackendMsgSetHsHashServerHello> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetHsHashServerHello as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetHsHashServerHello(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetServerFinishedVd {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgGetServerFinishedVd {
    type Return = Result<Vec<u8>, BackendError>;
}

impl From<BackendMsgGetServerFinishedVd> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetServerFinishedVd) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetServerFinishedVd(value)
    }
}

impl Wrap<BackendMsgGetServerFinishedVd> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetServerFinishedVd as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetServerFinishedVd(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientFinishedVd {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgGetClientFinishedVd {
    type Return = Result<Vec<u8>, BackendError>;
}

impl From<BackendMsgGetClientFinishedVd> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetClientFinishedVd) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetClientFinishedVd(value)
    }
}

impl Wrap<BackendMsgGetClientFinishedVd> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetClientFinishedVd as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetClientFinishedVd(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgPrepareEncryption;

impl Message for BackendMsgPrepareEncryption {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgPrepareEncryption> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgPrepareEncryption) -> Self {
        MpcTlsLeaderMsg::BackendMsgPrepareEncryption(value)
    }
}

impl Wrap<BackendMsgPrepareEncryption> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgPrepareEncryption as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgPrepareEncryption(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgEncrypt {
    pub msg: PlainMessage,
    pub seq: u64,
}

impl Message for BackendMsgEncrypt {
    type Return = Result<OpaqueMessage, BackendError>;
}

impl From<BackendMsgEncrypt> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgEncrypt) -> Self {
        MpcTlsLeaderMsg::BackendMsgEncrypt(value)
    }
}

impl Wrap<BackendMsgEncrypt> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgEncrypt as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgEncrypt(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgDecrypt {
    pub msg: OpaqueMessage,
    pub seq: u64,
}

impl Message for BackendMsgDecrypt {
    type Return = Result<PlainMessage, BackendError>;
}

impl From<BackendMsgDecrypt> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgDecrypt) -> Self {
        MpcTlsLeaderMsg::BackendMsgDecrypt(value)
    }
}

impl Wrap<BackendMsgDecrypt> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgDecrypt as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgDecrypt(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgBufferIncoming {
    pub msg: OpaqueMessage,
}

impl Message for BackendMsgBufferIncoming {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgBufferIncoming> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgBufferIncoming) -> Self {
        MpcTlsLeaderMsg::BackendMsgBufferIncoming(value)
    }
}

impl Wrap<BackendMsgBufferIncoming> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgBufferIncoming as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgBufferIncoming(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgNextIncoming;

impl Message for BackendMsgNextIncoming {
    type Return = Result<Option<OpaqueMessage>, BackendError>;
}

impl From<BackendMsgNextIncoming> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgNextIncoming) -> Self {
        MpcTlsLeaderMsg::BackendMsgNextIncoming(value)
    }
}

impl Wrap<BackendMsgNextIncoming> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgNextIncoming as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgNextIncoming(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetNotify;

impl Message for BackendMsgGetNotify {
    type Return = Result<BackendNotify, BackendError>;
}

impl From<BackendMsgGetNotify> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetNotify) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetNotify(value)
    }
}

impl Wrap<BackendMsgGetNotify> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgGetNotify as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetNotify(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgBufferLen;

impl Message for BackendMsgBufferLen {
    type Return = Result<usize, BackendError>;
}

impl From<BackendMsgBufferLen> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgBufferLen) -> Self {
        MpcTlsLeaderMsg::BackendMsgBufferLen(value)
    }
}

impl Wrap<BackendMsgBufferLen> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgBufferLen as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgBufferLen(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgServerClosed;

impl Message for BackendMsgServerClosed {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgServerClosed> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgServerClosed) -> Self {
        MpcTlsLeaderMsg::BackendMsgServerClosed(value)
    }
}

impl Wrap<BackendMsgServerClosed> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgServerClosed as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgServerClosed(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

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
