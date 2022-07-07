use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind};

use crate::msgs::handshake;
use crate::proto;

impl From<handshake::HandshakeMessage> for proto::HandshakeMessage {
    fn from(m: handshake::HandshakeMessage) -> Self {
        Self {
            msg: Some(match m {
                handshake::HandshakeMessage::MasterMs1(m) => {
                    proto::handshake_message::Msg::Mms1(m.into())
                }
                handshake::HandshakeMessage::SlaveMs1(m) => {
                    proto::handshake_message::Msg::Sms1(m.into())
                }
                handshake::HandshakeMessage::MasterMs2(m) => {
                    proto::handshake_message::Msg::Mms2(m.into())
                }
                handshake::HandshakeMessage::SlaveMs2(m) => {
                    proto::handshake_message::Msg::Sms2(m.into())
                }
                handshake::HandshakeMessage::MasterMs3(m) => {
                    proto::handshake_message::Msg::Mms3(m.into())
                }
                handshake::HandshakeMessage::SlaveMs3(m) => {
                    proto::handshake_message::Msg::Sms3(m.into())
                }
                handshake::HandshakeMessage::MasterKe1(m) => {
                    proto::handshake_message::Msg::Mke1(m.into())
                }
                handshake::HandshakeMessage::SlaveKe1(m) => {
                    proto::handshake_message::Msg::Ske1(m.into())
                }
                handshake::HandshakeMessage::MasterKe2(m) => {
                    proto::handshake_message::Msg::Mke2(m.into())
                }
                handshake::HandshakeMessage::SlaveKe2(m) => {
                    proto::handshake_message::Msg::Ske2(m.into())
                }
                handshake::HandshakeMessage::MasterCf1(m) => {
                    proto::handshake_message::Msg::Mcf1(m.into())
                }
                handshake::HandshakeMessage::SlaveCf1(m) => {
                    proto::handshake_message::Msg::Scf1(m.into())
                }
                handshake::HandshakeMessage::MasterCf2(m) => {
                    proto::handshake_message::Msg::Mcf2(m.into())
                }
                handshake::HandshakeMessage::SlaveCf2(m) => {
                    proto::handshake_message::Msg::Scf2(m.into())
                }
                handshake::HandshakeMessage::MasterSf1(m) => {
                    proto::handshake_message::Msg::Msf1(m.into())
                }
                handshake::HandshakeMessage::SlaveSf1(m) => {
                    proto::handshake_message::Msg::Ssf1(m.into())
                }
                handshake::HandshakeMessage::MasterSf2(m) => {
                    proto::handshake_message::Msg::Msf2(m.into())
                }
                handshake::HandshakeMessage::SlaveSf2(m) => {
                    proto::handshake_message::Msg::Ssf2(m.into())
                }
            }),
        }
    }
}

impl TryFrom<proto::HandshakeMessage> for handshake::HandshakeMessage {
    type Error = Error;
    fn try_from(m: proto::HandshakeMessage) -> Result<Self, Self::Error> {
        Ok(
            match m.msg.ok_or(Error::new(
                ErrorKind::InvalidData,
                "HandshakeMessage".to_string(),
            ))? {
                proto::handshake_message::Msg::Mms1(m) => {
                    handshake::HandshakeMessage::MasterMs1(m.try_into()?)
                }
                proto::handshake_message::Msg::Mms2(m) => {
                    handshake::HandshakeMessage::MasterMs2(m.try_into()?)
                }
                proto::handshake_message::Msg::Mms3(m) => {
                    handshake::HandshakeMessage::MasterMs3(m.try_into()?)
                }
                proto::handshake_message::Msg::Mke1(m) => {
                    handshake::HandshakeMessage::MasterKe1(m.try_into()?)
                }
                proto::handshake_message::Msg::Mke2(m) => {
                    handshake::HandshakeMessage::MasterKe2(m.try_into()?)
                }
                proto::handshake_message::Msg::Mcf1(m) => {
                    handshake::HandshakeMessage::MasterCf1(m.try_into()?)
                }
                proto::handshake_message::Msg::Mcf2(m) => {
                    handshake::HandshakeMessage::MasterCf2(m.try_into()?)
                }
                proto::handshake_message::Msg::Msf1(m) => {
                    handshake::HandshakeMessage::MasterSf1(m.try_into()?)
                }
                proto::handshake_message::Msg::Msf2(m) => {
                    handshake::HandshakeMessage::MasterSf2(m.try_into()?)
                }
                proto::handshake_message::Msg::Sms1(m) => {
                    handshake::HandshakeMessage::SlaveMs1(m.try_into()?)
                }
                proto::handshake_message::Msg::Sms2(m) => {
                    handshake::HandshakeMessage::SlaveMs2(m.try_into()?)
                }
                proto::handshake_message::Msg::Sms3(m) => {
                    handshake::HandshakeMessage::SlaveMs3(m.try_into()?)
                }
                proto::handshake_message::Msg::Ske1(m) => {
                    handshake::HandshakeMessage::SlaveKe1(m.try_into()?)
                }
                proto::handshake_message::Msg::Ske2(m) => {
                    handshake::HandshakeMessage::SlaveKe2(m.try_into()?)
                }
                proto::handshake_message::Msg::Scf1(m) => {
                    handshake::HandshakeMessage::SlaveCf1(m.try_into()?)
                }
                proto::handshake_message::Msg::Scf2(m) => {
                    handshake::HandshakeMessage::SlaveCf2(m.try_into()?)
                }
                proto::handshake_message::Msg::Ssf1(m) => {
                    handshake::HandshakeMessage::SlaveSf1(m.try_into()?)
                }
                proto::handshake_message::Msg::Ssf2(m) => {
                    handshake::HandshakeMessage::SlaveSf2(m.try_into()?)
                }
            },
        )
    }
}

impl From<handshake::MasterMs1> for proto::MasterMs1 {
    fn from(m: handshake::MasterMs1) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterMs1> for handshake::MasterMs1 {
    type Error = Error;
    fn try_from(m: proto::MasterMs1) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterMs1".to_string()))?,
        })
    }
}

impl From<handshake::MasterMs2> for proto::MasterMs2 {
    fn from(m: handshake::MasterMs2) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterMs2> for handshake::MasterMs2 {
    type Error = Error;
    fn try_from(m: proto::MasterMs2) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterMs2".to_string()))?,
        })
    }
}

impl From<handshake::MasterMs3> for proto::MasterMs3 {
    fn from(m: handshake::MasterMs3) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterMs3> for handshake::MasterMs3 {
    type Error = Error;
    fn try_from(m: proto::MasterMs3) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterMs3".to_string()))?,
        })
    }
}

impl From<handshake::MasterKe1> for proto::MasterKe1 {
    fn from(m: handshake::MasterKe1) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterKe1> for handshake::MasterKe1 {
    type Error = Error;
    fn try_from(m: proto::MasterKe1) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterKe1".to_string()))?,
        })
    }
}

impl From<handshake::MasterKe2> for proto::MasterKe2 {
    fn from(m: handshake::MasterKe2) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterKe2> for handshake::MasterKe2 {
    type Error = Error;
    fn try_from(m: proto::MasterKe2) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterKe2".to_string()))?,
        })
    }
}

impl From<handshake::MasterCf1> for proto::MasterCf1 {
    fn from(m: handshake::MasterCf1) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterCf1> for handshake::MasterCf1 {
    type Error = Error;
    fn try_from(m: proto::MasterCf1) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterCf1".to_string()))?,
        })
    }
}

impl From<handshake::MasterCf2> for proto::MasterCf2 {
    fn from(m: handshake::MasterCf2) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterCf2> for handshake::MasterCf2 {
    type Error = Error;
    fn try_from(m: proto::MasterCf2) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterCf2".to_string()))?,
        })
    }
}

impl From<handshake::MasterSf1> for proto::MasterSf1 {
    fn from(m: handshake::MasterSf1) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterSf1> for handshake::MasterSf1 {
    type Error = Error;
    fn try_from(m: proto::MasterSf1) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterSf1".to_string()))?,
        })
    }
}

impl From<handshake::MasterSf2> for proto::MasterSf2 {
    fn from(m: handshake::MasterSf2) -> Self {
        Self {
            inner_hash: m.inner_hash.to_vec(),
        }
    }
}

impl TryFrom<proto::MasterSf2> for handshake::MasterSf2 {
    type Error = Error;
    fn try_from(m: proto::MasterSf2) -> Result<Self, Self::Error> {
        Ok(Self {
            inner_hash: m
                .inner_hash
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "MasterSf2".to_string()))?,
        })
    }
}

impl From<handshake::SlaveMs1> for proto::SlaveMs1 {
    fn from(m: handshake::SlaveMs1) -> Self {
        Self { a1: m.a1.to_vec() }
    }
}

impl TryFrom<proto::SlaveMs1> for handshake::SlaveMs1 {
    type Error = Error;
    fn try_from(m: proto::SlaveMs1) -> Result<Self, Self::Error> {
        Ok(Self {
            a1: m
                .a1
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveMs1".to_string()))?,
        })
    }
}

impl From<handshake::SlaveMs2> for proto::SlaveMs2 {
    fn from(m: handshake::SlaveMs2) -> Self {
        Self { a2: m.a2.to_vec() }
    }
}

impl TryFrom<proto::SlaveMs2> for handshake::SlaveMs2 {
    type Error = Error;
    fn try_from(m: proto::SlaveMs2) -> Result<Self, Self::Error> {
        Ok(Self {
            a2: m
                .a2
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveMs2".to_string()))?,
        })
    }
}

impl From<handshake::SlaveMs3> for proto::SlaveMs3 {
    fn from(m: handshake::SlaveMs3) -> Self {
        Self { p2: m.p2.to_vec() }
    }
}

impl TryFrom<proto::SlaveMs3> for handshake::SlaveMs3 {
    type Error = Error;
    fn try_from(m: proto::SlaveMs3) -> Result<Self, Self::Error> {
        Ok(Self {
            p2: m
                .p2
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveMs3".to_string()))?,
        })
    }
}

impl From<handshake::SlaveKe1> for proto::SlaveKe1 {
    fn from(m: handshake::SlaveKe1) -> Self {
        Self { a1: m.a1.to_vec() }
    }
}

impl TryFrom<proto::SlaveKe1> for handshake::SlaveKe1 {
    type Error = Error;
    fn try_from(m: proto::SlaveKe1) -> Result<Self, Self::Error> {
        Ok(Self {
            a1: m
                .a1
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveKe1".to_string()))?,
        })
    }
}

impl From<handshake::SlaveKe2> for proto::SlaveKe2 {
    fn from(m: handshake::SlaveKe2) -> Self {
        Self { a2: m.a2.to_vec() }
    }
}

impl TryFrom<proto::SlaveKe2> for handshake::SlaveKe2 {
    type Error = Error;
    fn try_from(m: proto::SlaveKe2) -> Result<Self, Self::Error> {
        Ok(Self {
            a2: m
                .a2
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveKe2".to_string()))?,
        })
    }
}

impl From<handshake::SlaveCf1> for proto::SlaveCf1 {
    fn from(m: handshake::SlaveCf1) -> Self {
        Self { a1: m.a1.to_vec() }
    }
}

impl TryFrom<proto::SlaveCf1> for handshake::SlaveCf1 {
    type Error = Error;
    fn try_from(m: proto::SlaveCf1) -> Result<Self, Self::Error> {
        Ok(Self {
            a1: m
                .a1
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveCf1".to_string()))?,
        })
    }
}

impl From<handshake::SlaveCf2> for proto::SlaveCf2 {
    fn from(m: handshake::SlaveCf2) -> Self {
        Self {
            verify_data: m.verify_data.to_vec(),
        }
    }
}

impl TryFrom<proto::SlaveCf2> for handshake::SlaveCf2 {
    type Error = Error;
    fn try_from(m: proto::SlaveCf2) -> Result<Self, Self::Error> {
        Ok(Self {
            verify_data: m
                .verify_data
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveCf2".to_string()))?,
        })
    }
}

impl From<handshake::SlaveSf1> for proto::SlaveSf1 {
    fn from(m: handshake::SlaveSf1) -> Self {
        Self { a1: m.a1.to_vec() }
    }
}

impl TryFrom<proto::SlaveSf1> for handshake::SlaveSf1 {
    type Error = Error;
    fn try_from(m: proto::SlaveSf1) -> Result<Self, Self::Error> {
        Ok(Self {
            a1: m
                .a1
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveSf1".to_string()))?,
        })
    }
}

impl From<handshake::SlaveSf2> for proto::SlaveSf2 {
    fn from(m: handshake::SlaveSf2) -> Self {
        Self {
            verify_data: m.verify_data.to_vec(),
        }
    }
}

impl TryFrom<proto::SlaveSf2> for handshake::SlaveSf2 {
    type Error = Error;
    fn try_from(m: proto::SlaveSf2) -> Result<Self, Self::Error> {
        Ok(Self {
            verify_data: m
                .verify_data
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "SlaveSf2".to_string()))?,
        })
    }
}
