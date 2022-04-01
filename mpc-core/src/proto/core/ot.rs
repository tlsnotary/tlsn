#![cfg(feature = "ot")]

pub use crate::ot;
use crate::utils::parse_ristretto_key;
use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind};

include!(concat!(env!("OUT_DIR"), "/core.ot.rs"));

pub use ot_message::Msg;

impl From<ot::OtMessage> for OtMessage {
    #[inline]
    fn from(m: ot::OtMessage) -> Self {
        Self {
            msg: Some(match m {
                ot::OtMessage::BaseReceiverSetup(msg) => {
                    ot_message::Msg::BaseReceiverSetup(BaseOtReceiverSetup::from(msg))
                }
                ot::OtMessage::BaseSenderSetup(msg) => {
                    ot_message::Msg::BaseSenderSetup(BaseOtSenderSetup::from(msg))
                }
                ot::OtMessage::BaseSenderPayload(msg) => {
                    ot_message::Msg::BaseSenderPayload(BaseOtSenderPayload::from(msg))
                }
                ot::OtMessage::ReceiverSetup(msg) => {
                    ot_message::Msg::ReceiverSetup(OtReceiverSetup::from(msg))
                }
                ot::OtMessage::SenderPayload(msg) => {
                    ot_message::Msg::SenderPayload(OtSenderPayload::from(msg))
                }
            }),
        }
    }
}

impl TryFrom<OtMessage> for ot::OtMessage {
    type Error = std::io::Error;
    #[inline]
    fn try_from(m: OtMessage) -> Result<Self, Self::Error> {
        if let Some(msg) = m.msg {
            let m = match msg {
                ot_message::Msg::BaseReceiverSetup(msg) => {
                    ot::OtMessage::BaseReceiverSetup(ot::BaseOtReceiverSetup::try_from(msg)?)
                }
                ot_message::Msg::BaseSenderSetup(msg) => {
                    ot::OtMessage::BaseSenderSetup(ot::BaseOtSenderSetup::try_from(msg)?)
                }
                ot_message::Msg::BaseSenderPayload(msg) => {
                    ot::OtMessage::BaseSenderPayload(ot::BaseOtSenderPayload::from(msg))
                }
                ot_message::Msg::ReceiverSetup(msg) => {
                    ot::OtMessage::ReceiverSetup(ot::OtReceiverSetup::from(msg))
                }
                ot_message::Msg::SenderPayload(msg) => {
                    ot::OtMessage::SenderPayload(ot::OtSenderPayload::from(msg))
                }
            };
            Ok(m)
        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("{:?}", m)))
        }
    }
}

impl From<ot::BaseOtSenderSetup> for BaseOtSenderSetup {
    #[inline]
    fn from(s: ot::BaseOtSenderSetup) -> Self {
        Self {
            public_key: super::RistrettoPoint::from(s.public_key),
        }
    }
}

impl TryFrom<BaseOtSenderSetup> for ot::BaseOtSenderSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseOtSenderSetup) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: s.public_key.try_into()?,
        })
    }
}

impl From<ot::BaseOtSenderPayload> for BaseOtSenderPayload {
    #[inline]
    fn from(p: ot::BaseOtSenderPayload) -> Self {
        Self {
            encrypted_values: p
                .encrypted_values
                .into_iter()
                .map(|b| super::LabelPair {
                    low: super::Block::from(b[0]),
                    high: super::Block::from(b[1]),
                })
                .collect(),
        }
    }
}

impl From<BaseOtSenderPayload> for ot::BaseOtSenderPayload {
    #[inline]
    fn from(p: BaseOtSenderPayload) -> Self {
        Self {
            encrypted_values: p
                .encrypted_values
                .into_iter()
                .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
                .collect(),
        }
    }
}

impl From<ot::BaseOtReceiverSetup> for BaseOtReceiverSetup {
    #[inline]
    fn from(s: ot::BaseOtReceiverSetup) -> Self {
        Self {
            keys: s
                .keys
                .into_iter()
                .map(|k| super::RistrettoPoint::from(k))
                .collect(),
        }
    }
}

impl TryFrom<BaseOtReceiverSetup> for ot::BaseOtReceiverSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseOtReceiverSetup) -> Result<Self, Self::Error> {
        let mut keys: Vec<curve25519_dalek::ristretto::RistrettoPoint> =
            Vec::with_capacity(s.keys.len());
        for key in s.keys.into_iter() {
            keys.push(parse_ristretto_key(key.point)?);
        }
        Ok(Self { keys })
    }
}

impl From<ot::OtReceiverSetup> for OtReceiverSetup {
    #[inline]
    fn from(s: ot::OtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as u32,
            table: s.table,
        }
    }
}

impl From<OtReceiverSetup> for ot::OtReceiverSetup {
    #[inline]
    fn from(s: OtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as usize,
            table: s.table,
        }
    }
}

impl From<ot::OtSenderPayload> for OtSenderPayload {
    #[inline]
    fn from(p: ot::OtSenderPayload) -> Self {
        Self {
            encrypted_values: p
                .encrypted_values
                .into_iter()
                .map(|b| super::LabelPair {
                    low: super::Block::from(b[0]),
                    high: super::Block::from(b[1]),
                })
                .collect(),
        }
    }
}

impl From<OtSenderPayload> for ot::OtSenderPayload {
    #[inline]
    fn from(p: OtSenderPayload) -> Self {
        Self {
            encrypted_values: p
                .encrypted_values
                .into_iter()
                .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot_sender_payload() {
        let payload_a = ot::OtSenderPayload {
            encrypted_values: vec![
                [crate::Block::new(0), crate::Block::new(0)],
                [crate::Block::new(0), crate::Block::new(0)],
            ],
        };

        let proto = OtSenderPayload::from(payload_a.clone());
        let payload_b = ot::OtSenderPayload::from(proto);

        assert_eq!(payload_a, payload_b);
    }
}
