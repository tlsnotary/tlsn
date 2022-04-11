#![cfg(feature = "ot")]

pub use crate::ot;
use crate::utils::parse_ristretto_key;
use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind};

include!(concat!(env!("OUT_DIR"), "/core.ot.rs"));

pub use message::Msg;

impl From<ot::Message> for Message {
    #[inline]
    fn from(m: ot::Message) -> Self {
        Self {
            msg: Some(match m {
                ot::Message::ReceiverSetup(msg) => {
                    message::Msg::ReceiverSetup(ReceiverSetup::from(msg))
                }
                ot::Message::SenderSetup(msg) => message::Msg::SenderSetup(SenderSetup::from(msg)),
                ot::Message::SenderPayload(msg) => {
                    message::Msg::SenderPayload(SenderPayload::from(msg))
                }
                ot::Message::ExtReceiverSetup(msg) => {
                    message::Msg::ExtReceiverSetup(ExtReceiverSetup::from(msg))
                }
                ot::Message::ExtSenderPayload(msg) => {
                    message::Msg::ExtSenderPayload(ExtSenderPayload::from(msg))
                }
            }),
        }
    }
}

impl TryFrom<Message> for ot::Message {
    type Error = std::io::Error;
    #[inline]
    fn try_from(m: Message) -> Result<Self, Self::Error> {
        if let Some(msg) = m.msg {
            let m = match msg {
                message::Msg::ReceiverSetup(msg) => {
                    ot::Message::ReceiverSetup(ot::ReceiverSetup::try_from(msg)?)
                }
                message::Msg::SenderSetup(msg) => {
                    ot::Message::SenderSetup(ot::SenderSetup::try_from(msg)?)
                }
                message::Msg::SenderPayload(msg) => {
                    ot::Message::SenderPayload(ot::SenderPayload::from(msg))
                }
                message::Msg::ExtReceiverSetup(msg) => {
                    ot::Message::ExtReceiverSetup(ot::ExtReceiverSetup::from(msg))
                }
                message::Msg::ExtSenderPayload(msg) => {
                    ot::Message::ExtSenderPayload(ot::ExtSenderPayload::from(msg))
                }
            };
            Ok(m)
        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("{:?}", m)))
        }
    }
}

impl From<ot::SenderSetup> for SenderSetup {
    #[inline]
    fn from(s: ot::SenderSetup) -> Self {
        Self {
            public_key: super::RistrettoPoint::from(s.public_key),
        }
    }
}

impl TryFrom<SenderSetup> for ot::SenderSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: SenderSetup) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: s.public_key.try_into()?,
        })
    }
}

impl From<ot::SenderPayload> for SenderPayload {
    #[inline]
    fn from(p: ot::SenderPayload) -> Self {
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

impl From<SenderPayload> for ot::SenderPayload {
    #[inline]
    fn from(p: SenderPayload) -> Self {
        Self {
            encrypted_values: p
                .encrypted_values
                .into_iter()
                .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
                .collect(),
        }
    }
}

impl From<ot::ReceiverSetup> for ReceiverSetup {
    #[inline]
    fn from(s: ot::ReceiverSetup) -> Self {
        Self {
            keys: s
                .keys
                .into_iter()
                .map(super::RistrettoPoint::from)
                .collect(),
        }
    }
}

impl TryFrom<ReceiverSetup> for ot::ReceiverSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: ReceiverSetup) -> Result<Self, Self::Error> {
        let mut keys: Vec<curve25519_dalek::ristretto::RistrettoPoint> =
            Vec::with_capacity(s.keys.len());
        for key in s.keys.into_iter() {
            keys.push(parse_ristretto_key(key.point)?);
        }
        Ok(Self { keys })
    }
}

impl From<ot::ExtReceiverSetup> for ExtReceiverSetup {
    #[inline]
    fn from(s: ot::ExtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as u32,
            table: s.table,
        }
    }
}

impl From<ExtReceiverSetup> for ot::ExtReceiverSetup {
    #[inline]
    fn from(s: ExtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as usize,
            table: s.table,
        }
    }
}

impl From<ot::ExtSenderPayload> for ExtSenderPayload {
    #[inline]
    fn from(p: ot::ExtSenderPayload) -> Self {
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

impl From<ExtSenderPayload> for ot::ExtSenderPayload {
    #[inline]
    fn from(p: ExtSenderPayload) -> Self {
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
pub mod tests {
    use super::*;
    use crate::ot::base::tests::fixtures::{ot_core_data, Data};
    use fixtures::*;
    use rstest::*;

    pub mod fixtures {
        use super::*;

        pub struct ProtoData {
            pub sender_setup: SenderSetup,
            pub receiver_setup: ReceiverSetup,
            pub sender_payload: SenderPayload,
        }

        #[fixture]
        #[once]
        pub fn proto_base_core_data(ot_core_data: &Data) -> ProtoData {
            ProtoData {
                sender_setup: ot_core_data.sender_setup.clone().into(),
                receiver_setup: ot_core_data.receiver_setup.clone().into(),
                sender_payload: ot_core_data.sender_payload.clone().into(),
            }
        }
    }

    #[rstest]
    fn test_proto_ot(proto_base_core_data: &fixtures::ProtoData, ot_core_data: &Data) {
        let sender_setup: crate::ot::base::SenderSetup = proto_base_core_data
            .sender_setup
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(sender_setup, ot_core_data.sender_setup);

        let receiver_setup: crate::ot::base::ReceiverSetup = proto_base_core_data
            .receiver_setup
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(receiver_setup, ot_core_data.receiver_setup);

        let sender_payload: crate::ot::base::SenderPayload = proto_base_core_data
            .sender_payload
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(sender_payload, ot_core_data.sender_payload);
    }
}
