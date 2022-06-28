#![cfg(feature = "ot")]

pub use crate::ot::{self, dh_ot, kos15};
use crate::utils::parse_ristretto_key;
use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind};

include!(concat!(env!("OUT_DIR"), "/core.ot.rs"));

pub use message::Msg;

impl From<ot::Kos15Message> for Message {
    #[inline]
    fn from(m: ot::Kos15Message) -> Self {
        Self {
            msg: Some(match m {
                ot::Kos15Message::ReceiverSetup(msg) => {
                    message::Msg::ReceiverSetup(ReceiverSetup::from(msg))
                }
                ot::Kos15Message::SenderSetup(msg) => {
                    message::Msg::SenderSetup(SenderSetup::from(msg))
                }
                ot::Kos15Message::SenderPayload(msg) => {
                    message::Msg::SenderPayload(SenderPayload::from(msg))
                }
                ot::Kos15Message::ExtReceiverSetup(msg) => {
                    message::Msg::ExtReceiverSetup(ExtReceiverSetup::from(msg))
                }
                ot::Kos15Message::ExtDerandomize(msg) => {
                    message::Msg::ExtDerandomize(ExtDerandomize::from(msg))
                }
                ot::Kos15Message::ExtSenderPayload(msg) => {
                    message::Msg::ExtSenderPayload(ExtSenderPayload::from(msg))
                }
                ot::Kos15Message::BaseSenderSetup(msg) => {
                    message::Msg::BaseSenderSetup(BaseSenderSetup::from(msg))
                }
                ot::Kos15Message::BaseReceiverSetup(msg) => {
                    message::Msg::BaseReceiverSetup(BaseReceiverSetup::from(msg))
                }
                ot::Kos15Message::BaseSenderPayload(msg) => {
                    message::Msg::BaseSenderPayload(BaseSenderPayload::from(msg))
                }
            }),
        }
    }
}

impl TryFrom<Message> for ot::Kos15Message {
    type Error = std::io::Error;
    #[inline]
    fn try_from(m: Message) -> Result<Self, Self::Error> {
        if let Some(msg) = m.msg {
            let m = match msg {
                message::Msg::ReceiverSetup(msg) => {
                    ot::Kos15Message::ReceiverSetup(dh_ot::ReceiverChoices::try_from(msg)?)
                }
                message::Msg::SenderSetup(msg) => {
                    ot::Kos15Message::SenderSetup(dh_ot::SenderSetup::try_from(msg)?)
                }
                message::Msg::SenderPayload(msg) => {
                    ot::Kos15Message::SenderPayload(dh_ot::SenderPayload::from(msg))
                }
                message::Msg::ExtReceiverSetup(msg) => {
                    ot::Kos15Message::ExtReceiverSetup(kos15::ExtReceiverSetup::try_from(msg)?)
                }
                message::Msg::ExtDerandomize(msg) => {
                    ot::Kos15Message::ExtDerandomize(kos15::ExtDerandomize::from(msg))
                }
                message::Msg::ExtSenderPayload(msg) => {
                    ot::Kos15Message::ExtSenderPayload(kos15::ExtSenderPayload::from(msg))
                }
                message::Msg::BaseSenderSetup(msg) => {
                    ot::Kos15Message::BaseSenderSetup(kos15::BaseSenderSetup::try_from(msg)?)
                }
                message::Msg::BaseReceiverSetup(msg) => {
                    ot::Kos15Message::BaseReceiverSetup(kos15::BaseReceiverSetup::try_from(msg)?)
                }
                message::Msg::BaseSenderPayload(msg) => {
                    ot::Kos15Message::BaseSenderPayload(kos15::BaseSenderPayload::try_from(msg)?)
                }
            };
            Ok(m)
        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("{:?}", m)))
        }
    }
}

impl From<dh_ot::SenderSetup> for SenderSetup {
    #[inline]
    fn from(s: dh_ot::SenderSetup) -> Self {
        Self {
            public_key: super::RistrettoPoint::from(s.public_key),
        }
    }
}

impl TryFrom<SenderSetup> for dh_ot::SenderSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: SenderSetup) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: s.public_key.try_into()?,
        })
    }
}

impl From<dh_ot::SenderPayload> for SenderPayload {
    #[inline]
    fn from(p: dh_ot::SenderPayload) -> Self {
        Self {
            ciphertexts: p
                .ciphertexts
                .into_iter()
                .map(|b| super::LabelPair {
                    low: super::Block::from(b[0]),
                    high: super::Block::from(b[1]),
                })
                .collect(),
        }
    }
}

impl From<SenderPayload> for dh_ot::SenderPayload {
    #[inline]
    fn from(p: SenderPayload) -> Self {
        Self {
            ciphertexts: p
                .ciphertexts
                .into_iter()
                .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
                .collect(),
        }
    }
}

impl From<dh_ot::ReceiverChoices> for ReceiverSetup {
    #[inline]
    fn from(s: dh_ot::ReceiverChoices) -> Self {
        Self {
            blinded_choices: s
                .blinded_choices
                .into_iter()
                .map(super::RistrettoPoint::from)
                .collect(),
        }
    }
}

impl TryFrom<ReceiverSetup> for dh_ot::ReceiverChoices {
    type Error = Error;

    #[inline]
    fn try_from(s: ReceiverSetup) -> Result<Self, Self::Error> {
        let mut blinded_choices: Vec<curve25519_dalek::ristretto::RistrettoPoint> =
            Vec::with_capacity(s.blinded_choices.len());
        for key in s.blinded_choices.into_iter() {
            blinded_choices.push(parse_ristretto_key(key.point)?);
        }
        Ok(Self { blinded_choices })
    }
}

impl From<kos15::ExtReceiverSetup> for ExtReceiverSetup {
    #[inline]
    fn from(s: kos15::ExtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as u32,
            table: s.table,
            x: s.x.to_vec(),
            t0: s.t0.to_vec(),
            t1: s.t1.to_vec(),
        }
    }
}

impl TryFrom<ExtReceiverSetup> for kos15::ExtReceiverSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: ExtReceiverSetup) -> Result<Self, Error> {
        Ok(Self {
            ncols: s.ncols as usize,
            table: s.table,
            x: s.x.try_into().map_err(|_| ErrorKind::InvalidData)?,
            t0: s.t0.try_into().map_err(|_| ErrorKind::InvalidData)?,
            t1: s.t1.try_into().map_err(|_| ErrorKind::InvalidData)?,
        })
    }
}

impl From<kos15::ExtDerandomize> for ExtDerandomize {
    #[inline]
    fn from(d: kos15::ExtDerandomize) -> Self {
        Self { flip: d.flip }
    }
}

impl From<ExtDerandomize> for kos15::ExtDerandomize {
    #[inline]
    fn from(d: ExtDerandomize) -> Self {
        Self { flip: d.flip }
    }
}

impl From<kos15::ExtSenderPayload> for ExtSenderPayload {
    #[inline]
    fn from(p: kos15::ExtSenderPayload) -> Self {
        Self {
            ciphertexts: p
                .ciphertexts
                .into_iter()
                .map(|b| super::LabelPair {
                    low: super::Block::from(b[0]),
                    high: super::Block::from(b[1]),
                })
                .collect(),
        }
    }
}

impl From<ExtSenderPayload> for kos15::ExtSenderPayload {
    #[inline]
    fn from(p: ExtSenderPayload) -> Self {
        Self {
            ciphertexts: p
                .ciphertexts
                .into_iter()
                .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
                .collect(),
        }
    }
}

impl From<kos15::BaseSenderSetup> for BaseSenderSetup {
    #[inline]
    fn from(s: kos15::BaseSenderSetup) -> Self {
        Self {
            setup: SenderSetup::from(s.setup),
            cointoss_commit: s.cointoss_commit.to_vec(),
        }
    }
}

impl TryFrom<BaseSenderSetup> for kos15::BaseSenderSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseSenderSetup) -> Result<Self, Error> {
        Ok(Self {
            setup: s.setup.try_into().map_err(|_| ErrorKind::InvalidData)?,
            cointoss_commit: s
                .cointoss_commit
                .try_into()
                .map_err(|_| ErrorKind::InvalidData)?,
        })
    }
}

impl From<kos15::BaseReceiverSetup> for BaseReceiverSetup {
    #[inline]
    fn from(s: kos15::BaseReceiverSetup) -> Self {
        Self {
            setup: ReceiverSetup::from(s.setup),
            cointoss_share: s.cointoss_share.to_vec(),
        }
    }
}

impl TryFrom<BaseReceiverSetup> for kos15::BaseReceiverSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseReceiverSetup) -> Result<Self, Error> {
        Ok(Self {
            setup: s.setup.try_into().map_err(|_| ErrorKind::InvalidData)?,
            cointoss_share: s
                .cointoss_share
                .try_into()
                .map_err(|_| ErrorKind::InvalidData)?,
        })
    }
}

impl From<kos15::BaseSenderPayload> for BaseSenderPayload {
    #[inline]
    fn from(s: kos15::BaseSenderPayload) -> Self {
        Self {
            payload: SenderPayload::from(s.payload),
            cointoss_share: s.cointoss_share.to_vec(),
        }
    }
}

impl TryFrom<BaseSenderPayload> for kos15::BaseSenderPayload {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseSenderPayload) -> Result<Self, Error> {
        Ok(Self {
            payload: s.payload.try_into().map_err(|_| ErrorKind::InvalidData)?,
            cointoss_share: s
                .cointoss_share
                .try_into()
                .map_err(|_| ErrorKind::InvalidData)?,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ot::base::tests::fixtures::{ot_core_data, Data};
    use crate::ot::extension::tests::fixtures::{ot_ext_core_data, Data as ExtData};

    use fixtures::*;
    use rstest::*;

    pub mod fixtures {
        use super::*;

        pub struct ProtoData {
            pub sender_setup: SenderSetup,
            pub receiver_setup: ReceiverSetup,
            pub sender_payload: SenderPayload,
        }

        pub struct ProtoExtData {
            pub base_sender_setup: BaseSenderSetup,
            pub base_receiver_setup: BaseReceiverSetup,
            pub base_sender_payload: BaseSenderPayload,
        }

        #[fixture]
        #[once]
        pub fn proto_base_core_data(ot_core_data: &Data) -> ProtoData {
            ProtoData {
                sender_setup: ot_core_data.sender_setup.into(),
                receiver_setup: ot_core_data.receiver_setup.clone().into(),
                sender_payload: ot_core_data.sender_payload.clone().into(),
            }
        }

        #[fixture]
        #[once]
        pub fn proto_ext_core_data(ot_ext_core_data: &ExtData) -> ProtoExtData {
            ProtoExtData {
                base_sender_setup: ot_ext_core_data.base_sender_setup.into(),
                base_receiver_setup: ot_ext_core_data.base_receiver_setup.clone().into(),
                base_sender_payload: ot_ext_core_data.base_sender_payload.clone().into(),
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

    #[rstest]
    fn test_proto_ext(proto_ext_core_data: &fixtures::ProtoExtData, ot_ext_core_data: &ExtData) {
        let base_sender_setup: crate::ot::extension::BaseSenderSetup = proto_ext_core_data
            .base_sender_setup
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(base_sender_setup, ot_ext_core_data.base_sender_setup);

        let base_receiver_setup: crate::ot::extension::BaseReceiverSetup = proto_ext_core_data
            .base_receiver_setup
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(base_receiver_setup, ot_ext_core_data.base_receiver_setup);

        let base_sender_payload: crate::ot::extension::BaseSenderPayload = proto_ext_core_data
            .base_sender_payload
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(base_sender_payload, ot_ext_core_data.base_sender_payload);
    }
}
