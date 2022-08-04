#![cfg(feature = "ot")]

pub use crate::ot::{self, dh_ot, kos15};
use crate::utils::parse_ristretto_key;
use std::{
    convert::{TryFrom, TryInto},
    io::{Error, ErrorKind},
};

include!(concat!(env!("OUT_DIR"), "/core.ot.rs"));

pub use message::Msg;

impl From<ot::Message> for Message {
    #[inline]
    fn from(m: ot::Message) -> Self {
        Self {
            msg: Some(match m {
                ot::Message::BaseReceiverSetupWrapper(msg) => {
                    message::Msg::BaseReceiverSetupWrapper(BaseReceiverSetupWrapper::from(msg))
                }
                ot::Message::BaseReceiverSetup(msg) => {
                    message::Msg::BaseReceiverSetup(BaseReceiverSetup::from(msg))
                }
                ot::Message::BaseSenderSetup(msg) => {
                    message::Msg::BaseSenderSetup(BaseSenderSetup::from(msg))
                }
                ot::Message::BaseSenderSetupWrapper(msg) => {
                    message::Msg::BaseSenderSetupWrapper(BaseSenderSetupWrapper::from(msg))
                }
                ot::Message::BaseSenderPayloadWrapper(msg) => {
                    message::Msg::BaseSenderPayloadWrapper(BaseSenderPayloadWrapper::from(msg))
                }
                ot::Message::BaseSenderPayload(msg) => {
                    message::Msg::BaseSenderPayload(BaseSenderPayload::from(msg))
                }
                ot::Message::ExtReceiverSetup(msg) => {
                    message::Msg::ExtReceiverSetup(ExtReceiverSetup::from(msg))
                }
                ot::Message::ExtDerandomize(msg) => {
                    message::Msg::ExtDerandomize(ExtDerandomize::from(msg))
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
                message::Msg::BaseReceiverSetupWrapper(msg) => {
                    ot::Message::BaseReceiverSetupWrapper(
                        kos15::BaseReceiverSetupWrapper::try_from(msg)?,
                    )
                }
                message::Msg::BaseReceiverSetup(msg) => {
                    ot::Message::BaseReceiverSetup(kos15::BaseReceiverSetup::try_from(msg)?)
                }
                message::Msg::BaseSenderSetup(msg) => {
                    ot::Message::BaseSenderSetup(kos15::BaseSenderSetup::try_from(msg)?)
                }
                message::Msg::BaseSenderSetupWrapper(msg) => ot::Message::BaseSenderSetupWrapper(
                    kos15::BaseSenderSetupWrapper::try_from(msg)?,
                ),
                message::Msg::BaseSenderPayloadWrapper(msg) => {
                    ot::Message::BaseSenderPayloadWrapper(
                        kos15::BaseSenderPayloadWrapper::try_from(msg)?,
                    )
                }
                message::Msg::BaseSenderPayload(msg) => {
                    ot::Message::BaseSenderPayload(kos15::BaseSenderPayload::from(msg))
                }
                message::Msg::ExtReceiverSetup(msg) => {
                    ot::Message::ExtReceiverSetup(kos15::ExtReceiverSetup::try_from(msg)?)
                }
                message::Msg::ExtDerandomize(msg) => {
                    ot::Message::ExtDerandomize(kos15::ExtDerandomize::from(msg))
                }
                message::Msg::ExtSenderPayload(msg) => {
                    ot::Message::ExtSenderPayload(kos15::ExtSenderPayload::from(msg))
                }
            };
            Ok(m)
        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("{:?}", m)))
        }
    }
}

impl From<dh_ot::SenderSetup> for BaseSenderSetup {
    #[inline]
    fn from(s: dh_ot::SenderSetup) -> Self {
        Self {
            public_key: super::RistrettoPoint::from(s.public_key),
        }
    }
}

impl TryFrom<BaseSenderSetup> for dh_ot::SenderSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseSenderSetup) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: s.public_key.try_into()?,
        })
    }
}

impl From<dh_ot::SenderPayload> for BaseSenderPayload {
    #[inline]
    fn from(p: dh_ot::SenderPayload) -> Self {
        Self {
            ciphertexts: p
                .ciphertexts
                .into_iter()
                .map(|b| super::BlockPair {
                    low: super::Block::from(b[0]),
                    high: super::Block::from(b[1]),
                })
                .collect(),
        }
    }
}

impl From<BaseSenderPayload> for dh_ot::SenderPayload {
    #[inline]
    fn from(p: BaseSenderPayload) -> Self {
        Self {
            ciphertexts: p
                .ciphertexts
                .into_iter()
                .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
                .collect(),
        }
    }
}

impl From<dh_ot::ReceiverSetup> for BaseReceiverSetup {
    #[inline]
    fn from(s: dh_ot::ReceiverSetup) -> Self {
        Self {
            blinded_choices: s
                .blinded_choices
                .into_iter()
                .map(super::RistrettoPoint::from)
                .collect(),
        }
    }
}

impl TryFrom<BaseReceiverSetup> for dh_ot::ReceiverSetup {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseReceiverSetup) -> Result<Self, Self::Error> {
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
                .map(|b| super::BlockPair {
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

impl From<kos15::BaseSenderSetupWrapper> for BaseSenderSetupWrapper {
    #[inline]
    fn from(s: kos15::BaseSenderSetupWrapper) -> Self {
        Self {
            setup: BaseSenderSetup::from(s.setup),
            cointoss_commit: s.cointoss_commit.to_vec(),
        }
    }
}

impl TryFrom<BaseSenderSetupWrapper> for kos15::BaseSenderSetupWrapper {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseSenderSetupWrapper) -> Result<Self, Error> {
        Ok(Self {
            setup: s.setup.try_into().map_err(|_| ErrorKind::InvalidData)?,
            cointoss_commit: s
                .cointoss_commit
                .try_into()
                .map_err(|_| ErrorKind::InvalidData)?,
        })
    }
}

impl From<kos15::BaseReceiverSetupWrapper> for BaseReceiverSetupWrapper {
    #[inline]
    fn from(s: kos15::BaseReceiverSetupWrapper) -> Self {
        Self {
            setup: BaseReceiverSetup::from(s.setup),
            cointoss_share: s.cointoss_share.to_vec(),
        }
    }
}

impl TryFrom<BaseReceiverSetupWrapper> for kos15::BaseReceiverSetupWrapper {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseReceiverSetupWrapper) -> Result<Self, Error> {
        Ok(Self {
            setup: s.setup.try_into().map_err(|_| ErrorKind::InvalidData)?,
            cointoss_share: s
                .cointoss_share
                .try_into()
                .map_err(|_| ErrorKind::InvalidData)?,
        })
    }
}

impl From<kos15::BaseSenderPayloadWrapper> for BaseSenderPayloadWrapper {
    #[inline]
    fn from(s: kos15::BaseSenderPayloadWrapper) -> Self {
        Self {
            payload: BaseSenderPayload::from(s.payload),
            cointoss_share: s.cointoss_share.to_vec(),
        }
    }
}

impl TryFrom<BaseSenderPayloadWrapper> for kos15::BaseSenderPayloadWrapper {
    type Error = Error;

    #[inline]
    fn try_from(s: BaseSenderPayloadWrapper) -> Result<Self, Error> {
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
    use crate::ot::{
        base::tests::fixtures::{ot_core_data, Data},
        extension::tests::fixtures::{ot_ext_core_data, Data as ExtData},
    };

    use fixtures::*;
    use rstest::*;

    pub mod fixtures {
        use super::*;

        pub struct ProtoData {
            pub sender_setup: BaseSenderSetup,
            pub receiver_setup: BaseReceiverSetup,
            pub sender_payload: BaseSenderPayload,
        }

        pub struct ProtoExtData {
            pub base_sender_setup: BaseSenderSetupWrapper,
            pub base_receiver_setup: BaseReceiverSetupWrapper,
            pub base_sender_payload: BaseSenderPayloadWrapper,
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
        let sender_setup: crate::ot::base::dh_ot::SenderSetup = proto_base_core_data
            .sender_setup
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(sender_setup, ot_core_data.sender_setup);

        let receiver_setup: crate::ot::base::dh_ot::ReceiverSetup = proto_base_core_data
            .receiver_setup
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(receiver_setup, ot_core_data.receiver_setup);

        let sender_payload: crate::ot::base::dh_ot::SenderPayload = proto_base_core_data
            .sender_payload
            .clone()
            .try_into()
            .unwrap();

        assert_eq!(sender_payload, ot_core_data.sender_payload);
    }

    #[rstest]
    fn test_proto_ext(proto_ext_core_data: &fixtures::ProtoExtData, ot_ext_core_data: &ExtData) {
        let base_sender_setup: crate::ot::extension::kos15::BaseSenderSetupWrapper =
            proto_ext_core_data
                .base_sender_setup
                .clone()
                .try_into()
                .unwrap();

        assert_eq!(base_sender_setup, ot_ext_core_data.base_sender_setup);

        let base_receiver_setup: crate::ot::extension::kos15::BaseReceiverSetupWrapper =
            proto_ext_core_data
                .base_receiver_setup
                .clone()
                .try_into()
                .unwrap();

        assert_eq!(base_receiver_setup, ot_ext_core_data.base_receiver_setup);

        let base_sender_payload: crate::ot::extension::kos15::BaseSenderPayloadWrapper =
            proto_ext_core_data
                .base_sender_payload
                .clone()
                .try_into()
                .unwrap();

        assert_eq!(base_sender_payload, ot_ext_core_data.base_sender_payload);
    }
}
