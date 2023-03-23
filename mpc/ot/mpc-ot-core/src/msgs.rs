use curve25519_dalek::ristretto::RistrettoPoint;
use mpc_core::Block;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OTFactoryMessage {
    OTMessage(OTMessage),
    Split(Split),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OTMessage {
    BaseSenderSetup(SenderSetup),
    BaseSenderSetupWrapper(BaseSenderSetupWrapper),
    BaseSenderPayload(SenderPayload),
    BaseSenderPayloadWrapper(BaseSenderPayloadWrapper),
    BaseReceiverSetup(ReceiverSetup),
    BaseReceiverSetupWrapper(BaseReceiverSetupWrapper),
    ExtReceiverSetup(ExtReceiverSetup),
    ExtDerandomize(ExtDerandomize),
    ExtSenderPayload(ExtSenderPayload),
    ExtSenderCommit(ExtSenderCommit),
    ExtSenderReveal(ExtSenderReveal),
    ExtSenderEncryptedPayload(ExtSenderEncryptedPayload),
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SenderSetup {
    pub public_key: RistrettoPoint,
}

/// The final output of the sender to the receiver
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SenderPayload {
    /// The pairs of ciphertexts output by the sender. At most one of these can be decrypted by the
    /// receiver.
    pub ciphertexts: Vec<[Block; 2]>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReceiverSetup {
    pub blinded_choices: Vec<RistrettoPoint>,
}

/// OT extension Sender plays the role of base OT Receiver and sends the
/// second message containing base OT setup and cointoss share
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BaseReceiverSetupWrapper {
    pub setup: ReceiverSetup,
    // Cointoss protocol's 2nd message: Receiver reveals share
    pub cointoss_share: [u8; 32],
}

/// OT extension Receiver plays the role of base OT Sender and sends the
/// first message containing base OT setup and cointoss commitment
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BaseSenderSetupWrapper {
    pub setup: SenderSetup,
    // Cointoss protocol's 1st message: blake3 commitment
    pub cointoss_commit: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BaseSenderPayloadWrapper {
    pub payload: SenderPayload,
    // Cointoss protocol's 3rd message: Sender reveals share
    pub cointoss_share: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtSenderPayload {
    pub ciphertexts: Vec<[Block; 2]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtDerandomize {
    pub flip: Vec<bool>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtReceiverSetup {
    /// The unpadded number of OTs the receiver has prepared
    pub count: usize,
    pub table: Vec<u8>,
    // x, t0, t1 are used for the KOS15 check
    pub x: [u8; 16],
    pub t0: [u8; 16],
    pub t1: [u8; 16],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtSenderCommit(pub [u8; 32]);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtSenderReveal {
    pub seed: [u8; 32],
    pub salt: [u8; 32],
    pub offset: usize,
}

/// We use this message when we want to send data which is longer than 128 bits
///
/// This is an encrypted payload which can be decrypted by the receiver with keys
/// he receives during the OT
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtSenderEncryptedPayload {
    pub ciphertexts: Vec<u8>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Split {
    /// Child OT identifier
    pub id: String,
    /// Number of OTs
    pub count: usize,
}

// #[cfg(feature = "proto")]
// mod proto {
//     use super::*;
//     use crate::proto::ot as proto;

//     use crate::utils::parse_ristretto_key;
//     use std::{
//         convert::{TryFrom, TryInto},
//         io::{Error, ErrorKind},
//     };

//     impl From<OTMessage> for proto::Message {
//         #[inline]
//         fn from(m: OTMessage) -> Self {
//             Self {
//                 msg: Some(match m {
//                     OTMessage::BaseReceiverSetupWrapper(msg) => {
//                         proto::message::Msg::BaseReceiverSetupWrapper(
//                             proto::BaseReceiverSetupWrapper::from(msg),
//                         )
//                     }
//                     OTMessage::BaseReceiverSetup(msg) => {
//                         proto::message::Msg::BaseReceiverSetup(proto::BaseReceiverSetup::from(msg))
//                     }
//                     OTMessage::BaseSenderSetup(msg) => {
//                         proto::message::Msg::BaseSenderSetup(proto::BaseSenderSetup::from(msg))
//                     }
//                     OTMessage::BaseSenderSetupWrapper(msg) => {
//                         proto::message::Msg::BaseSenderSetupWrapper(
//                             proto::BaseSenderSetupWrapper::from(msg),
//                         )
//                     }
//                     OTMessage::BaseSenderPayloadWrapper(msg) => {
//                         proto::message::Msg::BaseSenderPayloadWrapper(
//                             proto::BaseSenderPayloadWrapper::from(msg),
//                         )
//                     }
//                     OTMessage::BaseSenderPayload(msg) => {
//                         proto::message::Msg::BaseSenderPayload(proto::BaseSenderPayload::from(msg))
//                     }
//                     OTMessage::ExtReceiverSetup(msg) => {
//                         proto::message::Msg::ExtReceiverSetup(proto::ExtReceiverSetup::from(msg))
//                     }
//                     OTMessage::ExtDerandomize(msg) => {
//                         proto::message::Msg::ExtDerandomize(proto::ExtDerandomize::from(msg))
//                     }
//                     OTMessage::ExtSenderPayload(msg) => {
//                         proto::message::Msg::ExtSenderPayload(proto::ExtSenderPayload::from(msg))
//                     }
//                 }),
//             }
//         }
//     }

//     impl TryFrom<proto::Message> for OTMessage {
//         type Error = std::io::Error;
//         #[inline]
//         fn try_from(m: proto::Message) -> Result<Self, Self::Error> {
//             if let Some(msg) = m.msg {
//                 let m = match msg {
//                     proto::message::Msg::BaseReceiverSetupWrapper(msg) => {
//                         OTMessage::BaseReceiverSetupWrapper(BaseReceiverSetupWrapper::try_from(
//                             msg,
//                         )?)
//                     }
//                     proto::message::Msg::BaseReceiverSetup(msg) => {
//                         OTMessage::BaseReceiverSetup(ReceiverSetup::try_from(msg)?)
//                     }
//                     proto::message::Msg::BaseSenderSetup(msg) => {
//                         OTMessage::BaseSenderSetup(SenderSetup::try_from(msg)?)
//                     }
//                     proto::message::Msg::BaseSenderSetupWrapper(msg) => {
//                         OTMessage::BaseSenderSetupWrapper(BaseSenderSetupWrapper::try_from(msg)?)
//                     }
//                     proto::message::Msg::BaseSenderPayloadWrapper(msg) => {
//                         OTMessage::BaseSenderPayloadWrapper(BaseSenderPayloadWrapper::try_from(
//                             msg,
//                         )?)
//                     }
//                     proto::message::Msg::BaseSenderPayload(msg) => {
//                         OTMessage::BaseSenderPayload(SenderPayload::from(msg))
//                     }
//                     proto::message::Msg::ExtReceiverSetup(msg) => {
//                         OTMessage::ExtReceiverSetup(ExtReceiverSetup::try_from(msg)?)
//                     }
//                     proto::message::Msg::ExtDerandomize(msg) => {
//                         OTMessage::ExtDerandomize(ExtDerandomize::from(msg))
//                     }
//                     proto::message::Msg::ExtSenderPayload(msg) => {
//                         OTMessage::ExtSenderPayload(ExtSenderPayload::from(msg))
//                     }
//                 };
//                 Ok(m)
//             } else {
//                 Err(Error::new(ErrorKind::InvalidData, format!("{:?}", m)))
//             }
//         }
//     }

//     impl From<SenderSetup> for proto::BaseSenderSetup {
//         #[inline]
//         fn from(s: SenderSetup) -> Self {
//             Self {
//                 public_key: s.public_key.into(),
//             }
//         }
//     }

//     impl TryFrom<proto::BaseSenderSetup> for SenderSetup {
//         type Error = Error;

//         #[inline]
//         fn try_from(s: proto::BaseSenderSetup) -> Result<Self, Self::Error> {
//             Ok(Self {
//                 public_key: s.public_key.try_into()?,
//             })
//         }
//     }

//     impl From<SenderPayload> for proto::BaseSenderPayload {
//         #[inline]
//         fn from(p: SenderPayload) -> Self {
//             Self {
//                 ciphertexts: p
//                     .ciphertexts
//                     .into_iter()
//                     .map(|b| super::BlockPair {
//                         low: super::Block::from(b[0]),
//                         high: super::Block::from(b[1]),
//                     })
//                     .collect(),
//             }
//         }
//     }

//     impl From<proto::BaseSenderPayload> for SenderPayload {
//         #[inline]
//         fn from(p: proto::BaseSenderPayload) -> Self {
//             Self {
//                 ciphertexts: p
//                     .ciphertexts
//                     .into_iter()
//                     .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
//                     .collect(),
//             }
//         }
//     }

//     impl From<ReceiverSetup> for proto::BaseReceiverSetup {
//         #[inline]
//         fn from(s: ReceiverSetup) -> Self {
//             Self {
//                 blinded_choices: s
//                     .blinded_choices
//                     .into_iter()
//                     .map(super::RistrettoPoint::from)
//                     .collect(),
//             }
//         }
//     }

//     impl TryFrom<proto::BaseReceiverSetup> for ReceiverSetup {
//         type Error = Error;

//         #[inline]
//         fn try_from(s: proto::BaseReceiverSetup) -> Result<Self, Self::Error> {
//             let mut blinded_choices: Vec<curve25519_dalek::ristretto::RistrettoPoint> =
//                 Vec::with_capacity(s.blinded_choices.len());
//             for key in s.blinded_choices.into_iter() {
//                 blinded_choices.push(parse_ristretto_key(key.point)?);
//             }
//             Ok(Self { blinded_choices })
//         }
//     }

//     impl From<ExtReceiverSetup> for proto::ExtReceiverSetup {
//         #[inline]
//         fn from(s: ExtReceiverSetup) -> Self {
//             Self {
//                 ncols: s.ncols as u32,
//                 table: s.table,
//                 x: s.x.to_vec(),
//                 t0: s.t0.to_vec(),
//                 t1: s.t1.to_vec(),
//             }
//         }
//     }

//     impl TryFrom<proto::ExtReceiverSetup> for ExtReceiverSetup {
//         type Error = Error;

//         #[inline]
//         fn try_from(s: proto::ExtReceiverSetup) -> Result<Self, Error> {
//             Ok(Self {
//                 ncols: s.ncols as usize,
//                 table: s.table,
//                 x: s.x.try_into().map_err(|_| ErrorKind::InvalidData)?,
//                 t0: s.t0.try_into().map_err(|_| ErrorKind::InvalidData)?,
//                 t1: s.t1.try_into().map_err(|_| ErrorKind::InvalidData)?,
//             })
//         }
//     }

//     impl From<ExtDerandomize> for proto::ExtDerandomize {
//         #[inline]
//         fn from(d: ExtDerandomize) -> Self {
//             Self { flip: d.flip }
//         }
//     }

//     impl From<proto::ExtDerandomize> for ExtDerandomize {
//         #[inline]
//         fn from(d: proto::ExtDerandomize) -> Self {
//             Self { flip: d.flip }
//         }
//     }

//     impl From<ExtSenderPayload> for proto::ExtSenderPayload {
//         #[inline]
//         fn from(p: ExtSenderPayload) -> Self {
//             Self {
//                 ciphertexts: p
//                     .ciphertexts
//                     .into_iter()
//                     .map(|b| super::BlockPair {
//                         low: super::Block::from(b[0]),
//                         high: super::Block::from(b[1]),
//                     })
//                     .collect(),
//             }
//         }
//     }

//     impl From<proto::ExtSenderPayload> for ExtSenderPayload {
//         #[inline]
//         fn from(p: proto::ExtSenderPayload) -> Self {
//             Self {
//                 ciphertexts: p
//                     .ciphertexts
//                     .into_iter()
//                     .map(|pair| [crate::Block::from(pair.low), crate::Block::from(pair.high)])
//                     .collect(),
//             }
//         }
//     }

//     impl From<BaseSenderSetupWrapper> for proto::BaseSenderSetupWrapper {
//         #[inline]
//         fn from(s: BaseSenderSetupWrapper) -> Self {
//             Self {
//                 setup: proto::BaseSenderSetup::from(s.setup),
//                 cointoss_commit: s.cointoss_commit.to_vec(),
//             }
//         }
//     }

//     impl TryFrom<proto::BaseSenderSetupWrapper> for BaseSenderSetupWrapper {
//         type Error = Error;

//         #[inline]
//         fn try_from(s: proto::BaseSenderSetupWrapper) -> Result<Self, Error> {
//             Ok(Self {
//                 setup: s.setup.try_into().map_err(|_| ErrorKind::InvalidData)?,
//                 cointoss_commit: s
//                     .cointoss_commit
//                     .try_into()
//                     .map_err(|_| ErrorKind::InvalidData)?,
//             })
//         }
//     }

//     impl From<BaseReceiverSetupWrapper> for proto::BaseReceiverSetupWrapper {
//         #[inline]
//         fn from(s: BaseReceiverSetupWrapper) -> Self {
//             Self {
//                 setup: proto::BaseReceiverSetup::from(s.setup),
//                 cointoss_share: s.cointoss_share.to_vec(),
//             }
//         }
//     }

//     impl TryFrom<proto::BaseReceiverSetupWrapper> for BaseReceiverSetupWrapper {
//         type Error = Error;

//         #[inline]
//         fn try_from(s: proto::BaseReceiverSetupWrapper) -> Result<Self, Error> {
//             Ok(Self {
//                 setup: s.setup.try_into().map_err(|_| ErrorKind::InvalidData)?,
//                 cointoss_share: s
//                     .cointoss_share
//                     .try_into()
//                     .map_err(|_| ErrorKind::InvalidData)?,
//             })
//         }
//     }

//     impl From<BaseSenderPayloadWrapper> for proto::BaseSenderPayloadWrapper {
//         #[inline]
//         fn from(s: BaseSenderPayloadWrapper) -> Self {
//             Self {
//                 payload: proto::BaseSenderPayload::from(s.payload),
//                 cointoss_share: s.cointoss_share.to_vec(),
//             }
//         }
//     }

//     impl TryFrom<proto::BaseSenderPayloadWrapper> for BaseSenderPayloadWrapper {
//         type Error = Error;

//         #[inline]
//         fn try_from(s: proto::BaseSenderPayloadWrapper) -> Result<Self, Error> {
//             Ok(Self {
//                 payload: s.payload.try_into().map_err(|_| ErrorKind::InvalidData)?,
//                 cointoss_share: s
//                     .cointoss_share
//                     .try_into()
//                     .map_err(|_| ErrorKind::InvalidData)?,
//             })
//         }
//     }

//     #[cfg(test)]
//     pub mod tests {
//         use super::*;
//         use crate::{
//             base::tests::fixtures::{ot_core_data, Data},
//             extension::tests::fixtures::{ot_ext_core_data, Data as ExtData},
//         };

//         use fixtures::*;
//         use rstest::*;

//         pub mod fixtures {
//             use super::*;

//             pub struct ProtoData {
//                 pub sender_setup: proto::BaseSenderSetup,
//                 pub receiver_setup: proto::BaseReceiverSetup,
//                 pub sender_payload: proto::BaseSenderPayload,
//             }

//             pub struct ProtoExtData {
//                 pub base_sender_setup: proto::BaseSenderSetupWrapper,
//                 pub base_receiver_setup: proto::BaseReceiverSetupWrapper,
//                 pub base_sender_payload: proto::BaseSenderPayloadWrapper,
//             }

//             #[fixture]
//             #[once]
//             pub fn proto_base_core_data(ot_core_data: &Data) -> ProtoData {
//                 ProtoData {
//                     sender_setup: ot_core_data.sender_setup.into(),
//                     receiver_setup: ot_core_data.receiver_setup.clone().into(),
//                     sender_payload: ot_core_data.sender_payload.clone().into(),
//                 }
//             }

//             #[fixture]
//             #[once]
//             pub fn proto_ext_core_data(ot_ext_core_data: &ExtData) -> ProtoExtData {
//                 ProtoExtData {
//                     base_sender_setup: ot_ext_core_data.base_sender_setup.into(),
//                     base_receiver_setup: ot_ext_core_data.base_receiver_setup.clone().into(),
//                     base_sender_payload: ot_ext_core_data.base_sender_payload.clone().into(),
//                 }
//             }
//         }

//         #[rstest]
//         fn test_proto_ot(proto_base_core_data: &fixtures::ProtoData, ot_core_data: &Data) {
//             let sender_setup: crate::base::SenderSetup = proto_base_core_data
//                 .sender_setup
//                 .clone()
//                 .try_into()
//                 .unwrap();

//             assert_eq!(sender_setup, ot_core_data.sender_setup);

//             let receiver_setup: crate::base::ReceiverSetup = proto_base_core_data
//                 .receiver_setup
//                 .clone()
//                 .try_into()
//                 .unwrap();

//             assert_eq!(receiver_setup, ot_core_data.receiver_setup);

//             let sender_payload: crate::base::SenderPayload = proto_base_core_data
//                 .sender_payload
//                 .clone()
//                 .try_into()
//                 .unwrap();

//             assert_eq!(sender_payload, ot_core_data.sender_payload);
//         }

//         #[rstest]
//         fn test_proto_ext(
//             proto_ext_core_data: &fixtures::ProtoExtData,
//             ot_ext_core_data: &ExtData,
//         ) {
//             let base_sender_setup: crate::extension::BaseSenderSetupWrapper =
//                 proto_ext_core_data
//                     .base_sender_setup
//                     .clone()
//                     .try_into()
//                     .unwrap();

//             assert_eq!(base_sender_setup, ot_ext_core_data.base_sender_setup);

//             let base_receiver_setup: crate::extension::BaseReceiverSetupWrapper =
//                 proto_ext_core_data
//                     .base_receiver_setup
//                     .clone()
//                     .try_into()
//                     .unwrap();

//             assert_eq!(base_receiver_setup, ot_ext_core_data.base_receiver_setup);

//             let base_sender_payload: crate::extension::BaseSenderPayloadWrapper =
//                 proto_ext_core_data
//                     .base_sender_payload
//                     .clone()
//                     .try_into()
//                     .unwrap();

//             assert_eq!(base_sender_payload, ot_ext_core_data.base_sender_payload);
//         }
//     }
// }

// #[cfg(feature = "proto")]
// pub use proto::*;
