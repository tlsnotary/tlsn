use crate::Block;

mod receiver;
mod sender;

use super::BASE_COUNT;
pub use receiver::*;
pub use sender::*;

// We instantiate KOS15 w.r.t the DH-OT defined in CO15
pub(crate) use crate::ot::base::dh_ot::{
    DhOtReceiver as BaseReceiver, DhOtSender as BaseSender, ReceiverSetup as BaseReceiverSetup,
    SenderPayload as BaseSenderPayload, SenderSetup as BaseSenderSetup,
};

/// OT extension Sender plays the role of base OT Receiver and sends the
/// second message containing base OT setup and cointoss share
#[derive(Debug, Clone, PartialEq)]
pub struct BaseReceiverSetupWrapper {
    pub setup: BaseReceiverSetup,
    // Cointoss protocol's 2nd message: Receiver reveals share
    pub cointoss_share: [u8; 32],
}

/// OT extension Receiver plays the role of base OT Sender and sends the
/// first message containing base OT setup and cointoss commitment
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BaseSenderSetupWrapper {
    pub setup: BaseSenderSetup,
    // Cointoss protocol's 1st message: sha256 commitment
    pub cointoss_commit: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct BaseSenderPayloadWrapper {
    pub payload: BaseSenderPayload,
    // Cointoss protocol's 3rd message: Sender reveals share
    pub cointoss_share: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExtSenderPayload {
    pub ciphertexts: Vec<[Block; 2]>,
}

#[derive(Clone, Debug)]
pub struct ExtDerandomize {
    pub flip: Vec<bool>,
}

#[derive(Clone, Debug)]
pub struct ExtReceiverSetup {
    pub ncols: usize,
    // Indicates by how many bits the boolean choices of the receiver have been extended for
    // performance or security checks
    pub padding: usize,
    pub table: Vec<u8>,
    // x, t0, t1 are used for the KOS15 check
    pub x: [u8; BASE_COUNT / 8],
    pub t0: [u8; BASE_COUNT / 8],
    pub t1: [u8; BASE_COUNT / 8],
}
