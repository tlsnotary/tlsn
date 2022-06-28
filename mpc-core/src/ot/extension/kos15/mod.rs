use crate::Block;

mod receiver;
mod sender;

pub use receiver::*;
pub use sender::*;

// We instantiate KOS15 w.r.t the DH-OT defined in CO15
pub(crate) use crate::ot::base::dh_ot::{
    DhOtReceiver as BaseReceiver, DhOtSender as BaseSender, ReceiverChoices as ReceiverSetup,
    SenderPayload, SenderSetup,
};

/// OT extension Sender plays the role of base OT Receiver and sends the
/// second message containing base OT setup and cointoss share
#[derive(Debug, Clone, std::cmp::PartialEq)]
pub struct BaseReceiverSetup {
    pub setup: ReceiverSetup,
    // Cointoss protocol's 2nd message: Receiver reveals share
    pub cointoss_share: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExtSenderPayload {
    pub ciphertexts: Vec<[Block; 2]>,
}
