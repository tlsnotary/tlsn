use crate::ghash::{SenderAddSharing, SenderMulSharing};
use mpc_core::Block;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// Message for 2PC Ghash computation
pub enum GhashMessage {
    SenderAddEnvelope(()),
    SenderMulEnvelope(()),
}

impl From<SenderAddSharing> for Vec<[Block; 2]> {
    fn from(value: SenderAddSharing) -> Self {
        let mut sender_add_envelope: Vec<[Block; 2]> = Vec::with_capacity(value.choice_zero.len());
        for (zero, one) in
            std::iter::zip(value.choice_zero.into_iter(), value.choice_one.into_iter())
        {
            sender_add_envelope.push([Block::new(zero), Block::new(one)]);
        }
        sender_add_envelope
    }
}

impl From<SenderMulSharing> for Vec<[Block; 2]> {
    fn from(value: SenderMulSharing) -> Self {
        let mut sender_mul_envelope: Vec<[Block; 2]> =
            Vec::with_capacity(value.choice_zero.len() * 128);
        for (zero, one) in std::iter::zip(
            value.choice_zero.into_iter().flatten(),
            value.choice_one.into_iter().flatten(),
        ) {
            sender_mul_envelope.push([Block::new(zero), Block::new(one)]);
        }
        sender_mul_envelope
    }
}
