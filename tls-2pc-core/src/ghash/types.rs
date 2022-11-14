use mpc_core::Block;

#[derive(Debug, Clone)]
/// The sharing for the additive share of the sender
///
/// Each struct field corresponds to the choices of the receiver
pub struct SenderAddSharing {
    pub choice_zero: Vec<u128>,
    pub choice_one: Vec<u128>,
}

/// The sharing for the multiplicative shares of the sender
///
/// Each struct field corresponds to the choices of the receiver. Note that we use this to send
/// several multiplicative shares in one go.
#[derive(Debug, Clone)]
pub struct SenderMulSharing {
    pub choice_zero: Vec<Vec<u128>>,
    pub choice_one: Vec<Vec<u128>>,
}

#[derive(Debug, Clone)]
/// The receiver choice for the additive share, needed as input for the OT
pub struct ReceiverAddChoice(pub u128);

impl From<ReceiverAddChoice> for Vec<bool> {
    fn from(value: ReceiverAddChoice) -> Vec<bool> {
        let mut out: Vec<bool> = vec![];
        for k in 0..128 {
            out.push((value.0 >> k & 1) == 1);
        }
        out
    }
}

#[derive(Debug, Clone)]
/// The receiver choices for the multiplicative shares, needed as input for the batched OT
pub struct ReceiverMulChoices(pub Vec<u128>);

impl From<ReceiverMulChoices> for Vec<bool> {
    fn from(value: ReceiverMulChoices) -> Vec<bool> {
        let mut out: Vec<bool> = vec![];
        for element in value.0 {
            for k in 0..128 {
                out.push((element >> k & 1) == 1);
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
/// The receiver's sharings as an output from the OT, needed to construct a multiplicative share
pub struct ReceiverMulShare(pub Vec<u128>);

impl From<Vec<Block>> for ReceiverMulShare {
    fn from(value: Vec<Block>) -> Self {
        Self(value.into_iter().map(|x| x.inner()).collect())
    }
}

#[derive(Debug, Clone)]
/// The receiver's sharings as an output from the batched OT, needed to construct additive shares
pub struct ReceiverAddShares(pub Vec<u128>);

impl From<Vec<Block>> for ReceiverAddShares {
    fn from(value: Vec<Block>) -> Self {
        Self(value.into_iter().map(|x| x.inner()).collect())
    }
}
