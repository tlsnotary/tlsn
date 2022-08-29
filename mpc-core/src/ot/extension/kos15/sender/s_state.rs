use super::BaseReceiver;

// Table's rows are such that for each row j: table[j] = R[j], if Receiver's choice bit was 0
// or table[j] = R[j] ^ base_choices, if Receiver's choice bit was 1
// (where R is the table which Receiver has. Note that base_choices is known only to us).
use super::KosMatrix;
use crate::Block;
use rand_chacha::ChaCha12Rng;

pub trait SenderState {}

// Number of extended OTs available
pub type Count = usize;

// Sent extended OTs
pub type Sent = usize;

// Our XOR share for the cointoss protocol
pub type CointossShare = [u8; 32];

// Choice bits for the base OT protocol
pub type BaseChoices = Vec<bool>;

pub struct Initialized {
    pub rng: ChaCha12Rng,
    pub base_receiver: BaseReceiver,
    pub base_choices: Vec<bool>,
    pub cointoss_share: CointossShare,
}
impl SenderState for Initialized {}

pub struct BaseSetup {
    // The Receiver's sha256 commitment to their cointoss share
    pub receiver_cointoss_commit: [u8; 32],
    pub base_receiver: BaseReceiver,
    pub base_choices: BaseChoices,
    pub cointoss_share: CointossShare,
}
impl SenderState for BaseSetup {}

#[cfg_attr(test, derive(Debug))]
pub struct BaseReceive {
    // The shared random value which both parties will have at the end of the cointoss protocol
    pub cointoss_random: [u8; 32],
    pub base_choices: BaseChoices,
    // Seeds are the result of running base OT setup. They are used to seed the RNGs.
    pub seeds: Vec<Block>,
    pub rngs: Vec<ChaCha12Rng>,
}
impl SenderState for BaseReceive {}

#[cfg_attr(test, derive(Debug))]
pub struct Setup {
    pub table: KosMatrix,
    pub count: Count,
    pub sent: Sent,
    pub base_choices: BaseChoices,
}
impl SenderState for Setup {}

#[cfg_attr(test, derive(Debug))]
pub struct RandSetup {
    pub table: KosMatrix,
    pub count: Count,
    pub sent: Sent,
    pub base_choices: BaseChoices,
}
impl SenderState for RandSetup {}
