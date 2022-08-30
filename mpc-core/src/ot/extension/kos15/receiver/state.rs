use super::BaseSender;
use super::KosMatrix;
use crate::Block;
use rand_chacha::ChaCha12Rng;

pub trait ReceiverState {}

// Our XOR share for the cointoss protocol
pub type CointossShare = [u8; 32];

pub struct Initialized {
    pub(crate) base_sender: BaseSender,
    pub(crate) rng: ChaCha12Rng,
    pub(crate) cointoss_share: CointossShare,
}
impl ReceiverState for Initialized {}

pub struct BaseSetup {
    pub(crate) rng: ChaCha12Rng,
    pub(crate) base_sender: BaseSender,
    pub(crate) cointoss_share: CointossShare,
}
impl ReceiverState for BaseSetup {}

pub struct BaseSend {
    pub(crate) rng: ChaCha12Rng,
    // Seeds are the result of running base OT setup. They are used to seed the RNGs.
    pub(crate) seeds: Vec<[Block; 2]>,
    pub(crate) rngs: Vec<[ChaCha12Rng; 2]>,
    // The shared random value which both parties will have at the end of the cointoss protocol
    pub(crate) cointoss_random: [u8; 32],
}
impl ReceiverState for BaseSend {}

pub struct Setup {
    pub(crate) table: KosMatrix,
    pub(crate) choices: Vec<bool>,
}
impl ReceiverState for Setup {}

pub struct RandSetup {
    pub(crate) table: KosMatrix,
    pub(crate) choices: Vec<bool>,
    pub(crate) derandomized: Vec<bool>,
}
impl ReceiverState for RandSetup {}
