use super::BaseSender;
use super::KosMatrix;
use crate::Block;
use rand_chacha::ChaCha12Rng;

pub trait ReceiverState {}

// Our XOR share for the cointoss protocol
pub type CointossShare = [u8; 32];

pub struct Initialized {
    pub base_sender: BaseSender,
    pub rng: ChaCha12Rng,
    pub cointoss_share: CointossShare,
}
impl ReceiverState for Initialized {}

pub struct BaseSetup {
    pub rng: ChaCha12Rng,
    pub base_sender: BaseSender,
    pub cointoss_share: CointossShare,
}
impl ReceiverState for BaseSetup {}

pub struct BaseSend {
    pub rng: ChaCha12Rng,
    // Seeds are the result of running base OT setup. They are used to seed the RNGs.
    pub seeds: Vec<[Block; 2]>,
    pub rngs: Vec<[ChaCha12Rng; 2]>,
    // The shared random value which both parties will have at the end of the cointoss protocol
    pub cointoss_random: [u8; 32],
    pub cointoss_share: CointossShare,
}
impl ReceiverState for BaseSend {}

pub struct Setup {
    pub table: KosMatrix,
    pub choices: Vec<bool>,
}
impl ReceiverState for Setup {}

pub struct RandSetup {
    pub table: KosMatrix,
    pub choices: Vec<bool>,
    pub derandomized: Vec<bool>,
}
impl ReceiverState for RandSetup {}
