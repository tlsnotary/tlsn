use super::BaseSender;
use super::KosMatrix;
use crate::Block;
use rand_chacha::ChaCha12Rng;

pub trait ReceiverState {}

pub struct Initialized {
    pub base_sender: BaseSender,
    pub rng: ChaCha12Rng,
    pub cointoss_share: [u8; 32],
}
impl ReceiverState for Initialized {}

pub struct BaseSetup {
    pub rng: ChaCha12Rng,
    pub base_sender: BaseSender,
    pub cointoss_share: [u8; 32],
}
impl ReceiverState for BaseSetup {}

pub struct BaseSend {
    pub rng: ChaCha12Rng,
    pub seeds: Vec<[Block; 2]>,
    pub rngs: Vec<[ChaCha12Rng; 2]>,
    pub cointoss_random: [u8; 32],
    pub cointoss_share: [u8; 32],
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
