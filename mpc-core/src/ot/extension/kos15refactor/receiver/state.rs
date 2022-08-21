use super::BaseSender;
use crate::{matrix::ByteMatrix, Block};
use rand_chacha::ChaCha12Rng;

pub trait SenderState {}

pub struct Initialized {
    pub base_sender: BaseSender,
    pub rng: ChaCha12Rng,
    pub cointoss_share: [u8; 32],
}
impl SenderState for Initialized {}

pub struct BaseSetup {
    pub rng: ChaCha12Rng,
    pub base_sender: BaseSender,
    pub cointoss_share: [u8; 32],
}
impl SenderState for BaseSetup {}

pub struct BaseSend {
    pub rng: ChaCha12Rng,
    pub seeds: Vec<[Block; 2]>,
    pub rngs: Vec<[ChaCha12Rng; 2]>,
    pub cointoss_random: [u8; 32],
    pub cointoss_share: [u8; 32],
}
impl SenderState for BaseSend {}

pub struct Setup {
    pub table: ByteMatrix,
    pub choices: Vec<bool>,
    pub derandomized: Vec<bool>,
}
impl SenderState for Setup {}
