use super::BaseReceiver;
use super::KosMatrix;
use crate::Block;
use rand_chacha::ChaCha12Rng;

pub trait SenderState {}

pub struct Initialized {
    pub rng: ChaCha12Rng,
    pub base_receiver: BaseReceiver,
    pub base_choices: Vec<bool>,
    pub cointoss_share: [u8; 32],
}
impl SenderState for Initialized {}

pub struct BaseSetup {
    pub receiver_cointoss_commit: [u8; 32],
    pub base_receiver: BaseReceiver,
    pub base_choices: Vec<bool>,
    pub cointoss_share: [u8; 32],
}
impl SenderState for BaseSetup {}

#[cfg_attr(test, derive(Debug))]
pub struct BaseReceive {
    pub cointoss_random: [u8; 32],
    pub base_choices: Vec<bool>,
    pub seeds: Vec<Block>,
    pub rngs: Vec<ChaCha12Rng>,
}
impl SenderState for BaseReceive {}

#[cfg_attr(test, derive(Debug))]
pub struct Setup {
    pub table: KosMatrix,
    pub count: usize,
    pub sent: usize,
    pub base_choices: Vec<bool>,
}
impl SenderState for Setup {}

#[cfg_attr(test, derive(Debug))]
pub struct RandSetup {
    pub table: KosMatrix,
    pub count: usize,
    pub sent: usize,
    pub base_choices: Vec<bool>,
}
impl SenderState for RandSetup {}
