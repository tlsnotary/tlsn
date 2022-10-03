use super::{BaseSender, KosMatrix};
use crate::Block;
use rand_chacha::ChaCha12Rng;

pub trait ReceiverState {}

// Our XOR share for the cointoss protocol
pub type CointossShare = [u8; 32];

// Commitment of the sender for committed OT
pub type Commitment = [u8; 32];

pub struct Initialized {
    pub(crate) base_sender: BaseSender,
    pub(crate) rng: ChaCha12Rng,
    pub(crate) cointoss_share: CointossShare,
    pub(crate) commitment: Option<Commitment>,
}
impl ReceiverState for Initialized {}

pub struct BaseSetup {
    pub(crate) rng: ChaCha12Rng,
    pub(crate) base_sender: BaseSender,
    pub(crate) cointoss_share: CointossShare,
    pub(crate) commitment: Option<Commitment>,
}
impl ReceiverState for BaseSetup {}

pub struct BaseSend {
    pub(crate) rng: ChaCha12Rng,
    pub(crate) rngs: Vec<[ChaCha12Rng; 2]>,
    // The shared random value which both parties will have at the end of the cointoss protocol
    pub(crate) cointoss_random: [u8; 32],
    pub(crate) commitment: Option<Commitment>,
}
impl ReceiverState for BaseSend {}

pub struct Setup {
    pub(crate) table: KosMatrix,
    pub(crate) choices: Vec<bool>,
}
impl ReceiverState for Setup {}

pub struct RandSetup {
    pub(crate) rng: ChaCha12Rng,
    pub(crate) table: KosMatrix,
    pub(crate) choices: Vec<bool>,
    pub(crate) derandomized: Vec<bool>,
    // Records the received, encrypted blocks, sent by the sender for later use in committed OT
    pub(crate) sender_output_tape: Vec<[Block; 2]>,
    // Records the choices made by the receiver for later use in committed OT
    pub(crate) choices_tape: Vec<bool>,
    pub(crate) commitment: Option<Commitment>,
    // The initial number of OTs supported by this setup
    // Used for committed OT
    pub(crate) init_ot_number: usize,
}
impl ReceiverState for RandSetup {}
