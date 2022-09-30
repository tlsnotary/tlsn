use super::BaseReceiver;

// Table's rows are such that for each row j: table[j] = R[j], if Receiver's choice bit was 0
// or table[j] = R[j] ^ base_choices, if Receiver's choice bit was 1
// (where R is the table which Receiver has. Note that base_choices is known only to us).
use super::KosMatrix;
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

// Salt for the seed of the rng
pub type Salt = [u8; 32];

pub struct Initialized {
    pub(crate) rng: ChaCha12Rng,
    pub(crate) base_receiver: BaseReceiver,
    pub(crate) base_choices: Vec<bool>,
    pub(crate) cointoss_share: CointossShare,
    pub(crate) salt: Salt,
}
impl SenderState for Initialized {}

pub struct BaseSetup {
    pub(crate) rng: ChaCha12Rng,
    // The Receiver's sha256 commitment to their cointoss share
    pub(crate) receiver_cointoss_commit: [u8; 32],
    pub(crate) base_receiver: BaseReceiver,
    pub(crate) base_choices: BaseChoices,
    pub(crate) cointoss_share: CointossShare,
    pub(crate) salt: Salt,
}
impl SenderState for BaseSetup {}

#[cfg_attr(test, derive(Debug))]
pub struct BaseReceive {
    pub(crate) rng: ChaCha12Rng,
    // The shared random value which both parties will have at the end of the cointoss protocol
    pub(crate) cointoss_random: [u8; 32],
    pub(crate) base_choices: BaseChoices,
    pub(crate) rngs: Vec<ChaCha12Rng>,
    pub(crate) salt: Salt,
}
impl SenderState for BaseReceive {}

#[cfg_attr(test, derive(Debug))]
pub struct Setup {
    pub(crate) table: KosMatrix,
    pub(crate) count: Count,
    pub(crate) sent: Sent,
    pub(crate) base_choices: BaseChoices,
}
impl SenderState for Setup {}

#[cfg_attr(test, derive(Debug))]
pub struct RandSetup {
    pub(crate) rng: ChaCha12Rng,
    pub(crate) table: KosMatrix,
    pub(crate) count: Count,
    pub(crate) sent: Sent,
    pub(crate) base_choices: BaseChoices,
    // Tracks the offset of OTs split off from other OTs
    pub(crate) offset: usize,
    pub(crate) salt: Salt,
}
impl SenderState for RandSetup {}
