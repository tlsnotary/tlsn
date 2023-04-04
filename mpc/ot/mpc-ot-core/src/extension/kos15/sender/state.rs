use super::BaseReceiver;

use super::KosMatrix;
use rand_chacha::ChaCha12Rng;

pub trait SenderState {}

/// Number of extended OTs available
type Count = usize;

/// Sent extended OTs
type Sent = usize;

/// Our XOR share for the cointoss protocol
type CointossShare = [u8; 32];

/// Choice bits for the base OT protocol
type BaseChoices = Vec<bool>;

/// Salt for the seed of the rng
type Salt = [u8; 32];

/// The RNG which this extended OT sender will use for the following:
/// - base OT setup
/// - extended OT setup
/// - cointoss protocol inside extended OT setup
/// - salt (when committing to this RNG's seed)
type OTRng = ChaCha12Rng;

pub struct Initialized {
    pub(crate) rng: OTRng,
    pub(crate) base_receiver: BaseReceiver,
    pub(crate) base_choices: Vec<bool>,
    pub(crate) cointoss_share: CointossShare,
    pub(crate) salt: Salt,
}
impl SenderState for Initialized {}

pub struct BaseSetup {
    pub(crate) rng: OTRng,
    // The Receiver's blake3 commitment to their cointoss share
    pub(crate) receiver_cointoss_commit: [u8; 32],
    pub(crate) base_receiver: BaseReceiver,
    pub(crate) base_choices: BaseChoices,
    pub(crate) cointoss_share: CointossShare,
    pub(crate) salt: Salt,
}
impl SenderState for BaseSetup {}

#[cfg_attr(test, derive(Debug))]
pub struct BaseReceive {
    pub(crate) rng: OTRng,
    // The shared random value which both parties will have at the end of the cointoss protocol
    pub(crate) cointoss_random: [u8; 32],
    pub(crate) base_choices: BaseChoices,
    // RNGs seeded with random messages from base OT
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
    pub(crate) rng: OTRng,
    pub(crate) table: KosMatrix,
    pub(crate) count: Count,
    pub(crate) sent: Sent,
    pub(crate) base_choices: BaseChoices,
    pub(crate) salt: Salt,
}
impl SenderState for RandSetup {}
