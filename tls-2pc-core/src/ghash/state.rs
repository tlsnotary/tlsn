mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Init {}
    impl Sealed for super::Intermediate {}
    impl Sealed for super::Finalized {}
}

/// Init state for Ghash protocol
///
/// This is before any OT has taken place
#[derive(Clone, Debug)]
pub struct Init {
    pub(super) add_share: u128,
}

/// Intermediate state for Ghash protocol
///
/// This is when the additive share has been converted into a multiplicative share and all the
/// needed powers have been computed
#[derive(Clone, Debug)]
pub struct Intermediate {
    pub(super) odd_mul_shares: Vec<u128>,
    pub(super) cached_add_shares: Vec<u128>,
}

/// Final state for Ghash protocol
///
/// This is when each party can compute a final share of the ghash output, because both now have
/// additive shares of all the powers of `H`
#[derive(Clone, Debug)]
pub struct Finalized {
    pub(super) odd_mul_shares: Vec<u128>,
    pub(super) add_shares: Vec<u128>,
}
