use mpz_fields::gf2_128::Gf2_128;

mod sealed {
    pub(crate) trait Sealed {}

    impl Sealed for super::Init {}
    impl Sealed for super::Intermediate {}
    impl Sealed for super::Finalized {}
}

pub(crate) trait State: sealed::Sealed {}

impl State for Init {}
impl State for Intermediate {}
impl State for Finalized {}

/// Init state for Ghash protocol.
///
/// This is before any OT has taken place.
#[derive(Clone)]
pub(crate) struct Init;

opaque_debug::implement!(Init);

/// Intermediate state for Ghash protocol.
///
/// This is when the additive share has been converted into a multiplicative
/// share and all the needed powers have been computed.
#[derive(Clone)]
pub(crate) struct Intermediate {
    pub(super) odd_mul_shares: Vec<Gf2_128>,
    // A vec of all additive shares (even and odd) we already have.
    // (In order to simplify the code) the n-th index of the vec corresponds to the additive share
    // of the (n+1)-th power of H, e.g. the share of H^1 is located at the 0-th index of the vec
    // It always contains an even number of consecutive shares starting from the share of H^1 up to
    // the share of H^(cached_add_shares.len()).
    pub(super) cached_add_shares: Vec<Gf2_128>,
}

opaque_debug::implement!(Intermediate);

/// Final state for Ghash protocol.
///
/// This is when each party can compute a final share of the ghash output,
/// because both now have additive shares of all the powers of `H`.
#[derive(Clone)]
pub(crate) struct Finalized {
    pub(super) odd_mul_shares: Vec<Gf2_128>,
    pub(super) add_shares: Vec<Gf2_128>,
}

opaque_debug::implement!(Finalized);
