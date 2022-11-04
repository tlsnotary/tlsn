use super::{compute_powers, mul, AddShare, MaskedPartialValue, MulShare};

/// The sender part for our 2PC Ghash implementation
///
/// `GhashSender` will be the sender side during the oblivious transfer.
pub struct GhashSender<T = AddShare> {
    /// Different hashkey representations
    hashkey_repr: T,
    /// The ciphertext for which a 2PC MAC should be constructed
    ciphertext: Vec<u128>,
}

impl GhashSender {
    /// Create a new `GhashSender`
    ///
    /// * `hashkey` - This is `H`, which is the AES-encrypted 0 block
    /// * `ciphertext` - The AES-encrypted 128-bit blocks
    pub fn new(hashkey: u128, ciphertext: Vec<u128>) -> Self {
        Self {
            hashkey_repr: AddShare::new(hashkey),
            ciphertext,
        }
    }

    /// Transform `self` into a `GhashSender` holding multiplicative shares of powers of `H`
    ///
    /// Converts the additive share into multiplicative shares of powers of `H`; also returns
    /// `MaskedPartialValue`, which is needed for the receiver side
    pub fn compute_mul_powers(self) -> (GhashSender<Vec<MulShare>>, MaskedPartialValue) {
        let (mul_share, sharing) = self.hashkey_repr.to_multiplicative();

        let hashkey_powers = compute_powers(mul_share.inner(), self.ciphertext.len())
            .into_iter()
            .map(|power| MulShare::new(power))
            .collect();
        (
            GhashSender {
                hashkey_repr: hashkey_powers,
                ciphertext: self.ciphertext,
            },
            sharing,
        )
    }
}

impl GhashSender<Vec<MulShare>> {
    /// Convert all powers of `H` into additive shares
    ///
    /// Converts the multiplicative shares into additive ones; also returns
    /// `MaskedPartialValue`, which is needed for the receiver side
    pub fn into_add_powers(self) -> (GhashSender<Vec<AddShare>>, Vec<MaskedPartialValue>) {
        let mut sharings: Vec<MaskedPartialValue> = vec![];
        let hashkey_powers: Vec<AddShare> = self
            .hashkey_repr
            .into_iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                sharings.push(sharing);
                add_share
            })
            .collect();
        (
            GhashSender {
                hashkey_repr: hashkey_powers,
                ciphertext: self.ciphertext,
            },
            sharings,
        )
    }
}

impl GhashSender<Vec<AddShare>> {
    /// Compute the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `self.ciphertext`
    pub fn into_mac(self) -> u128 {
        self.hashkey_repr
            .into_iter()
            .enumerate()
            .fold(0, |acc, (k, hashkey_power)| {
                acc ^ mul(hashkey_power.inner(), self.ciphertext[k])
            })
    }
}
