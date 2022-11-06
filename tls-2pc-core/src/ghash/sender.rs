use super::{
    compute_powers, mul, AddShare, Finalized, Init, Intermediate, MaskedPartialValue, MulShare,
    SenderAddSharing, SenderMulPowerSharings,
};

/// The sender part for our 2PC Ghash implementation
///
/// `GhashSender` will be the sender side during the oblivious transfer.
pub struct GhashSender<T = Init> {
    /// Different hashkey representations
    state: T,
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
            state: Init {
                add_share: AddShare::new(hashkey),
            },
            ciphertext,
        }
    }

    /// Transform `self` into a `GhashSender` holding multiplicative shares of powers of `H`
    ///
    /// Converts the additive share into multiplicative shares of powers of `H`; also returns
    /// `SenderAddSharing`, which is needed for the receiver side
    pub fn compute_mul_powers(self) -> (GhashSender<Intermediate>, SenderAddSharing) {
        let (mul_share, sharing) = self.state.add_share.to_multiplicative();

        let hashkey_powers = compute_powers(mul_share.inner(), self.ciphertext.len())
            .into_iter()
            .map(MulShare::new)
            .collect();
        (
            GhashSender {
                state: Intermediate {
                    mul_shares: hashkey_powers,
                },
                ciphertext: self.ciphertext,
            },
            SenderAddSharing(Box::new(sharing)),
        )
    }
}

impl GhashSender<Intermediate> {
    /// Convert all powers of `H` into additive shares
    ///
    /// Converts the multiplicative shares into additive ones; also returns
    /// `SenderMulPowerSharings`, which is needed for the receiver side
    pub fn into_add_powers(self) -> (GhashSender<Finalized>, SenderMulPowerSharings) {
        let mut sharings: Vec<MaskedPartialValue> = vec![];
        let hashkey_powers: Vec<AddShare> = self
            .state
            .mul_shares
            .iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                sharings.push(sharing);
                add_share
            })
            .collect();
        (
            GhashSender {
                state: Finalized {
                    add_shares: hashkey_powers,
                    mul_shares: self.state.mul_shares,
                },
                ciphertext: self.ciphertext,
            },
            SenderMulPowerSharings(sharings),
        )
    }
}

impl GhashSender<Finalized> {
    /// Generate the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `self.ciphertext`
    pub fn generate_mac(&self) -> u128 {
        self.state
            .add_shares
            .iter()
            .skip(1)
            .rev()
            .enumerate()
            .fold(0, |acc, (k, hashkey_power)| {
                acc ^ mul(hashkey_power.inner(), self.ciphertext[k])
            })
    }

    /// Change the ciphertext
    ///
    /// This allows to reuse the hashkeys for computing a MAC for a different ciphertext
    pub fn change_ciphertext(&mut self, new_ciphertext: Vec<u128>) {
        self.ciphertext = new_ciphertext;
    }
}

#[cfg(test)]
impl<T> GhashSender<T> {
    pub fn state(&self) -> &T {
        &self.state
    }
}
