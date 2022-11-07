use super::{
    attach_missing_mul_powers, compute_powers, mul, AddShare, Finalized, GhashError, Init,
    Intermediate, MaskedPartialValue, MulShare, SenderAddSharing, SenderMulPowerSharings,
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
    pub fn new(hashkey: u128, ciphertext: Vec<u128>) -> Result<Self, GhashError> {
        if ciphertext.is_empty() {
            return Err(GhashError::NoCipherText);
        }

        let sender = Self {
            state: Init {
                add_share: AddShare::new(hashkey),
            },
            ciphertext,
        };
        Ok(sender)
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
                    cached_add_shares: vec![],
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
    pub fn into_add_powers(mut self) -> (GhashSender<Finalized>, SenderMulPowerSharings) {
        let offset = self.state.cached_add_shares.len();

        let mut sharings: Vec<MaskedPartialValue> = vec![];
        let hashkey_powers: Vec<AddShare> = self.state.mul_shares[offset..]
            .iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                sharings.push(sharing);
                add_share
            })
            .collect();

        self.state
            .cached_add_shares
            .extend_from_slice(&hashkey_powers);
        (
            GhashSender {
                state: Finalized {
                    add_shares: self.state.cached_add_shares,
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
    /// This allows to reuse the hashkeys for computing a MAC for a different ciphertext.
    /// If the new ciphertext is longer than the old one, we need to compute the missing
    /// powers of `H`, so in this case we also get new sharings.
    pub fn change_ciphertext(
        mut self,
        new_ciphertext: Vec<u128>,
    ) -> (GhashSender<Finalized>, Option<SenderMulPowerSharings>) {
        // Check if we need to compute new powers of `H`
        let difference = new_ciphertext.len() as i32 - self.state.add_shares.len() as i32 + 1;

        if difference > 0 {
            attach_missing_mul_powers(&mut self.state.mul_shares, difference as usize);
        } else {
            self.ciphertext = new_ciphertext;
            return (self, None);
        }

        let sender = GhashSender {
            state: Intermediate {
                mul_shares: self.state.mul_shares,
                cached_add_shares: self.state.add_shares,
            },
            ciphertext: new_ciphertext,
        };

        let (sender, sharings) = sender.into_add_powers();
        (sender, Some(sharings))
    }
}

#[cfg(test)]
impl<T> GhashSender<T> {
    pub fn state(&self) -> &T {
        &self.state
    }

    pub fn ciphertext(&self) -> &Vec<u128> {
        &self.ciphertext
    }
}
