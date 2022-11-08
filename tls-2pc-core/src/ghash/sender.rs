use super::{
    compute_higher_powers, mul, AddShare, Finalized, GhashError, Init, Intermediate,
    MaskedPartialValue, MulShare, SenderAddSharing, SenderMulPowerSharings,
};

/// The sender part for our 2PC Ghash implementation
///
/// `GhashSender` will be the sender side during the oblivious transfer.
pub struct GhashSender<T = Init> {
    /// Inner state
    state: T,
    /// The ciphertext for which a 2PC MAC should be constructed
    ciphertext: Vec<u128>,
}

impl GhashSender {
    /// Create a new `GhashSender`
    ///
    /// * `hashkey` - This is an additive sharing of `H`, which is the AES-encrypted 0 block
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
        let mut hashkey_powers = vec![1_u128 << 127, mul_share.inner()];

        compute_higher_powers(&mut hashkey_powers, self.ciphertext.len() - 1);
        let hashkey_powers = hashkey_powers.into_iter().map(MulShare::new).collect();
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
        // If we already have some cached additive sharings, we do not need to do an OT for them.
        // So we compute an offset to ignore them
        let offset = self.state.cached_add_shares.len();

        let mut mul_power_sharings: Vec<MaskedPartialValue> = vec![];
        let additive_shares: Vec<AddShare> = self.state.mul_shares[offset..]
            .iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                mul_power_sharings.push(sharing);
                add_share
            })
            .collect();

        self.state
            .cached_add_shares
            .extend_from_slice(&additive_shares);
        (
            GhashSender {
                state: Finalized {
                    add_shares: self.state.cached_add_shares,
                    mul_shares: self.state.mul_shares,
                },
                ciphertext: self.ciphertext,
            },
            SenderMulPowerSharings(mul_power_sharings),
        )
    }
}

impl GhashSender<Finalized> {
    /// Generate the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `self.ciphertext`
    pub fn generate_mac(&self) -> u128 {
        let offset = self.state.add_shares.len() - self.ciphertext.len() - 1;
        self.ciphertext
            .iter()
            .zip(self.state.add_shares.iter().rev().skip(offset))
            .fold(0, |acc, (block, share)| acc ^ mul(*block, share.inner()))
    }

    /// Change the ciphertext
    ///
    /// This allows to reuse the hashkeys for computing a MAC for a different ciphertext. If the
    /// new ciphertext is longer than the old one, we need to compute the missing powers of `H`
    /// using batched OTs, so in this case we also get new sharings for the receiver.
    pub fn change_ciphertext(
        mut self,
        new_ciphertext: Vec<u128>,
    ) -> (GhashSender<Finalized>, Option<SenderMulPowerSharings>) {
        // Check if we need to compute new powers of `H`
        let difference = new_ciphertext.len() as i32 - self.state.add_shares.len() as i32 + 1;

        let mut hashkey_powers = self.state.mul_shares.iter().map(MulShare::inner).collect();
        if difference > 0 {
            compute_higher_powers(&mut hashkey_powers, difference as usize);
        } else {
            self.ciphertext = new_ciphertext;
            return (self, None);
        }

        let sender = GhashSender {
            state: Intermediate {
                mul_shares: hashkey_powers.iter().map(|x| MulShare::new(*x)).collect(),
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
}
