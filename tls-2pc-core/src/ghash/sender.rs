use super::{
    compute_missing_mul_shares, compute_new_add_shares, mul, AddShare, Finalized, GhashError, Init,
    Intermediate, MulShare, SenderAddSharing, SenderMulSharings,
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
        let mut hashkey_powers = vec![mul_share.inner()];

        compute_missing_mul_shares(&mut hashkey_powers, self.ciphertext.len());
        let hashkey_powers = hashkey_powers.into_iter().map(MulShare::new).collect();
        (
            GhashSender {
                state: Intermediate {
                    odd_mul_shares: hashkey_powers,
                    cached_add_shares: vec![],
                },
                ciphertext: self.ciphertext,
            },
            SenderAddSharing {
                sender_add_sharing: sharing.inner(),
            },
        )
    }
}

impl GhashSender<Intermediate> {
    /// Convert all powers of `H` into additive shares
    ///
    /// Converts the multiplicative shares into additive ones; also returns
    /// `SenderMulPowerSharings`, which is needed for the receiver side
    pub fn into_add_powers(mut self) -> (GhashSender<Finalized>, SenderMulSharings) {
        // If we already have some cached additive sharings, we do not need to do an OT for them.
        // So we compute an offset to ignore them. We divide by 2 because `cached_add_shares`
        // contain even and odd powers, while mul_shares only have odd powers.
        let offset =
            self.state.cached_add_shares.len() / 2 + (self.state.cached_add_shares.len() & 1);

        let mut mul_power_sharings: Vec<([u128; 128], [u128; 128])> = vec![];
        let additive_odd_shares: Vec<AddShare> = self.state.odd_mul_shares[offset..]
            .iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                mul_power_sharings.push(sharing.inner());
                add_share
            })
            .collect();

        compute_new_add_shares(&additive_odd_shares, &mut self.state.cached_add_shares);

        (
            GhashSender {
                state: Finalized {
                    add_shares: self.state.cached_add_shares,
                    odd_mul_shares: self.state.odd_mul_shares,
                },
                ciphertext: self.ciphertext,
            },
            SenderMulSharings {
                sender_mul_sharing: mul_power_sharings,
            },
        )
    }
}

impl GhashSender<Finalized> {
    /// Generate the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `self.ciphertext`
    pub fn generate_mac(&self) -> u128 {
        let offset = self.state.add_shares.len() - self.ciphertext.len();
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
    ) -> (GhashSender<Finalized>, Option<SenderMulSharings>) {
        if new_ciphertext.len() <= self.ciphertext.len() {
            self.ciphertext = new_ciphertext;
            return (self, None);
        }

        let mut hashkey_powers = self
            .state
            .odd_mul_shares
            .iter()
            .map(MulShare::inner)
            .collect();
        compute_missing_mul_shares(&mut hashkey_powers, new_ciphertext.len());

        let sender = GhashSender {
            state: Intermediate {
                odd_mul_shares: hashkey_powers.iter().map(|x| MulShare::new(*x)).collect(),
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
