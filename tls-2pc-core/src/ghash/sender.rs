use super::{
    compute_powers, mul, AddShare, Finalized, GhashError, Init, Intermediate, MaskedPartialValue,
    MulShare, SenderAddSharing, SenderMulPowerSharings,
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
        let (hashkey_powers, sharings) = batch_mul_to_add(&self.state.mul_shares);
        (
            GhashSender {
                state: Finalized {
                    add_shares: hashkey_powers,
                    mul_shares: self.state.mul_shares,
                },
                ciphertext: self.ciphertext,
            },
            sharings,
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
    pub fn change_ciphertext(
        &mut self,
        new_ciphertext: Vec<u128>,
    ) -> Option<SenderMulPowerSharings> {
        // new ciphertext is not longer than the old one, so we do no need to compute new powers of
        // H
        if new_ciphertext.len() < self.state.add_shares.len() {
            self.ciphertext = new_ciphertext;
            return None;
        }

        let difference = new_ciphertext.len() - self.ciphertext.len();

        // Compute the needed higher powers of H
        let mut higher_powers = vec![];
        for _ in 0..difference {
            let h = self.state.mul_shares[1].inner();
            let last_power = self.state.mul_shares.last().unwrap().inner();

            let new_mul_share = MulShare::new(mul(h, last_power));
            higher_powers.push(new_mul_share);
        }
        self.state.mul_shares.extend_from_slice(&higher_powers);

        let (new_add_shares, new_sharings) = batch_mul_to_add(&higher_powers);
        self.state.add_shares.extend_from_slice(&new_add_shares);

        Some(new_sharings)
    }
}

/// Batch converts multiplicative shares into additive shares and sharings needed for oblivious
/// transfer
fn batch_mul_to_add(mul_shares: &[MulShare]) -> (Vec<AddShare>, SenderMulPowerSharings) {
    let mut sharings: Vec<MaskedPartialValue> = vec![];
    let hashkey_powers: Vec<AddShare> = mul_shares
        .iter()
        .map(|share| {
            let (add_share, sharing) = share.to_additive();
            sharings.push(sharing);
            add_share
        })
        .collect();
    (hashkey_powers, SenderMulPowerSharings(sharings))
}

#[cfg(test)]
impl<T> GhashSender<T> {
    pub fn state(&self) -> &T {
        &self.state
    }
}
