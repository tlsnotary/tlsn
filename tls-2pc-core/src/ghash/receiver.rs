use super::{
    compute_higher_powers, mul, AddShare, Finalized, GhashError, Init, Intermediate, MulShare,
    ReceiverAddChoice, ReceiverMulPowerChoices,
};

/// The receiver part for our 2PC Ghash implementation
///
/// `GhashReceiver` will be the receiver side during the oblivious transfer.
pub struct GhashReceiver<T = Init> {
    /// Different hashkey representations
    state: T,
    /// The ciphertext for which a 2PC MAC should be constructed
    ciphertext: Vec<u128>,
}

impl GhashReceiver {
    /// Create a new `GhashReceiver`
    ///
    /// * `hashkey` - This is `H`, which is the AES-encrypted 0 block
    /// * `ciphertext` - The AES-encrypted 128-bit blocks
    pub fn new(hashkey: u128, ciphertext: Vec<u128>) -> Result<Self, GhashError> {
        if ciphertext.is_empty() {
            return Err(GhashError::NoCipherText);
        }

        let receiver = Self {
            state: Init {
                add_share: AddShare::new(hashkey),
            },
            ciphertext,
        };
        Ok(receiver)
    }

    /// Return the choices, needed for the oblivious transfer
    ///
    /// The bits in the returned `ReceiverAddChoice` encode the choices for
    /// the OT
    pub fn choices(&self) -> ReceiverAddChoice {
        ReceiverAddChoice(self.state.add_share.inner())
    }

    /// Transform `self` into a `GhashReceiver` holding multiplicative shares of powers of `H`
    ///
    /// Converts the additive share into multiplicative shares of powers of `H`.
    ///
    /// * `chosen_inputs` - the result of the oblivious transfer.
    pub fn compute_mul_powers(self, chosen_inputs: [u128; 128]) -> GhashReceiver<Intermediate> {
        let mul_share = MulShare::from_choice(chosen_inputs);
        let mut hashkey_powers = vec![1_u128 << 127, mul_share.inner()];

        compute_higher_powers(&mut hashkey_powers, self.ciphertext.len() - 1);
        let hashkey_powers = hashkey_powers.into_iter().map(MulShare::new).collect();

        GhashReceiver {
            state: Intermediate {
                mul_shares: hashkey_powers,
                cached_add_shares: vec![],
            },
            ciphertext: self.ciphertext,
        }
    }
}

impl GhashReceiver<Intermediate> {
    /// Return the choices, needed for the batched oblivious transfer
    ///
    /// The bits in the returned `ReceiverMulPowerChoices` encode the choices for
    /// the OTs
    pub fn choices(&self) -> Option<ReceiverMulPowerChoices> {
        let offset = self.state.cached_add_shares.len();
        if offset == self.state.mul_shares.len() {
            return None;
        }

        Some(ReceiverMulPowerChoices(
            self.state.mul_shares[offset..]
                .iter()
                .map(|x| x.inner())
                .collect(),
        ))
    }

    /// Convert all powers of `H` into additive shares
    ///
    /// Converts the multiplicative shares into additive ones.
    ///
    /// * `chosen_inputs` - the results of the batched oblivious transfer.
    pub fn into_add_powers(
        mut self,
        chosen_inputs: Option<Vec<[u128; 128]>>,
    ) -> GhashReceiver<Finalized> {
        let hashkey_powers: Vec<AddShare> = if let Some(inputs) = chosen_inputs {
            inputs.into_iter().map(AddShare::from_choice).collect()
        } else {
            vec![]
        };

        self.state
            .cached_add_shares
            .extend_from_slice(&hashkey_powers);

        GhashReceiver {
            state: Finalized {
                add_shares: self.state.cached_add_shares,
                mul_shares: self.state.mul_shares,
            },
            ciphertext: self.ciphertext,
        }
    }
}

impl GhashReceiver<Finalized> {
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
    pub fn change_ciphertext(self, new_ciphertext: Vec<u128>) -> GhashReceiver<Intermediate> {
        // Check if we need to compute new powers of `H`
        let difference = new_ciphertext.len() as i32 - self.state.add_shares.len() as i32 + 1;

        let mut hashkey_powers = self.state.mul_shares.iter().map(MulShare::inner).collect();
        if difference > 0 {
            compute_higher_powers(&mut hashkey_powers, difference as usize);
        }

        GhashReceiver {
            state: Intermediate {
                mul_shares: hashkey_powers.iter().map(|x| MulShare::new(*x)).collect(),
                cached_add_shares: self.state.add_shares,
            },
            ciphertext: new_ciphertext,
        }
    }
}

#[cfg(test)]
impl<T> GhashReceiver<T> {
    pub fn state(&self) -> &T {
        &self.state
    }

    pub fn ciphertext(&self) -> &Vec<u128> {
        &self.ciphertext
    }
}
