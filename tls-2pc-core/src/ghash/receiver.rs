use super::{
    compute_missing_mul_shares, compute_new_add_shares, mul, AddShare, Finalized, GhashError, Init,
    Intermediate, MulShare, ReceiverAddChoice, ReceiverMulPowerChoices,
};

/// The receiver part for our 2PC Ghash implementation
///
/// `GhashReceiver` will be the receiver side during the oblivious transfer.
pub struct GhashReceiver<T = Init> {
    /// Inner state
    state: T,
    /// This determines how many powers of the hashkey we will compute.
    highest_hashkey_power: usize,
}

impl GhashReceiver {
    /// Create a new `GhashReceiver`
    ///
    /// * `hashkey` - This is an additive sharing of `H`, which is the AES-encrypted 0 block
    /// * `highest_hashkey_power` - Determines the highest power of the hashkey to be computed
    pub fn new(hashkey: u128, highest_hashkey_power: usize) -> Result<Self, GhashError> {
        if highest_hashkey_power == 0 {
            return Err(GhashError::ZeroHashkeyPower);
        }

        let receiver = Self {
            state: Init {
                add_share: AddShare::new(hashkey),
            },
            highest_hashkey_power,
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
        let mut hashkey_powers = vec![mul_share.inner()];

        compute_missing_mul_shares(&mut hashkey_powers, self.highest_hashkey_power);
        let hashkey_powers = hashkey_powers.into_iter().map(MulShare::new).collect();

        GhashReceiver {
            state: Intermediate {
                odd_mul_shares: hashkey_powers,
                cached_add_shares: vec![],
            },
            highest_hashkey_power: self.highest_hashkey_power,
        }
    }
}

impl GhashReceiver<Intermediate> {
    /// Return the choices, needed for the batched oblivious transfer
    ///
    /// The bits in the returned `ReceiverMulPowerChoices` encode the choices for
    /// the OTs
    pub fn choices(&self) -> Option<ReceiverMulPowerChoices> {
        // If we already have some cached additive sharings, we do not need to do an OT for them.
        // So we compute an offset to ignore them. We divide by 2 because `cached_add_shares`
        // contain even and odd powers, while mul_shares only have odd powers.
        let offset = self.state.cached_add_shares.len() / 2;
        if offset == self.state.odd_mul_shares.len() {
            return None;
        }

        Some(ReceiverMulPowerChoices(
            self.state.odd_mul_shares[offset..]
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
        // If we get new input, we build the additive shares and add them to our
        // `cached_add_shares`
        let additive_odd_shares: Vec<AddShare> = if let Some(inputs) = chosen_inputs {
            inputs.into_iter().map(AddShare::from_choice).collect()
        } else {
            vec![]
        };

        compute_new_add_shares(&additive_odd_shares, &mut self.state.cached_add_shares);

        GhashReceiver {
            state: Finalized {
                add_shares: self.state.cached_add_shares,
                odd_mul_shares: self.state.odd_mul_shares,
            },
            highest_hashkey_power: self.highest_hashkey_power,
        }
    }
}

impl GhashReceiver<Finalized> {
    /// Generate the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `ciphertext`
    pub fn generate_mac(&self, ciphertext: &[u128]) -> Result<u128, GhashError> {
        if ciphertext.len() > self.highest_hashkey_power {
            return Err(GhashError::InvalidCiphertextLength);
        }
        let offset = self.state.add_shares.len() - ciphertext.len();
        Ok(ciphertext
            .iter()
            .zip(self.state.add_shares.iter().rev().skip(offset))
            .fold(0, |acc, (block, share)| acc ^ mul(*block, share.inner())))
    }

    /// Change the maximum hashkey power
    ///
    /// If we want to create a MAC for a new ciphertext, which is longer than the old one, we need
    /// to compute the missing powers of `H`, using batched OTs.
    pub fn change_max_hashkey(
        self,
        new_highest_hashkey_power: usize,
    ) -> GhashReceiver<Intermediate> {
        if new_highest_hashkey_power <= self.highest_hashkey_power {
            return GhashReceiver {
                state: Intermediate {
                    odd_mul_shares: self.state.odd_mul_shares,
                    cached_add_shares: self.state.add_shares,
                },
                highest_hashkey_power: new_highest_hashkey_power,
            };
        }

        let mut hashkey_powers = self
            .state
            .odd_mul_shares
            .iter()
            .map(MulShare::inner)
            .collect();
        compute_missing_mul_shares(&mut hashkey_powers, new_highest_hashkey_power);

        GhashReceiver {
            state: Intermediate {
                odd_mul_shares: hashkey_powers.iter().map(|x| MulShare::new(*x)).collect(),
                cached_add_shares: self.state.add_shares,
            },
            highest_hashkey_power: new_highest_hashkey_power,
        }
    }
}

#[cfg(test)]
impl<T> GhashReceiver<T> {
    pub fn state(&self) -> &T {
        &self.state
    }
}
