use super::{
    compute_missing_mul_shares, compute_new_add_shares, mul, AddShare, Finalized, GhashError, Init,
    Intermediate, MulShare, ReceiverAddChoice, ReceiverAddShares, ReceiverMulChoices,
    ReceiverMulShare,
};

/// The receiver part for our 2PC Ghash implementation
///
/// `GhashReceiver` will be the receiver side during the oblivious transfer.
pub struct GhashReceiver<T = Init> {
    /// Inner state
    state: T,
    /// Maximum number of message blocks we want to authenticate
    max_message_length: usize,
}

impl GhashReceiver {
    /// Create a new `GhashReceiver`
    ///
    /// * `hashkey` - This is an additive sharing of `H`, which is the AES-encrypted 0 block
    /// * `max_message_length` - Determines the maximum number of 128-bit message blocks we want to
    ///                          authenticate
    pub fn new(hashkey: u128, max_message_length: usize) -> Result<Self, GhashError> {
        if max_message_length == 0 {
            return Err(GhashError::ZeroHashkeyPower);
        }

        let receiver = Self {
            state: Init {
                add_share: AddShare::new(hashkey),
            },
            max_message_length,
        };
        Ok(receiver)
    }

    /// Return the receiver's choices, needed for the oblivious transfer
    ///
    /// The bits in the returned `ReceiverAddChoice` encode the choices for
    /// the OT
    pub fn choices(&self) -> ReceiverAddChoice {
        ReceiverAddChoice(self.state.add_share.inner())
    }

    /// Transform `self` into a `GhashReceiver`, holding multiplicative shares of powers of `H`
    ///
    /// Converts the additive share into multiplicative shares of powers of `H`
    ///
    /// * `chosen_inputs` - the output of the oblivious transfer
    pub fn compute_mul_powers(
        self,
        chosen_inputs: ReceiverMulShare,
    ) -> GhashReceiver<Intermediate> {
        let mul_share = MulShare::from_choice(&chosen_inputs.0);
        let mut hashkey_powers = vec![mul_share.inner()];

        compute_missing_mul_shares(&mut hashkey_powers, self.max_message_length);
        let hashkey_powers = hashkey_powers.into_iter().map(MulShare::new).collect();

        GhashReceiver {
            state: Intermediate {
                odd_mul_shares: hashkey_powers,
                cached_add_shares: vec![],
            },
            max_message_length: self.max_message_length,
        }
    }
}

impl GhashReceiver<Intermediate> {
    /// Return the choices, needed for the batched oblivious transfer
    ///
    /// The bits in the returned `ReceiverMulChoices` encode the choices for
    /// the OTs
    pub fn choices(&self) -> Option<ReceiverMulChoices> {
        // If we already have some cached additive sharings, we do not need to do an OT for them.
        // So we compute an offset to ignore them. We divide by 2 because
        // `self.state.cached_add_shares` contain even and odd powers, while
        // `self.state.mul_shares` only have odd powers.
        let offset = self.state.cached_add_shares.len() / 2;
        if offset == self.state.odd_mul_shares.len() {
            return None;
        }

        Some(ReceiverMulChoices(
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
        chosen_inputs: Option<ReceiverAddShares>,
    ) -> GhashReceiver<Finalized> {
        // If we get new input, we build the additive shares and add them to our
        // `cached_add_shares`
        let additive_odd_shares: Vec<AddShare> = if let Some(inputs) = chosen_inputs {
            inputs.0.chunks(128).map(AddShare::from_choice).collect()
        } else {
            vec![]
        };

        compute_new_add_shares(&additive_odd_shares, &mut self.state.cached_add_shares);

        GhashReceiver {
            state: Finalized {
                add_shares: self.state.cached_add_shares,
                odd_mul_shares: self.state.odd_mul_shares,
            },
            max_message_length: self.max_message_length,
        }
    }
}

impl GhashReceiver<Finalized> {
    /// Generate the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `message`
    pub fn generate_mac(&self, message: &[u128]) -> Result<u128, GhashError> {
        if message.len() > self.max_message_length {
            return Err(GhashError::InvalidMessageLength);
        }
        let offset = self.state.add_shares.len() - message.len();
        Ok(message
            .iter()
            .zip(self.state.add_shares.iter().rev().skip(offset))
            .fold(0, |acc, (block, share)| acc ^ mul(*block, share.inner())))
    }

    /// Change the maximum hashkey power
    ///
    /// If we want to create a MAC for a new message, which is longer than the old one, we need
    /// to compute the missing powers of `H`, using batched OTs.
    pub fn change_max_hashkey(
        self,
        new_highest_hashkey_power: usize,
    ) -> GhashReceiver<Intermediate> {
        if new_highest_hashkey_power <= self.max_message_length {
            return GhashReceiver {
                state: Intermediate {
                    odd_mul_shares: self.state.odd_mul_shares,
                    cached_add_shares: self.state.add_shares,
                },
                max_message_length: new_highest_hashkey_power,
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
            max_message_length: new_highest_hashkey_power,
        }
    }
}

#[cfg(test)]
impl<T> GhashReceiver<T> {
    pub fn state(&self) -> &T {
        &self.state
    }
}
