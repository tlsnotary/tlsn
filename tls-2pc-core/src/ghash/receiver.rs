use super::{compute_powers, mul, AddShare, MulShare, ReceiverAddChoice, ReceiverMulPowerChoices};

/// The receiver part for our 2PC Ghash implementation
///
/// `GhashReceiver` will be the receiver side during the oblivious transfer.
pub struct GhashReceiver<T = AddShare> {
    /// Different hashkey representations
    hashkey_repr: T,
    /// The ciphertext for which a 2PC MAC should be constructed
    ciphertext: Vec<u128>,
}

impl GhashReceiver {
    /// Create a new `GhashReceiver`
    ///
    /// * `hashkey` - This is `H`, which is the AES-encrypted 0 block
    /// * `ciphertext` - The AES-encrypted 128-bit blocks
    pub fn new(hashkey: u128, ciphertext: Vec<u128>) -> Self {
        Self {
            hashkey_repr: AddShare::new(hashkey),
            ciphertext,
        }
    }

    /// Return the choices, needed for the oblivious transfer
    ///
    /// The bits in the returned `ReceiverAddChoice` encode the choices for
    /// the OT
    pub fn choices(&self) -> ReceiverAddChoice {
        ReceiverAddChoice(self.hashkey_repr.inner())
    }

    /// Transform `self` into a `GhashReceiver` holding multiplicative shares of powers of `H`
    ///
    /// Converts the additive share into multiplicative shares of powers of `H`.
    ///
    /// * `chosen_inputs` - the result of the oblivious transfer.
    pub fn compute_mul_powers(self, chosen_inputs: [u128; 128]) -> GhashReceiver<Vec<MulShare>> {
        let mul_share = MulShare::from_choice(chosen_inputs);

        let hashkey_powers = compute_powers(mul_share.inner(), self.ciphertext.len())
            .into_iter()
            .map(MulShare::new)
            .collect();

        GhashReceiver {
            hashkey_repr: hashkey_powers,
            ciphertext: self.ciphertext,
        }
    }
}

impl GhashReceiver<Vec<MulShare>> {
    /// Return the choices, needed for the batched oblivious transfer
    ///
    /// The bits in the returned `ReceiverMulPowerChoices` encode the choices for
    /// the OTs
    pub fn choices(&self) -> ReceiverMulPowerChoices {
        ReceiverMulPowerChoices(self.hashkey_repr.iter().map(|x| x.inner()).collect())
    }

    /// Convert all powers of `H` into additive shares
    ///
    /// Converts the multiplicative shares into additive ones.
    ///
    /// * `chosen_inputs` - the results of the batched oblivious transfer.
    pub fn into_add_powers(self, chosen_inputs: Vec<[u128; 128]>) -> GhashReceiver<Vec<AddShare>> {
        let hashkey_powers: Vec<AddShare> = chosen_inputs
            .into_iter()
            .map(AddShare::from_choice)
            .collect();

        GhashReceiver {
            hashkey_repr: hashkey_powers,
            ciphertext: self.ciphertext,
        }
    }
}

impl GhashReceiver<Vec<AddShare>> {
    /// Compute the final MAC
    ///
    /// Computes the 2PC additive share of the MAC of `self.ciphertext`
    pub fn into_mac(self) -> u128 {
        self.hashkey_repr
            .into_iter()
            .skip(1)
            .rev()
            .enumerate()
            .fold(0, |acc, (k, hashkey_power)| {
                acc ^ mul(hashkey_power.inner(), self.ciphertext[k])
            })
    }
}

#[cfg(test)]
impl<T: Clone> GhashReceiver<T> {
    pub fn hashkey_repr(&self) -> T {
        self.hashkey_repr.clone()
    }
}
