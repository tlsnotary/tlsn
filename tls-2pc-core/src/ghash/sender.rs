use super::{
    compute_missing_mul_shares, compute_new_add_shares, mul, AddShare, Finalized, GhashError, Init,
    Intermediate, MulShare, SenderAddSharing, SenderMulSharing,
};

/// The sender part for our 2PC Ghash implementation
///
/// `GhashSender` will be the sender side during the oblivious transfer.
pub struct GhashSender<T = Init> {
    /// Inner state
    state: T,
    /// Maximum number of message blocks we want to authenticate
    max_message_length: usize,
}

impl GhashSender {
    /// Create a new `GhashSender`
    ///
    /// * `hashkey` - This is an additive sharing of `H`, which is the AES-encrypted 0 block
    /// * `max_message_length` - Determines the maximum number of 128-bit message blocks we want to
    ///                          authenticate
    pub fn new(hashkey: u128, max_message_length: usize) -> Result<Self, GhashError> {
        if max_message_length == 0 {
            return Err(GhashError::ZeroHashkeyPower);
        }

        let sender = Self {
            state: Init {
                add_share: AddShare::new(hashkey),
            },
            max_message_length,
        };
        Ok(sender)
    }

    /// Transform `self` into a `GhashSender`, holding multiplicative shares of powers of `H`
    ///
    /// Converts the additive share into multiplicative shares of powers of `H`; also returns
    /// `SenderAddSharing`, which is needed for the receiver side
    pub fn compute_mul_powers(self) -> (GhashSender<Intermediate>, SenderAddSharing) {
        let (mul_share, sharing) = self.state.add_share.to_multiplicative();
        let mut hashkey_powers = vec![mul_share.inner()];

        compute_missing_mul_shares(&mut hashkey_powers, self.max_message_length);
        let hashkey_powers = hashkey_powers.into_iter().map(MulShare::new).collect();

        (
            GhashSender {
                state: Intermediate {
                    odd_mul_shares: hashkey_powers,
                    cached_add_shares: vec![],
                },
                max_message_length: self.max_message_length,
            },
            SenderAddSharing {
                choice_zero: sharing.0,
                choice_one: sharing.1,
            },
        )
    }
}

impl GhashSender<Intermediate> {
    /// Convert all powers of `H` into additive shares
    ///
    /// Converts the multiplicative shares into additive ones; also returns
    /// `SenderMulSharing`, which is needed for the receiver side
    pub fn into_add_powers(mut self) -> (GhashSender<Finalized>, SenderMulSharing) {
        // If we already have some cached additive sharings, we do not need to do an OT for them.
        // So we compute an offset to ignore them. We divide by 2 because
        // `self.state.cached_add_shares` contain even and odd powers, while
        // `self.state.odd_mul_shares` only have odd powers.
        let offset = self.state.cached_add_shares.len() / 2;

        let mut sender_mul_sharing_zero: Vec<Vec<u128>> = vec![];
        let mut sender_mul_sharing_one: Vec<Vec<u128>> = vec![];
        let additive_odd_shares: Vec<AddShare> = self.state.odd_mul_shares[offset..]
            .iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                sender_mul_sharing_zero.push(sharing.0);
                sender_mul_sharing_one.push(sharing.1);
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
                max_message_length: self.max_message_length,
            },
            SenderMulSharing {
                choice_zero: sender_mul_sharing_zero,
                choice_one: sender_mul_sharing_one,
            },
        )
    }
}

impl GhashSender<Finalized> {
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
    ) -> (GhashSender<Finalized>, Option<SenderMulSharing>) {
        if new_highest_hashkey_power <= self.max_message_length {
            return (self, None);
        }

        let mut hashkey_powers = self
            .state
            .odd_mul_shares
            .iter()
            .map(MulShare::inner)
            .collect();
        compute_missing_mul_shares(&mut hashkey_powers, new_highest_hashkey_power);

        let sender = GhashSender {
            state: Intermediate {
                odd_mul_shares: hashkey_powers.iter().map(|x| MulShare::new(*x)).collect(),
                cached_add_shares: self.state.add_shares,
            },
            max_message_length: new_highest_hashkey_power,
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
