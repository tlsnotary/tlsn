use super::{compute_powers, mul, AddShare, MaskedPartialValue, MulShare};

pub struct GhashSender<T = AddShare> {
    hashkey_repr: T,
    ciphertext: Vec<u128>,
}

impl GhashSender {
    pub fn new(hashkey: u128, ciphertext: Vec<u128>) -> Self {
        Self {
            hashkey_repr: AddShare::new(hashkey),
            ciphertext,
        }
    }

    pub fn share_partial_values(self) -> (GhashSender<Vec<MulShare>>, MaskedPartialValue) {
        let (mul_share, sharing) = self.hashkey_repr.to_multiplicative();

        let hashkey_powers = compute_powers(mul_share.inner(), self.ciphertext.len())
            .into_iter()
            .map(|power| MulShare::new(power))
            .collect();
        (
            GhashSender {
                hashkey_repr: hashkey_powers,
                ciphertext: self.ciphertext,
            },
            sharing,
        )
    }
}

impl GhashSender<Vec<MulShare>> {
    pub fn back_to_additive(self) -> (GhashSender<Vec<AddShare>>, Vec<MaskedPartialValue>) {
        let mut sharings: Vec<MaskedPartialValue> = vec![];
        let hashkey_powers: Vec<AddShare> = self
            .hashkey_repr
            .into_iter()
            .map(|share| {
                let (add_share, sharing) = share.to_additive();
                sharings.push(sharing);
                add_share
            })
            .collect();
        (
            GhashSender {
                hashkey_repr: hashkey_powers,
                ciphertext: self.ciphertext,
            },
            sharings,
        )
    }
}

impl GhashSender<Vec<AddShare>> {
    pub fn finalize(self) -> u128 {
        self.hashkey_repr
            .into_iter()
            .enumerate()
            .fold(0, |acc, (k, hashkey_power)| {
                acc ^ mul(hashkey_power.inner(), self.ciphertext[k])
            })
    }
}
