use ark_secp256r1::fq::Fq;

use super::Field;
use ark_ff::Field as ArkField;

pub type P256 = Fq;

impl Field for P256 {
    const BIT_SIZE: usize = 256;

    fn inverse(self) -> Self {
        <Self as ArkField>::inverse(&self).expect("Unable to invert field element")
    }
}
