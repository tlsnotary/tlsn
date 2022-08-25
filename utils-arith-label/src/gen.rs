use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

// The psuedorandom generator we use for all label and randomness generation
type Prg = ChaCha20Rng;
// The seed type of `Prg`
type Seed = <Prg as SeedableRng>::Seed;

/// A seed used by the Notary to generate random arithmetic labels
#[derive(Copy, Clone, SerdeSerialize, SerdeDeserialize)]
pub struct ArithLabelSeed(Seed);

impl ArithLabelSeed {
    /// Generates a random seed for arithmetic label generation
    pub fn new<R: CryptoRng + RngCore>(mut rng: R) -> Self {
        let mut seed = Seed::default();
        rng.fill_bytes(&mut seed);

        ArithLabelSeed(seed)
    }
}
