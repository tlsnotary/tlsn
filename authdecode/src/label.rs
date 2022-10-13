use super::utils::bits_to_bigint;
use num::BigUint;
use rand::RngCore;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// The PRG for generating arithmetic labels.
type Prg = ChaCha20Rng;
/// The seed from which to generate the arithmetic labels.
pub type Seed = [u8; 32];
// The arithmetic label.
type Label = BigUint;
/// A pair of labels: the first one encodes the value 0, the second one encodes
/// the value 1.
pub type LabelPair = [Label; 2];

pub struct LabelGenerator {}

impl LabelGenerator {
    /// Generates a seed and then generates `count` arithmetic label pairs
    /// of bitsize `label_size` from that seed. Returns the labels and the seed.
    pub fn generate(count: usize, label_size: usize) -> (Vec<LabelPair>, Seed) {
        let seed = thread_rng().gen::<Seed>();
        let pairs = LabelGenerator::generate_from_seed(count, label_size, seed);
        (pairs, seed)
    }

    // Generates `count` arithmetic label pairs of bitsize `label_size` from a
    // seed and returns the labels.
    pub fn generate_from_seed(count: usize, label_size: usize, seed: Seed) -> Vec<LabelPair> {
        let prg = Prg::from_seed(seed);
        LabelGenerator::generate_from_prg(count, label_size, Box::new(prg))
    }

    /// Generates `count` arithmetic label pairs of bitsize `label_size` using a PRG.
    /// Returns the generated label pairs.
    fn generate_from_prg(
        count: usize,
        label_size: usize,
        mut prg: Box<dyn RngCore>,
    ) -> Vec<LabelPair> {
        (0..count)
            .map(|_| {
                // To keep the handling simple, we want to avoid a negative delta, that's why
                // W_0 and delta must be (label_size - 1)-bit values and W_1 will be
                // set to W_0 + delta
                let zero_label = bits_to_bigint(
                    &core::iter::repeat_with(|| prg.gen::<bool>())
                        .take(label_size - 1)
                        .collect::<Vec<_>>(),
                );

                let delta = bits_to_bigint(
                    &core::iter::repeat_with(|| prg.gen::<bool>())
                        .take(label_size - 1)
                        .collect::<Vec<_>>(),
                );

                let one_label = zero_label.clone() + delta;
                [zero_label, one_label]
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::LabelGenerator;
    use num::BigUint;
    use rand::rngs::mock::StepRng;

    #[test]
    fn test_label_generator() {
        // PRG which always returns bit 1
        let prg = StepRng::new(u64::MAX, 0);

        // zero_label and delta should be 511 (bit 1 repeated 9 times), one_label
        // should be 511+511=1022
        let result = LabelGenerator::generate_from_prg(10, 10, Box::new(prg));
        let expected = (0..10)
            .map(|_| [BigUint::from(511u128), BigUint::from(1022u128)])
            .collect::<Vec<_>>();

        assert_eq!(expected, result);
    }
}
