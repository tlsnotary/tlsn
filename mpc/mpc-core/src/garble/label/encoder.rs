use std::collections::HashMap;

use mpc_circuits::Input;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::{Delta, FullInputLabels};

/// Encodes wire labels using the ChaCha algorithm and a global offset (delta).
///
/// Stream ids can be used to partition labels sets.
#[derive(Debug)]
pub struct ChaChaEncoder {
    seed: [u8; 32],
    rng: ChaCha20Rng,
    stream_state: HashMap<u64, u128>,
    delta: Delta,
}

impl ChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Stream id 0 is reserved to generate delta.
        // This way there is only ever 1 delta per seed
        rng.set_stream(0);
        let delta = Delta::random(&mut rng);

        Self {
            seed,
            rng,
            stream_state: HashMap::default(),
            delta,
        }
    }

    /// Returns encoder's rng seed
    pub fn get_seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Returns encoder's global offset
    pub fn get_delta(&self) -> Delta {
        self.delta
    }

    /// Encodes input using the provided stream id
    ///
    /// * `stream_id` - Stream id, must be less than or equal to (u64::MAX >> 1)
    /// * `input` - Circuit input to encode
    pub fn encode(&mut self, stream_id: u64, input: &Input) -> FullInputLabels {
        self.set_stream(stream_id);
        FullInputLabels::generate(&mut self.rng, input.clone(), self.delta)
    }

    /// Returns a mutable reference to the encoder's rng
    ///
    /// * `stream_id` - Stream id, must be less than or equal to (u64::MAX >> 1)
    pub fn get_stream(&mut self, stream_id: u64) -> &mut ChaCha20Rng {
        self.set_stream(stream_id);
        &mut self.rng
    }

    /// Sets the selected stream id, restoring word position if a stream
    /// has been used before.
    ///
    /// * `id` - Stream id, must be less than or equal to (u64::MAX >> 1)
    fn set_stream(&mut self, id: u64) {
        assert!(id <= (u64::MAX >> 1));
        // The reserved bit ensures that we never pull from stream 0 which
        // is reserved to generate delta
        let new_id = (id << 1) + 1;

        let current_id = self.rng.get_stream();

        // noop if stream already set
        if new_id == current_id {
            return;
        }

        // Store word position for current stream
        self.stream_state
            .insert(current_id, self.rng.get_word_pos());

        // Update stream id
        self.rng.set_stream(new_id);

        // Get word position if stored, otherwise default to 0
        let word_pos = self.stream_state.get(&new_id).copied().unwrap_or(0);

        // Update word position
        self.rng.set_word_pos(word_pos);
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use mpc_circuits::{Circuit, WireGroup, ADDER_64};

    use super::*;
    use rstest::*;

    #[fixture]
    fn circ() -> Arc<Circuit> {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    fn test_encoder(circ: Arc<Circuit>) {
        let mut enc = ChaChaEncoder::new([0u8; 32]);

        for input in circ.inputs() {
            enc.encode(input.index() as u64, input);
        }
    }

    #[rstest]
    fn test_encoder_no_duplicates(circ: Arc<Circuit>) {
        let input = circ.input(0).unwrap();

        let mut enc = ChaChaEncoder::new([0u8; 32]);

        // Pull from stream 0
        let a = enc.encode(0, &input);

        // Pull from a different stream
        let c = enc.encode(1, &input);

        // Pull from stream 0 again
        let b = enc.encode(0, &input);

        // Switching back to the same stream should preserve the word position
        assert_ne!(a, b);
        // Different stream ids should produce different labels
        assert_ne!(a, c);
    }
}
