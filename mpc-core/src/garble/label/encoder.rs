use std::collections::HashMap;

use mpc_circuits::Input;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::{Delta, FullInputLabels};

/// Encodes wire labels using the ChaCha algorithm and a global offset (delta).
///
/// An encoder instance is configured using a domain id. Domain ids can be used in combination
/// with stream ids to partition label sets.
#[derive(Debug)]
pub struct ChaChaEncoder {
    seed: [u8; 32],
    domain: u32,
    rng: ChaCha20Rng,
    stream_state: HashMap<u64, u128>,
    delta: Delta,
}

impl ChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    /// * `domain` - Domain id
    ///
    /// Domain id must be less than 2^31
    pub fn new(seed: [u8; 32], domain: u32) -> Self {
        assert!(domain <= u32::MAX >> 1);

        let mut rng = ChaCha20Rng::from_seed(seed);

        // Stream id 0 is reserved to generate delta.
        // This way there is only ever 1 delta per seed
        rng.set_stream(0);
        let delta = Delta::random(&mut rng);

        Self {
            seed,
            domain,
            rng,
            stream_state: HashMap::default(),
            delta,
        }
    }

    /// Returns encoder's rng seed
    pub fn get_seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Encodes input using the provided stream id
    ///
    /// * `stream_id` - Stream id which can be used to partition label sets
    /// * `input` - Circuit input to encode
    pub fn encode(&mut self, stream_id: u32, input: &Input) -> FullInputLabels {
        self.set_stream(stream_id);
        FullInputLabels::generate(&mut self.rng, input.clone(), self.delta)
    }

    /// Sets the selected stream id, restoring word position if a stream
    /// has been used before.
    fn set_stream(&mut self, id: u32) {
        //           MSB -> LSB
        //   31 bits   32 bits   1 bit
        //   [domain]   [id]   [reserved]
        // The reserved bit ensures that we never pull from stream 0 which
        // is reserved to generate delta
        let new_id = ((self.domain as u64) << 33) + ((id as u64) << 1) + 1;

        let current_id = self.rng.get_stream();

        // noop if stream already set
        if new_id == current_id {
            return;
        }

        // Store word position for current stream
        self.stream_state
            .entry(current_id)
            .or_insert(self.rng.get_word_pos());

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
    use mpc_circuits::{Circuit, WireGroup, ADDER_64};

    use super::*;
    use rstest::*;

    #[fixture]
    fn circ() -> Circuit {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    fn test_encoder(circ: Circuit) {
        let mut enc = ChaChaEncoder::new([0u8; 32], 0);

        circ.inputs()
            .iter()
            .for_each(|input| _ = enc.encode(input.id() as u32, input))
    }
}
