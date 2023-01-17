use std::collections::HashMap;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

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
    delta: u128,
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
        let delta: u128 = rng.gen();

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

    /// Returns next 8 label pairs
    ///
    /// * `stream_id` - Stream id which can be used to partition label sets
    /// * `input` - Circuit input to encode
    pub fn labels_for_next_byte(&mut self, stream_id: u32) -> Vec<[u128; 2]> {
        self.set_stream(stream_id);
        (0..8)
            .map(|_| {
                //test
                let zero_label: u128 = self.rng.gen();
                let one_label = zero_label ^ self.delta;
                [zero_label, one_label]
            })
            .collect()
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
            .insert(current_id, self.rng.get_word_pos());

        // Update stream id
        self.rng.set_stream(new_id);

        // Get word position if stored, otherwise default to 0
        let word_pos = self.stream_state.get(&new_id).copied().unwrap_or(0);

        // Update word position
        self.rng.set_word_pos(word_pos);
    }
}
