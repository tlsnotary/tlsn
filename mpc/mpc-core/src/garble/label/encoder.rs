use std::collections::HashMap;

use mpc_circuits::{Input, WireGroup};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::Block;

use super::{Delta, FullEncodedInput, FullLabels};

const DELTA_STREAM_ID: u64 = u64::MAX;
const PADDING_STREAM_ID: u64 = u64::MAX - 1;

pub trait EncoderRng: RngCore + CryptoRng {}

impl<T> EncoderRng for T where T: RngCore + CryptoRng {}

/// This trait is used to encode wire labels using a global offset (delta).
///
/// Implementations of this trait *must* preserve the state of each stream between
/// calls to `encode`. This is required to ensure that duplicate labels are never
/// generated.
pub trait Encoder: Send + Sync {
    /// Returns encoder's rng seed
    fn get_seed(&self) -> Vec<u8>;

    /// Returns encoder's global offset
    fn get_delta(&self) -> Delta;

    /// Encodes input using the provided stream id
    ///
    /// * `stream_id` - Stream id
    /// * `input` - Circuit input to encode
    /// * `reversed` - If true, the encoding is reversed
    fn encode(&mut self, stream_id: u32, input: &Input, reversed: bool) -> FullEncodedInput;

    /// Encodes input using the provided stream id, generating the right-most
    /// `pad` bits as padding labels.
    ///
    /// This is useful for ensuring that a stream of labels is packed when
    /// a plaintext input contains padding bits.
    ///
    /// Padding labels are generated using a reserved padding stream id to ensure
    /// they are not used for any other purpose.
    ///
    /// Panics if the input length is less than the number of padding labels.
    ///
    /// * `stream_id` - Stream id
    /// * `input` - Circuit input to encode
    /// * `pad` - Number of padding labels to generate
    /// * `reversed` - If true, the encoding is reversed
    fn encode_padded(
        &mut self,
        stream_id: u32,
        input: &Input,
        pad: usize,
        reversed: bool,
    ) -> FullEncodedInput;

    /// Returns a mutable reference to the encoder's rng stream
    ///
    /// * `stream_id` - Stream id
    fn get_stream(&mut self, stream_id: u32) -> &mut dyn EncoderRng;
}

/// Encodes wires into labels using the ChaCha algorithm.
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

        // Stream id u64::MAX is reserved to generate delta.
        // This way there is only ever 1 delta per seed
        rng.set_stream(DELTA_STREAM_ID);
        let delta = Delta::random(&mut rng);

        Self {
            seed,
            rng,
            stream_state: HashMap::default(),
            delta,
        }
    }

    /// Sets the selected stream id, restoring word position if a stream
    /// has been used before.
    ///
    /// * `id` - Stream id
    fn set_stream(&mut self, id: u64) {
        let current_id = self.rng.get_stream();

        // noop if stream already set
        if id == current_id {
            return;
        }

        // Store word position for current stream
        self.stream_state
            .insert(current_id, self.rng.get_word_pos());

        // Update stream id
        self.rng.set_stream(id);

        // Get word position if stored, otherwise default to 0
        let word_pos = self.stream_state.get(&id).copied().unwrap_or(0);

        // Update word position
        self.rng.set_word_pos(word_pos);
    }
}

impl Encoder for ChaChaEncoder {
    /// Returns encoder's rng seed
    fn get_seed(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Returns encoder's global offset
    fn get_delta(&self) -> Delta {
        self.delta
    }

    /// Encodes input using the provided stream id
    ///
    /// * `stream_id` - Stream id
    /// * `input` - Circuit input to encode
    /// * `reversed` - If true, the encoding is reversed
    fn encode(&mut self, stream_id: u32, input: &Input, reversed: bool) -> FullEncodedInput {
        self.set_stream(stream_id as u64);

        let mut blocks = Block::random_vec(&mut self.rng, input.len());

        if reversed {
            blocks.reverse();
        }

        let labels = FullLabels::from_blocks(blocks, self.delta);

        FullEncodedInput::from_labels(input.clone(), labels)
            .expect("Label length should match input length")
    }

    /// Encodes input using the provided stream id, generating the right-most
    /// `pad` bits as padding labels.
    ///
    /// This is useful for ensuring that a stream of labels is packed when
    /// a plaintext input contains padding bits.
    ///
    /// Padding labels are generated using a reserved padding stream id to ensure
    /// they are not used for any other purpose.
    ///
    /// Panics if the input length is less than the number of padding labels.
    ///
    /// * `stream_id` - Stream id
    /// * `input` - Circuit input to encode
    /// * `pad` - Number of padding labels to generate
    /// * `reversed` - If true, the encoding is reversed
    fn encode_padded(
        &mut self,
        stream_id: u32,
        input: &Input,
        pad: usize,
        reversed: bool,
    ) -> FullEncodedInput {
        assert!(input.len() >= pad);

        self.set_stream(stream_id as u64);
        let left = Block::random_vec(&mut self.rng, input.len() - pad);

        self.set_stream(PADDING_STREAM_ID);
        let right = Block::random_vec(&mut self.rng, pad);

        let labels = left.into_iter().chain(right.into_iter());

        let labels = if reversed {
            labels.rev().collect()
        } else {
            labels.collect()
        };

        let labels = FullLabels::from_blocks(labels, self.delta);

        FullEncodedInput::from_labels(input.clone(), labels)
            .expect("Label length should match input length")
    }

    /// Returns a mutable reference to the encoder's rng stream
    ///
    /// * `stream_id` - Stream id
    fn get_stream(&mut self, stream_id: u32) -> &mut dyn EncoderRng {
        self.set_stream(stream_id as u64);
        &mut self.rng
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
            enc.encode(input.index() as u32, input, false);
        }
    }

    #[rstest]
    fn test_encoder_reversed(circ: Arc<Circuit>) {
        let mut enc = ChaChaEncoder::new([0u8; 32]);

        let input = circ.input(0).unwrap();

        let encoded_0 = enc.encode_padded(0, &input, 32, false);

        let mut enc = ChaChaEncoder::new([0u8; 32]);

        let encoded_1 = enc.encode_padded(0, &input, 32, true);

        let encoded_0 = encoded_0.iter().collect::<Vec<_>>();
        let mut encoded_1 = encoded_1.iter().collect::<Vec<_>>();

        encoded_1.reverse();

        assert_eq!(encoded_0, encoded_1)
    }

    #[rstest]
    fn test_encoder_padded(circ: Arc<Circuit>) {
        let mut enc = ChaChaEncoder::new([0u8; 32]);

        let input = circ.input(0).unwrap();

        let encoded_0 = enc.encode_padded(0, &input, 32, false);
        let encoded_1 = enc.encode_padded(0, &input, 32, false);

        let mut enc = ChaChaEncoder::new([0u8; 32]);
        let encoded_no_pad = enc.encode(0, &input, false);

        let labels_0 = encoded_0.iter().collect::<Vec<_>>();
        let labels_1 = encoded_1.iter().collect::<Vec<_>>();

        let labels_no_pad = encoded_no_pad.iter().collect::<Vec<_>>();

        assert_eq!(labels_0[..32], labels_no_pad[..32]);
        assert_eq!(labels_1[..32], labels_no_pad[32..]);
    }

    #[rstest]
    fn test_encoder_mut_ref(circ: Arc<Circuit>) {
        let mut enc = ChaChaEncoder::new([0u8; 32]);
        let delta = enc.get_delta();
        let mut_ref = enc.get_stream(0);

        _ = FullEncodedInput::generate(mut_ref, circ.input(0).unwrap().clone(), delta);
    }

    #[rstest]
    fn test_encoder_no_duplicates(circ: Arc<Circuit>) {
        let input = circ.input(0).unwrap();

        let mut enc = ChaChaEncoder::new([0u8; 32]);

        // Pull from stream 0
        let a = enc.encode(0, &input, false);

        // Pull from a different stream
        let c = enc.encode(1, &input, false);

        // Pull from stream 0 again
        let b = enc.encode(0, &input, false);

        // Switching back to the same stream should preserve the word position
        assert_ne!(a, b);
        // Different stream ids should produce different labels
        assert_ne!(a, c);
    }
}
