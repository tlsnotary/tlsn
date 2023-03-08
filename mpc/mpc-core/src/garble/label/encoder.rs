use std::collections::HashMap;

use mpc_circuits::{BitOrder, ValueType, WireGroup};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::Block;

use super::{Delta, FullLabels};

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

    /// Returns the encoder's bit order
    fn get_bit_order(&self) -> BitOrder;

    /// Encodes wire group using the provided stream id
    ///
    /// * `stream_id` - Stream id
    /// * `group` - Wire group to encode
    fn encode<G: WireGroup>(&mut self, stream_id: u32, group: &G) -> FullLabels;

    /// Encodes wire group using the provided stream id, generating the least-significant
    /// `pad` bits as padding labels.
    ///
    /// This is useful for ensuring that a stream of labels is packed when
    /// a wire group contains padding bits.
    ///
    /// Padding labels are generated using a reserved padding stream id to ensure
    /// they are not used for any other purpose.
    ///
    /// Panics if the group length is less than the number of padding labels.
    ///
    /// * `stream_id` - Stream id
    /// * `group` - Wire group to encode
    /// * `pad` - Number of padding labels to generate
    fn encode_padded<G: WireGroup>(&mut self, stream_id: u32, group: &G, pad: usize) -> FullLabels;

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
    bit_order: BitOrder,
}

impl ChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    /// * `bit_order` - Bit order of labels generated from stream
    pub fn new(seed: [u8; 32], bit_order: BitOrder) -> Self {
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
            bit_order,
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
    fn get_seed(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    fn get_delta(&self) -> Delta {
        self.delta
    }

    fn get_bit_order(&self) -> BitOrder {
        self.bit_order
    }

    fn encode<G: WireGroup>(&mut self, stream_id: u32, group: &G) -> FullLabels {
        self.set_stream(stream_id as u64);

        let mut blocks = Block::random_vec(&mut self.rng, group.len());

        // Reverse blocks if bit order is reversed
        if self.bit_order != group.bit_order() {
            match group.value_type() {
                // If value type is bytes, we need to reverse each byte
                ValueType::Bytes => {
                    blocks.chunks_exact_mut(8).for_each(|byte| byte.reverse());
                }
                _ => blocks.reverse(),
            }
        }

        FullLabels::from_blocks(blocks, self.delta)
    }

    fn encode_padded<G: WireGroup>(&mut self, stream_id: u32, group: &G, pad: usize) -> FullLabels {
        assert!(group.len() >= pad);

        self.set_stream(stream_id as u64);
        let msbs = Block::random_vec(&mut self.rng, group.len() - pad);

        self.set_stream(PADDING_STREAM_ID);
        let lsbs = Block::random_vec(&mut self.rng, pad);

        let mut blocks: Vec<Block> = match self.bit_order {
            BitOrder::Msb0 => msbs.into_iter().chain(lsbs.into_iter()).collect(),
            BitOrder::Lsb0 => lsbs.into_iter().chain(msbs.into_iter()).collect(),
        };

        // Reverse blocks if bit order is reversed
        if self.bit_order != group.bit_order() {
            match group.value_type() {
                // If value type is bytes, we need to reverse each byte
                ValueType::Bytes => {
                    blocks.chunks_exact_mut(8).for_each(|byte| byte.reverse());
                }
                _ => blocks.reverse(),
            }
        }

        FullLabels::from_blocks(blocks, self.delta)
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

    use mpc_circuits::WireGroup;

    use super::*;
    use rstest::*;

    struct TestGroup {
        len: usize,
        bit_order: BitOrder,
        value_type: ValueType,
    }

    impl WireGroup for TestGroup {
        fn circuit(&self) -> Arc<mpc_circuits::Circuit> {
            unimplemented!()
        }

        fn id(&self) -> &mpc_circuits::GroupId {
            unimplemented!()
        }

        fn index(&self) -> usize {
            unimplemented!()
        }

        fn description(&self) -> &str {
            unimplemented!()
        }

        fn value_type(&self) -> ValueType {
            self.value_type
        }

        fn bit_order(&self) -> BitOrder {
            self.bit_order
        }

        fn wires(&self) -> &[usize] {
            unimplemented!()
        }

        fn len(&self) -> usize {
            self.len
        }
    }

    #[rstest]
    #[case::u8(ValueType::U8, 8)]
    #[case::u16(ValueType::U16, 16)]
    #[case::u32(ValueType::U32, 32)]
    #[case::u64(ValueType::U64, 64)]
    #[case::u128(ValueType::U128, 128)]
    #[case::bytes(ValueType::Bytes, 32)]
    fn test_encoder_bit_order(#[case] value_type: ValueType, #[case] len: usize) {
        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

        let group = TestGroup {
            len,
            bit_order: BitOrder::Msb0,
            value_type,
        };

        let encoded_0 = enc.encode(0, &group);

        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Lsb0);

        let encoded_1 = enc.encode(0, &group);

        let encoded_0 = encoded_0.iter().collect::<Vec<_>>();
        let mut encoded_1 = encoded_1.iter().collect::<Vec<_>>();

        match value_type {
            ValueType::Bytes => {
                encoded_1
                    .chunks_exact_mut(8)
                    .for_each(|byte| byte.reverse());
            }
            _ => encoded_1.reverse(),
        }

        assert_eq!(encoded_0, encoded_1)
    }

    #[rstest]
    fn test_encoder_pad_bytes_msb0() {
        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

        let group = TestGroup {
            len: 64,
            bit_order: BitOrder::Msb0,
            value_type: ValueType::Bytes,
        };

        let encoded_0 = enc.encode_padded(0, &group, 32);
        let encoded_1 = enc.encode_padded(0, &group, 32);

        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

        let group2 = TestGroup {
            len: 32,
            bit_order: BitOrder::Msb0,
            value_type: ValueType::Bytes,
        };

        let encoded_2 = enc.encode(0, &group2);
        let encoded_3 = enc.encode(0, &group2);

        let labels_0 = encoded_0.iter().collect::<Vec<_>>();
        let labels_1 = encoded_1.iter().collect::<Vec<_>>();
        let labels_2 = encoded_2.iter().collect::<Vec<_>>();
        let labels_3 = encoded_3.iter().collect::<Vec<_>>();

        assert_eq!(labels_0[..32], labels_2[..]);
        assert_eq!(labels_1[..32], labels_3[..]);
    }

    #[rstest]
    fn test_encoder_pad_bytes_lsb0() {
        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Lsb0);

        let group = TestGroup {
            len: 64,
            bit_order: BitOrder::Lsb0,
            value_type: ValueType::Bytes,
        };

        let encoded_0 = enc.encode_padded(0, &group, 32);
        let encoded_1 = enc.encode_padded(0, &group, 32);

        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Lsb0);

        let group2 = TestGroup {
            len: 32,
            bit_order: BitOrder::Lsb0,
            value_type: ValueType::Bytes,
        };

        let encoded_2 = enc.encode(0, &group2);
        let encoded_3 = enc.encode(0, &group2);

        let labels_0 = encoded_0.iter().collect::<Vec<_>>();
        let labels_1 = encoded_1.iter().collect::<Vec<_>>();
        let labels_2 = encoded_2.iter().collect::<Vec<_>>();
        let labels_3 = encoded_3.iter().collect::<Vec<_>>();

        assert_eq!(labels_0[32..], labels_2[..]);
        assert_eq!(labels_1[32..], labels_3[..]);
    }

    #[rstest]
    fn test_encoder_no_duplicates() {
        let group = TestGroup {
            len: 64,
            bit_order: BitOrder::Msb0,
            value_type: ValueType::Bytes,
        };

        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);

        // Pull from stream 0
        let a = enc.encode(0, &group);

        // Pull from a different stream
        let c = enc.encode(1, &group);

        // Pull from stream 0 again
        let b = enc.encode(0, &group);

        // Switching back to the same stream should preserve the word position
        assert_ne!(a, b);
        // Different stream ids should produce different labels
        assert_ne!(a, c);
    }
}
