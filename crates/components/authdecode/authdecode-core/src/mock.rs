use crate::{
    encodings::{Encoding, EncodingProvider, EncodingProviderError, FullEncodings},
    id::{Id, IdCollection},
};

use itybity::{FromBitIterator, ToBits};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    ops::Range,
};

/// The direction of the transcript.
#[derive(Clone, PartialEq, Serialize, Deserialize, Default, Debug)]
pub enum Direction {
    #[default]
    Sent,
    Received,
}

/// A collection of ids of transcript bits. Each bit is uniquely identified by the transcript's direction
/// and the bit's index in the transcript.
/// Ranges may overlap.
#[derive(Clone, PartialEq, Serialize, Deserialize, Default, Debug)]
pub struct MockBitIds {
    /// The direction of the transcript.
    direction: Direction,
    /// Ranges of bits in the transcript. The ranges may overlap.
    ranges: VecDeque<Range<usize>>,
}

impl MockBitIds {
    /// Constructs a new collection from ids in the given **byte** `ranges`.
    pub fn new(direction: Direction, ranges: &[Range<usize>]) -> Self {
        // Convert to bit ranges.
        let ranges = ranges
            .iter()
            .map(|r| Range {
                start: r.start * 8,
                end: r.end * 8,
            })
            .collect::<VecDeque<_>>();
        Self { direction, ranges }
    }

    /// Encodes the direction and the bit's `offset` in the transcript into an id.
    ///
    /// # Panics
    ///
    /// Panics if `offset` > 2^32.
    fn encode_bit_id(&self, offset: usize) -> Id {
        // All values are encoded in MSB-first order.
        // The first bit encodes the direction, the remaining bits encode the offset.
        let mut id = vec![false; 64];
        let encoded_direction = if self.direction == Direction::Sent {
            [false]
        } else {
            [true]
        };

        assert!(offset < (1 << 32));

        let encoded_offset = (offset as u32).to_be_bytes().to_msb0_vec();

        id[0..1].copy_from_slice(&encoded_direction);
        id[1 + (63 - encoded_offset.len())..].copy_from_slice(&encoded_offset);

        Id(u64::from_be_bytes(
            boolvec_to_u8vec(&id).try_into().unwrap(),
        ))
    }

    /// Decodes bit id into the direction and the bit's offset in the transcript.
    #[allow(dead_code)]
    fn decode_bit_id(&self, id: Id) -> (Direction, usize) {
        let encoding = id.0.to_be_bytes().to_msb0_vec();
        let direction_encoding = &encoding[0..1];

        let direction = if direction_encoding == [false] {
            Direction::Sent
        } else {
            Direction::Received
        };

        let offset_encoding = &encoding[1..];
        let offset = usize::from_be_bytes(boolvec_to_u8vec(offset_encoding).try_into().unwrap());

        (direction, offset)
    }
}

impl IdCollection for MockBitIds {
    fn drain_front(&mut self, mut count: usize) -> Self {
        let mut drained_ranges: VecDeque<Range<usize>> = VecDeque::new();

        while count > 0 {
            let mut range = match self.ranges.remove(0) {
                None => {
                    // Nothing more to drain.
                    break;
                }
                Some(range) => range,
            };

            // It is safe to `unwrap()` here and below since all iters/ranges will contain at least
            // 1 element.
            let min = range.clone().min().unwrap();
            let yielded = range.by_ref().take(count);
            let max = yielded.max().unwrap() + 1;
            drained_ranges.push_back(Range {
                start: min,
                end: max,
            });

            // If the range was only partially drained, put back the undrained subrange.
            if !range.is_empty() {
                self.ranges.push_back(Range {
                    start: range.clone().min().unwrap(),
                    end: range.max().unwrap() + 1,
                });
                break;
            }

            count -= max - min;
        }

        Self {
            direction: self.direction.clone(),
            // Optimization: combine adjacent ranges.
            ranges: drained_ranges,
        }
    }

    fn id(&self, index: usize) -> Id {
        assert!(self.len() > index);
        // How many indices already checked.
        let mut checked = 0;

        // Find which range the `index` is located in.
        for r in &self.ranges {
            if checked + r.len() > index {
                // Offset of the `index` from the start of this range.
                let offset = index - checked;
                return self.encode_bit_id(r.start + offset);
            }
            checked += r.len();
        }

        unreachable!()
    }

    fn len(&self) -> usize {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn new_from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        let mut direction = None;
        let ranges = iter
            .into_iter()
            .flat_map(|i| {
                if let Some(dir) = &direction {
                    assert!(dir == &i.direction)
                } else {
                    // On first iteration, set the direction.
                    direction = Some(i.direction)
                }
                i.ranges
            })
            .collect::<VecDeque<_>>();

        Self {
            direction: direction.unwrap(),
            // Optimization: combine adjacent ranges.
            ranges,
        }
    }
}

/// A mock provider of encodings.
#[derive(Clone)]
pub struct MockEncodingProvider<T>
where
    T: IdCollection,
{
    /// A mapping from a bit id to the full encoding of the bit.
    full_encodings: HashMap<Id, [Encoding; 2]>,
    phantom: PhantomData<T>,
}

impl<T> MockEncodingProvider<T>
where
    T: IdCollection,
{
    pub fn new(full_encodings: FullEncodings<T>) -> Self {
        let mut hashmap = HashMap::new();
        let ids = (0..full_encodings.ids().len())
            .map(|idx| full_encodings.ids().id(idx))
            .collect::<Vec<_>>();

        for (full_enc, id) in full_encodings.encodings().iter().zip(ids) {
            if hashmap.insert(id.clone(), *full_enc).is_some() {
                panic!("duplicate ids detected");
            }
        }
        Self {
            full_encodings: hashmap,
            phantom: PhantomData,
        }
    }
}

impl<T> EncodingProvider<T> for MockEncodingProvider<T>
where
    T: IdCollection,
{
    fn get_by_ids(&self, ids: &T) -> Result<FullEncodings<T>, EncodingProviderError> {
        let all_ids = (0..ids.len()).map(|idx| ids.id(idx)).collect::<Vec<_>>();

        let full_encodings = all_ids
            .iter()
            .map(|id| *self.full_encodings.get(id).unwrap())
            .collect::<Vec<_>>();
        Ok(FullEncodings::new(full_encodings, ids.clone()))
    }
}

/// Converts bits in MSB-first order into BE bytes. The bits will be internally left-padded
/// with zeroes to the nearest multiple of 8.
fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    // Reverse to lsb0 since `itybity` can only pad the rightmost bits.
    let mut b = Vec::<u8>::from_lsb0_iter(bv.iter().rev().copied());
    // Reverse to get big endian byte order.
    b.reverse();
    b
}
